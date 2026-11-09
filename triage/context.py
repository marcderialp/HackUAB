"""B2 context checks: the questions an analyst asks before judging an alert, answered by code.

For one alert, `context_for(alert)` returns FACTS (never verdicts) for the EvidencePack:
  - approved_change: is there an approved change or flow that really covers this activity?
    `find_changes()` returns every change active at that moment, including ones whose scope is free
    text ("Todos los puestos", "Correo"). Here each one is checked against its scope, its PURPOSE
    (the kind of activity it authorizes must be what the alert's rule detects, `CHANGE_PURPOSES`), the
    alert's own evidence (a cited change, "ninguna", unsigned binaries, the group involved) and the
    conditions written in `detalle` (who, from where, which hours, which recipient of outgoing data).
  - adm_outside_jump01, vendor_window, ot_source, remote_tool, mfa_exempt_account, hr_*:
    the internal rules in 01_contexto/empresa_tarvia.md and the HR calendar.

Each flag has `applies` True/False, or None when the alert lacks the data to decide (a person or the
deep-dive agent has to look). Times are judged in Europe/Madrid, using the earliest related event,
because an alert's created_at can lag behind the activity it describes.

Only structured fields are read (entities, evidence keys, inventory, change calendar). Free text written
by the attacker (subjects, bodies, prompts, service descriptions) is never interpreted here.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

from triage import data
from triage.entities import extract_entities
from triage.policy import parse_utc, to_local

COMPANY = "01_contexto/empresa_tarvia.md"
CHANGES = "02_inventario/calendario_cambios.csv"
USERS = "02_inventario/usuarios.csv"
HR = "02_inventario/eventos_rrhh.csv"

JUMP_HOST = "JUMP01"
OT_ZONE = "LOGISTICS-OT"
OT_AUTHORIZED_SOURCES = ("ENG-WS01", "WMS01")
VENDOR_ACCOUNT = "ext.logisoft"
VENDOR_WINDOW = (0, 4, 8, 18)  # Monday..Friday, 08:00-18:00 local
MFA_EXEMPT = {"svc_backup": "excluida de MFA por compatibilidad del agente de copias (riesgo aceptado en 2024)"}
UNAPPROVED_REMOTE_TOOLS = ("anydesk",)
APPROVED_REMOTE_TOOLS = ("teamviewer corporate",)
WEB_FRONTENDS = ("WEB-ECOM01", "WEB-ECOM02", "WEB-ECOM03", "WEB-ECOM04")
# Service accounts whose activity shows up as their tool, not their name (e.g. SCCM runs as SYSTEM).
ACCOUNT_TOOLS = {"svc_sccm": "ccmexec", "svc_scanner": "nessus"}


@dataclass
class Flag:
    flag: str
    applies: bool | None
    detail: str
    source: str


@dataclass
class Check:
    condition: str
    ok: bool | None  # None = the alert doesn't carry the data to check it
    detail: str


@dataclass
class ChangeMatch:
    change_id: str
    title: str
    applies: bool | None  # None = possible, but a specific condition could not be checked
    checks: list[Check] = field(default_factory=list)
    # D-6: the change documents a ROUTINE task (the normal function of a management tool), not a risky
    # action. If the alert is that task, the answer is false_positive + tune_rule, never BTP.
    routine: bool = False


# ---------------------------------------------------------------- facts about the alert

def related_event_ids(alert: dict[str, Any]) -> list[str]:
    """related_events as a list of ids, whatever shape a live alert brings (str, list of ids or dicts)."""
    raw = alert.get("related_events")
    if isinstance(raw, str):
        raw = [x.strip() for x in raw.replace(";", ",").split(",")]
    if not isinstance(raw, (list, tuple)):
        return []
    ids = []
    for item in raw:
        if isinstance(item, dict):
            item = item.get("event_id")
        if isinstance(item, str) and item.strip():
            ids.append(item.strip())
    return ids


def alert_time(alert: dict[str, Any]) -> datetime | None:
    """The alert's own time (created_at, else ts), or None if it has none that can be read."""
    for key in ("created_at", "ts", "timestamp"):
        if (parsed := parse_utc(alert.get(key))) is not None:
            return parsed
    return None


def event_time(alert: dict[str, Any]) -> str:
    """Earliest related event timestamp; falls back to the alert's time, then to now (never raises).
    Always ISO UTC with 'Z'."""
    try:
        events = data.get_events(related_event_ids(alert))
    except Exception:  # a live alert with odd ids must not stop the triage
        events = []
    times = [t for e in events if (t := parse_utc(e.get("timestamp"))) is not None]
    at = min(times) if times else alert_time(alert) or datetime.now(timezone.utc)
    return at.isoformat().replace("+00:00", "Z")


def _assets(alert: dict[str, Any], ents: dict[str, Any]) -> list[dict[str, Any]]:
    """Inventory rows for the hosts and internal IPs in the alert (IPs resolve to their host)."""
    keys = list(ents.get("hosts", [])) + list(ents.get("ips", []))
    if not ents.get("hosts") and alert.get("source_product") in ("WAF", "ECOM"):
        keys += WEB_FRONTENDS  # web alerts target the online store frontends
    seen, out = set(), []
    for key in keys:
        asset = data.get_asset(key)
        if asset and asset["hostname"] not in seen:
            seen.add(asset["hostname"])
            out.append(asset)
    return out


def _source_host(alert: dict[str, Any], ents: dict[str, Any]) -> str | None:
    ev = alert.get("evidence") or {}
    for key in ("from_host", "src"):
        if isinstance(ev.get(key), str) and data.get_asset(ev[key]):
            return data.get_asset(ev[key])["hostname"]
    return ents["hosts"][0] if ents.get("hosts") else None


def _structured_text(alert: dict[str, Any]) -> str:
    """Process names, parents and tool fields only (no attacker-written free text)."""
    ev = alert.get("evidence") or {}
    parts = [str(ev.get(k, "")) for k in ("parent", "parent_process", "tool", "process", "user")]
    for p in (alert.get("entities") or {}).get("processes", []) or []:
        parts += [str(p.get("name", "")), str(p.get("parent", ""))]
    return " ".join(parts).casefold()


def _in_hours(local: datetime, start: str, end: str) -> bool:
    return start <= local.strftime("%H:%M") <= end


# ---------------------------------------------------------------- approved changes and flows

_IP_RANGE = re.compile(r"IPs? origen (\d+\.\d+\.\d+\.)(\d+)-(\d+)", re.IGNORECASE)
_ORIGIN_HOST = re.compile(r"\bOrigen ([A-Z][A-Z0-9-]+)")
_FROM_HOST = re.compile(r"\b(?:desde|v[ií]a) ([A-Z][A-Z0-9]+[0-9]+)\b")
_DAILY = re.compile(r"\b(\d{2}:\d{2})-(\d{2}:\d{2})\b")
_DEST = re.compile(r"\bDestino ([^\s;,]+@[^\s;,]+)", re.IGNORECASE)
_ACCOUNT = re.compile(r"\b(svc_[a-z_]+|ext\.[a-z]+)\b")
_CHANGE_REF = re.compile(r"\b(?:CHG|FLUJO)-[\w-]+", re.IGNORECASE)

# What each kind of approved change authorizes, read from its text (titulo + detalle + alcance), and the
# detection rules (01_contexto/catalogo_casos_de_uso.csv) that see that activity. A change only covers
# alerts of those rules: an approved EDR-agent upgrade says nothing about a Domain Admins change on the
# same server. A change whose purpose isn't recognized can only be "possible" (None), never "covered".
CHANGE_PURPOSES: tuple[tuple[str, tuple[str, ...], frozenset[str]], ...] = (
    ("actualización o parada del agente EDR", ("agente edr",), frozenset({"UC-EDR-011"})),
    ("PsExec administrativo", ("psexec",), frozenset({"UC-NET-004"})),
    ("escaneo de vulnerabilidades", ("escaneo", "nessus"), frozenset({"UC-NET-003"})),
    ("pentest de la tienda online", ("pentest",), frozenset({"UC-WEB-001", "UC-WEB-002"})),
    ("PowerShell codificado de gestión", ("powershell codificado", "encodedcommand"), frozenset({"UC-EDR-002"})),
    ("mantenimiento con acceso a OT", ("clasificador", "ot-maint", "plc-sort"), frozenset({"UC-OT-001"})),
    ("alta en un grupo privilegiado", ("backup operators", "domain admins", "enterprise admins"),
     frozenset({"UC-IDP-008"})),
    ("acceso VPN de proveedor o cambio en la VPN", ("vpn",), frozenset({"UC-VPN-001"})),
    ("envío de datos a un destino aprobado", ("destino ",), frozenset({"UC-DLP-002", "UC-DLP-001"})),
)
PRIVILEGED_GROUPS = ("backup operators", "domain admins", "enterprise admins")
# D-6: purposes that are the normal function of a management tool (inventory, monitoring, telemetry,
# updates of the tool itself). A change with only these purposes documents routine work; it doesn't
# authorize a risky action, so it explains an alert (FP + tune_rule) but never makes it a BTP. Every
# other purpose above is a risky action done with authorization (pentest, scan, remote execution,
# stopping a defense, privilege change, OT access, vendor access, sending data out) -> BTP.
ROUTINE_PURPOSES = frozenset({"PowerShell codificado de gestión"})


def change_purposes(change: dict[str, Any]) -> list[str]:
    """Labels of CHANGE_PURPOSES found in the change's own text."""
    text = " ".join(str(change.get(k) or "") for k in ("titulo", "detalle", "alcance")).casefold()
    return [label for label, keys, _ in CHANGE_PURPOSES if any(k in text for k in keys)]
# Evidence keys where the SIEM itself states which change (if any) covers the activity.
CHANGE_EVIDENCE_KEYS = ("change_ticket", "maintenance_window", "change_id")


def _scope_checks(change: dict[str, Any], alert: dict[str, Any], assets: list[dict[str, Any]]) -> list[Check]:
    hosts = {a["hostname"] for a in assets}
    checks: list[Check] = []
    if change.get("scope_hosts"):
        hit = sorted(hosts & set(change["scope_hosts"]))
        if hit:
            checks.append(Check("equipo dentro del alcance", True, f"{', '.join(hit)} en {change['alcance']}"))
        elif hosts:
            checks.append(Check("equipo dentro del alcance", False,
                                f"{', '.join(sorted(hosts))} no está en {change['alcance']}"))
        else:
            checks.append(Check("equipo dentro del alcance", None, f"la alerta no indica equipo ({change['alcance']})"))
    for text in change.get("scope_text") or []:
        t = text.casefold()
        if "puestos" in t:
            ok = any(a.get("type") == "Portátil" or str(a.get("zone", "")).endswith("-USERS") for a in assets)
            checks.append(Check(f"alcance «{text}»", ok if assets else None,
                                "equipo de usuario" if ok else "ningún puesto de usuario implicado"))
        elif "servidores windows" in t:
            ok = any("windows server" in str(a.get("os", "")).casefold() for a in assets)
            checks.append(Check(f"alcance «{text}»", ok if assets else None,
                                "servidor Windows" if ok else "ningún servidor Windows implicado"))
        elif "salvo ot" in t:
            ot = [a["hostname"] for a in assets if a.get("zone") == OT_ZONE]
            checks.append(Check(f"alcance «{text}»", not ot if assets else None,
                                f"afecta a OT: {', '.join(ot)}" if ot else "fuera de OT"))
        elif t == "correo":
            ok = alert.get("rule_id", "").startswith(("UC-EML", "UC-DLP-002"))
            checks.append(Check(f"alcance «{text}»", ok, "alerta de correo" if ok else "no es una alerta de correo"))
        elif "directorio activo" in t:
            ok = alert.get("source_product") == "AD" or alert.get("rule_id") == "UC-IDP-008"
            checks.append(Check(f"alcance «{text}»", ok, "alerta del directorio" if ok else "no es del directorio"))
        else:
            checks.append(Check(f"alcance «{text}»", None, "alcance en texto libre: revisar a mano"))
    return checks


def _detail_checks(change: dict[str, Any], alert: dict[str, Any], ents: dict[str, Any],
                   assets: list[dict[str, Any]], local: datetime) -> list[Check]:
    detalle = change.get("detalle") or ""
    hosts = {a["hostname"] for a in assets} | set(ents.get("hosts", []))
    src = _source_host(alert, ents)
    users = set(ents.get("users", []))
    checks: list[Check] = []

    if m := _IP_RANGE.search(detalle):
        stem, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
        allowed = {f"{stem}{n}" for n in range(lo, hi + 1)}
        seen = [ip for ip in ents.get("ips", []) if not ip.startswith(("10.", "172.16."))]
        hit = [ip for ip in seen if ip in allowed]
        checks.append(Check(f"IP de origen {stem}{lo}-{hi}", bool(hit) if seen else None,
                            f"origen {', '.join(seen) or 'desconocido'}"))
    if m := _ORIGIN_HOST.search(detalle):
        checks.append(Check(f"origen {m.group(1)}", m.group(1) in hosts or src == m.group(1),
                            f"equipos de la alerta: {', '.join(sorted(hosts)) or 'ninguno'}"))
    if m := _FROM_HOST.search(detalle):
        checks.append(Check(f"desde {m.group(1)}", (src == m.group(1)) if src else None,
                            f"origen real: {src or 'desconocido'}"))
    if m := _DAILY.search(detalle):
        checks.append(Check(f"franja diaria {m.group(1)}-{m.group(2)}", _in_hours(local, m.group(1), m.group(2)),
                            f"hora local {local.strftime('%H:%M')}"))
    if m := _DEST.search(detalle):
        # Only the recipient of outgoing data counts. A sender (e.g. a compromised supplier writing FROM the
        # approved address) never makes an alert part of an approved outgoing flow.
        wanted = m.group(1).casefold()
        recipients = _recipients(alert)
        ok = (wanted in recipients) if recipients else None
        checks.append(Check(f"destinatario {m.group(1)}", ok,
                            f"destinatario en la alerta: {', '.join(recipients) or 'desconocido'}"))
    if "cuenta adm" in detalle.casefold():
        adm = sorted(u for u in users if u.startswith("adm."))
        checks.append(Check("cuenta adm.*", bool(adm), f"cuentas: {', '.join(sorted(users)) or 'ninguna'}"))
    tool_text = _structured_text(alert) + " " + " ".join(h.casefold() for h in hosts)
    for account in sorted(set(_ACCOUNT.findall(detalle))):
        tool = ACCOUNT_TOOLS.get(account)
        if account in users:
            checks.append(Check(f"cuenta {account}", True, f"{account} en la alerta"))
        elif tool and tool in tool_text:
            checks.append(Check(f"cuenta {account}", True, f"actividad de su herramienta ({tool})"))
        elif users - {"system"}:
            checks.append(Check(f"cuenta {account}", False, f"cuentas en la alerta: {', '.join(sorted(users))}"))
        else:
            checks.append(Check(f"cuenta {account}", None, "la alerta no indica la cuenta"))
    if "ip corporativa" in detalle.casefold() and VENDOR_ACCOUNT in users:
        usual = usual_vpn_ip(VENDOR_ACCOUNT)
        ips = [ip for ip in ents.get("ips", []) if not ip.startswith("10.")]
        checks.append(Check("desde su IP corporativa", (usual in ips) if ips and usual else None,
                            f"IP {', '.join(ips) or 'desconocida'}; habitual {usual or 'desconocida'}"))
    return checks


def _recipients(alert: dict[str, Any]) -> list[str]:
    """Destination addresses of outgoing data, from structured evidence only (never the sender)."""
    ev = alert.get("evidence") or {}
    values: list[Any] = [ev.get("recipient"), ev.get("destination")]
    many = ev.get("recipients")
    values += many if isinstance(many, list) else [many]
    return sorted({str(v).strip().casefold() for v in values if isinstance(v, str) and "@" in v})


def _purpose_checks(change: dict[str, Any], alert: dict[str, Any]) -> list[Check]:
    """Does the alert's activity match what the change authorizes? Uses the change text, the alert's rule
    and the alert's own structured evidence (never attacker-written free text)."""
    text = " ".join(str(change.get(k) or "") for k in ("titulo", "detalle", "alcance")).casefold()
    rule = str(alert.get("rule_id") or "")
    ev = alert.get("evidence") or {}
    checks: list[Check] = []

    purposes = [(label, rules) for label, keys, rules in CHANGE_PURPOSES if any(k in text for k in keys)]
    if not purposes:
        checks.append(Check("propósito del cambio", None,
                            "no se reconoce qué actividad autoriza el cambio: revisar a mano"))
    else:
        allowed = frozenset().union(*(rules for _, rules in purposes))
        labels = "; ".join(label for label, _ in purposes)
        checks.append(Check("propósito del cambio", rule in allowed,
                            f"el cambio autoriza: {labels}; la alerta es {rule} ({alert.get('rule_name', '')})"))

    groups = [g for g in PRIVILEGED_GROUPS if g in text]
    if groups and ev.get("group"):
        alert_group = str(ev["group"]).casefold()
        checks.append(Check(f"grupo {', '.join(groups)}", alert_group in groups,
                            f"grupo en la alerta: {ev['group']}"))

    for key in CHANGE_EVIDENCE_KEYS:
        value = ev.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        refs = {r.upper() for r in _CHANGE_REF.findall(value)}
        if refs:
            checks.append(Check(f"la alerta cita {', '.join(sorted(refs))}", change["id"].upper() in refs,
                                f"evidence.{key} = {value}"))
        elif value.strip().casefold().startswith("ningun"):
            checks.append(Check("la alerta indica que no hay cambio", False, f"evidence.{key} = {value}"))

    unsigned = [f"{k}: {v}" for k, v in ev.items() if isinstance(v, str) and "sin firma" in v.casefold()]
    if unsigned:
        checks.append(Check("sin procesos sin firmar", False,
                            "un cambio aprobado no lanza binarios sin firmar: " + "; ".join(unsigned)[:160]))
    return checks


def match_changes(alert: dict[str, Any], ents: dict[str, Any] | None = None,
                  at: str | None = None) -> list[ChangeMatch]:
    """Every change active at the event time, with whether it really covers this alert and why."""
    ents = ents or extract_entities(alert)
    at = at or event_time(alert)
    local = to_local(at)
    assets = _assets(alert, ents)
    out = []
    for change in data.find_changes(at=at):
        window = Check("ventana del cambio", True,
                       f"{change['inicio']} → {change['fin']} (hora local {local.strftime('%d/%m %H:%M')})")
        scope = _scope_checks(change, alert, assets)
        detail = _purpose_checks(change, alert) + _detail_checks(change, alert, ents, assets, local)
        purposes = change_purposes(change)
        routine = bool(purposes) and all(p in ROUTINE_PURPOSES for p in purposes)
        out.append(ChangeMatch(change["id"], change["titulo"], _decide(scope, detail), [window, *scope, *detail],
                               routine))
    return out


def _decide(scope: list[Check], detail: list[Check]) -> bool | None:
    """False if any condition fails; None if a specific condition (who, from where, recipient...) could
    not be checked, so a person must confirm; True only when everything checkable passes.
    A missing host alone doesn't block a match that its specific conditions confirm (e.g. a VPN alert)."""
    checks = scope + detail
    if any(c.ok is False for c in checks):
        return False
    if any(c.ok is None for c in detail):
        return None
    return any(c.ok for c in checks) or None


# ---------------------------------------------------------------- internal rules

def usual_vpn_ip(user: str) -> str | None:
    """Most frequent VPN source IP of an account (its 'usual origin')."""
    items = data.timeline(user, sources=["vpn"], limit=5000)["items"]
    counts = Counter(i["event"].get("src_ip") for i in items if i["event"].get("src_ip"))
    if not counts:
        return None
    ip, n = counts.most_common(1)[0]
    return ip if n / sum(counts.values()) > 0.5 else None


def _rule_flags(alert: dict[str, Any], ents: dict[str, Any], assets: list[dict[str, Any]],
                local: datetime) -> list[Flag]:
    flags: list[Flag] = []
    users = set(ents.get("users", []))
    src = _source_host(alert, ents)
    ev = alert.get("evidence") or {}

    adm = sorted(u for u in users if u.startswith("adm."))
    if adm:
        flags.append(Flag("adm_outside_jump01", (src != JUMP_HOST) if src else None,
                          f"{', '.join(adm)} usada desde {src or 'origen desconocido'}; solo se permite desde {JUMP_HOST}",
                          COMPANY))

    if VENDOR_ACCOUNT in users:
        d0, d1, h0, h1 = VENDOR_WINDOW
        inside = d0 <= local.weekday() <= d1 and h0 <= local.hour < h1
        usual = usual_vpn_ip(VENDOR_ACCOUNT)
        ips = [ip for ip in ents.get("ips", []) if not ip.startswith("10.")]
        flags.append(Flag("vendor_outside_window", not inside,
                          f"{local.strftime('%A %d/%m %H:%M')} local; ventana contractual L-V 08:00-18:00", USERS))
        if ips and usual:
            flags.append(Flag("vendor_unusual_source", usual not in ips,
                              f"origen {', '.join(ips)}; origen habitual {usual}", USERS))

    ot_assets = [a for a in assets if a.get("zone") == OT_ZONE]
    if ot_assets or ev.get("dst_zone") == OT_ZONE:
        origin = src if src and src not in {a["hostname"] for a in ot_assets} else None
        flags.append(Flag("ot_unauthorized_source", (origin not in OT_AUTHORIZED_SOURCES) if origin else None,
                          f"origen {origin or 'desconocido'}; autorizados: {', '.join(OT_AUTHORIZED_SOURCES)} "
                          "(otros solo con un cambio aprobado)", COMPANY))

    text = _structured_text(alert)
    for tool in UNAPPROVED_REMOTE_TOOLS:
        if tool in text:
            flags.append(Flag("unapproved_remote_tool", True,
                              f"{tool}: no aprobado (solo TeamViewer Corporate gestionado por IT)", COMPANY))
    if "teamviewer" in text and not any(t in text for t in APPROVED_REMOTE_TOOLS):
        flags.append(Flag("unapproved_remote_tool", None, "TeamViewer: confirmar que es la versión Corporate", COMPANY))

    for user in sorted(users & set(MFA_EXEMPT)):
        flags.append(Flag("mfa_exempt_account", True, f"{user}: {MFA_EXEMPT[user]}", COMPANY))
    return flags


# ---------------------------------------------------------------- HR calendar

_RANGE = re.compile(r"(\d{1,2})/(\d{1,2})(?:/\d{4})?\s*(?:al|a)\s*(\d{1,2})/(\d{1,2})")
_HR_DAYS = {"viaje": 4, "vacaciones": 7, "teletrabajo_temporal": 14, "alta": 14}


def _hr_period(event: dict[str, Any], year: int) -> tuple[date, date, bool]:
    """(start, end, exact): exact=False when the period is estimated from fecha_efectiva."""
    if m := _RANGE.search(event.get("detalle") or ""):
        d1, m1, d2, m2 = map(int, m.groups())
        return date(year, m1, d1), date(year, m2, d2), True
    start = date.fromisoformat(event["fecha_efectiva"])
    if event["tipo"] == "baja_voluntaria_comunicada":
        return date.fromisoformat(event["fecha"]), start, True  # notice period up to the last day
    return start, start + timedelta(days=_HR_DAYS.get(event["tipo"], 7)), False


def _hr_flags(ents: dict[str, Any], local: datetime) -> list[Flag]:
    flags: list[Flag] = []
    for name in ents.get("users", []):
        user = data.get_user(name)
        for ev in (user or {}).get("hr_events", []) or []:
            start, end, exact = _hr_period(ev, local.year)
            inside = start <= local.date() <= end
            when = f"{start:%d/%m}-{end:%d/%m}{'' if exact else ' (aprox.)'}"
            kind = {"viaje": "hr_travel", "vacaciones": "hr_vacation", "teletrabajo_temporal": "hr_remote_work",
                    "alta": "hr_new_hire", "baja_voluntaria_comunicada": "hr_leaving",
                    "cambio_puesto": "hr_role_change"}.get(ev["tipo"], "hr_event")
            flags.append(Flag(kind, inside if exact else (inside or None),
                              f"{user['username']}: {ev['detalle']} [{when}]", HR))
            if ev["tipo"] == "baja_voluntaria_comunicada" and local.date() > end:
                # activity AFTER the last working day: the account should no longer be in use
                days = (local.date() - end).days
                flags.append(Flag("hr_departed", True, f"{user['username']}: actividad {days} día(s) después de su "
                                  f"último día de trabajo ({end:%d/%m}); la cuenta no debería usarse", HR))
    return flags


# ---------------------------------------------------------------- entry point

def context_for(alert: dict[str, Any]) -> dict[str, Any]:
    """All context facts for one alert, ready for the EvidencePack and the trace."""
    ents = extract_entities(alert)
    at = event_time(alert)
    local = to_local(at)
    assets = _assets(alert, ents)
    changes = match_changes(alert, ents, at)
    covering = [c for c in changes if c.applies is True]
    possible = [c for c in changes if c.applies is None]
    if covering:
        flags = [Flag("approved_change", True, "; ".join(f"{c.change_id}: {c.title}" for c in covering), CHANGES)]
    elif possible:
        flags = [Flag("approved_change", None,
                      "posible, sin confirmar: " + "; ".join(
                          f"{c.change_id} ({', '.join(k.condition for k in c.checks if k.ok is None)})" for c in possible),
                      CHANGES)]
    else:
        flags = [Flag("approved_change", False, "ningún cambio o flujo aprobado la cubre", CHANGES)]
    flags += _rule_flags(alert, ents, assets, local) + _hr_flags(ents, local)
    return {
        "alert_id": alert.get("alert_id"),
        "event_time": at,
        "event_time_local": local.strftime("%a %d/%m/%Y %H:%M"),
        "flags": [asdict(f) for f in flags],
        "changes": [asdict(c) for c in changes],
    }
