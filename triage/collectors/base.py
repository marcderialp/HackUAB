"""B3 shared machinery: the EvidencePack builder, the query trace and the checks every runbook needs.

A collector answers a runbook's "Comprobaciones" with queries and writes FINDINGS: short facts in
Spanish, each citing the event_ids that back it. Findings are facts, not verdicts; `notable` only
marks what the runbook itself calls out (new domain, TI hit, credentials used after a click...), so the
UI can highlight it. Every query is recorded in the trace, which is what the demo shows as
"what the system checked".

Attacker-controlled free text (subjects, bodies, prompts, service descriptions, command lines) is
never interpreted here: it is copied to `untrusted` so the LLM sees it fenced off as data.
"""
from __future__ import annotations

import ipaddress
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from triage import data
from triage.context import alert_time, context_for, event_time, related_event_ids
from triage.entities import extract_entities
from triage.policy import parse_utc, to_local
from triage.untrusted import UNTRUSTED_EVIDENCE_KEYS, untrusted_fields  # noqa: F401 (re-exported)


MAX_ITEMS = 2000  # hard cap per query (data.MAX_LIMIT)
# B2 flags that break an internal rule; HR facts (travel, leaving...) are context, not highlights by themselves.
RISK_FLAGS = ("adm_outside_jump01", "vendor_outside_window", "vendor_unusual_source", "ot_unauthorized_source",
              "unapproved_remote_tool", "mfa_exempt_account", "hr_leaving", "hr_departed")


@dataclass
class Finding:
    check: str  # runbook step, e.g. "RB-01.4 interacción"
    fact: str  # Spanish, for the analyst and the LLM
    source: str  # log source or reference file
    event_ids: list[str] = field(default_factory=list)
    notable: bool = False


@dataclass
class TraceStep:
    step: str
    tool: str
    params: dict[str, Any]
    result_count: int
    ms: int


def ts(value: str | datetime) -> datetime:
    """Any timestamp the data or a live alert brings -> aware UTC. Raises ValueError if unreadable."""
    parsed = parse_utc(value)
    if parsed is None:
        raise ValueError(f"unreadable timestamp: {value!r}")
    return parsed


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_internal(ip: str) -> bool:
    """Tarvia's own address space. The dataset uses documentation ranges (192.0.2.x, 198.51.100.x,
    203.0.113.x, 198.18.0.0/15) for EXTERNAL hosts, which Python's is_private would wrongly call internal."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETS)


def local_str(value: str | datetime) -> str:
    return to_local(value).strftime("%d/%m %H:%M")


class Pack:
    """Builds one EvidencePack. Collectors call `query()` for every lookup and `find()` for every fact."""

    def __init__(self, alert: dict[str, Any]):
        self.alert = alert
        self.ents = extract_entities(alert)
        self.at = ts(event_time(alert))
        self.findings: list[Finding] = []
        if alert_time(alert) is None and not related_event_ids(alert):
            self.find("hora", "la alerta no trae una hora legible (created_at) ni eventos relacionados: "
                      f"se toma la hora actual ({iso(self.at)}) y las ventanas de búsqueda pueden no cuadrar",
                      "triage.collectors", notable=True)
        self.trace: list[TraceStep] = []
        self.intel: list[dict[str, Any]] = []
        self.related_alerts: list[dict[str, Any]] = []
        self.assets: list[dict[str, Any]] = []
        self.identities: list[dict[str, Any]] = []
        self.context: dict[str, Any] = {}

    # -------------------------------------------------------------- recording
    def query(self, step: str, tool: str, params: dict[str, Any], fn: Callable[[], Any]) -> Any:
        start = time.perf_counter()
        try:
            result = fn()
        except Exception as exc:  # a failing lookup must not kill the whole pack
            self.trace.append(TraceStep(step, tool, {**params, "error": str(exc)}, 0,
                                        int((time.perf_counter() - start) * 1000)))
            return None
        self.trace.append(TraceStep(step, tool, params, _count(result), int((time.perf_counter() - start) * 1000)))
        return result

    def find(self, check: str, fact: str, source: str, event_ids: list[str] | None = None,
             notable: bool = False) -> None:
        self.findings.append(Finding(check, fact, source, list(dict.fromkeys(event_ids or []))[:20], notable))

    # -------------------------------------------------------------- common lookups
    def window(self, before_h: float = 24, after_h: float = 24) -> tuple[str, str]:
        return iso(self.at - timedelta(hours=before_h)), iso(self.at + timedelta(hours=after_h))

    def events(self, step: str, source: str, q: str = "", before_h: float = 24, after_h: float = 24,
               limit: int = MAX_ITEMS) -> list[dict[str, Any]]:
        start, end = self.window(before_h, after_h)
        res = self.query(step, "search_logs", {"source": source, "q": q, "start": start, "end": end},
                         lambda: data.search_logs(source, q=q, start=start, end=end, limit=limit))
        return (res or {}).get("items", [])

    def timeline(self, step: str, entity: str, sources: list[str] | None = None, before_h: float = 24,
                 after_h: float = 24, entity_type: str | None = None) -> list[dict[str, Any]]:
        start, end = self.window(before_h, after_h)
        res = self.query(step, "timeline", {"entity": entity, "sources": sources, "start": start, "end": end},
                         lambda: data.timeline(entity, entity_type=entity_type, start=start, end=end,
                                               sources=sources, limit=MAX_ITEMS))
        return (res or {}).get("items", [])

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert.get("alert_id"),
            "rule_id": self.alert.get("rule_id"),
            "rule_name": self.alert.get("rule_name"),
            "rule_severity": self.alert.get("severity"),
            "runbook": runbook_for(self.alert),
            "event_time": iso(self.at),
            "event_time_local": to_local(self.at).strftime("%a %d/%m/%Y %H:%M"),
            "alert": self.alert,
            "entities": self.ents,
            "context": self.context,
            "inventory": {"assets": self.assets, "identities": self.identities},
            "intel": self.intel,
            "related_alerts": self.related_alerts,
            "findings": [asdict(f) for f in self.findings],
            # computed last, after the runbook collector has added its assets
            "signals": {"personal_data_payments": personal_data_signals(self.alert, self.assets)},
            "untrusted": untrusted_fields(self.alert),
            "trace": [asdict(t) for t in self.trace],
        }


def _count(result: Any) -> int:
    if isinstance(result, dict):
        if "items" in result:
            return len(result["items"])
        return 1
    if isinstance(result, list):
        return len(result)
    return 0 if result is None else 1


def runbook_for(alert: dict[str, Any]) -> str | None:
    if alert.get("runbook"):
        return alert["runbook"]
    from triage.collectors import RULE_RUNBOOK  # catalog fallback for alerts without the field
    return RULE_RUNBOOK.get(alert.get("rule_id", ""))


# ---------------------------------------------------------------- checks shared by every runbook

def common(pack: Pack) -> None:
    """Context (B2), inventory, intel and related alerts: what every runbook starts with."""
    ents = pack.ents
    pack.context = pack.query("Contexto: cambios aprobados y reglas internas", "context_for",
                              {"alert_id": pack.alert.get("alert_id")}, lambda: context_for(pack.alert)) or {}
    for flag in pack.context.get("flags", []):  # surface B2 facts next to the runbook findings
        if flag["flag"] == "approved_change":
            if flag["applies"] is not False:
                pack.find("Contexto", ("cambio aprobado: " if flag["applies"] else "") + flag["detail"], flag["source"])
        elif flag["applies"]:
            pack.find("Contexto", flag["detail"], flag["source"], notable=flag["flag"] in RISK_FLAGS)

    for host in ents.get("hosts", []):
        asset = pack.query("Inventario: activo", "get_asset", {"key": host}, lambda h=host: data.get_asset(h))
        if asset:
            pack.assets.append(asset)
        else:
            pack.find("Inventario", f"{host} no está en la CMDB (¿equipo externo o no gestionado?)", "activos.csv",
                      notable=True)
    for user in ents.get("users", []):
        ident = pack.query("Inventario: identidad", "get_user", {"key": user}, lambda u=user: data.get_user(u))
        if ident:
            pack.identities.append(ident)

    indicators = [(ip, "ip") for ip in ents.get("ips", []) if not is_internal(ip)]
    indicators += [(d, "domain") for d in ents.get("domains", [])]
    indicators += [(h, "hash") for h in ents.get("hashes", [])]
    tip_hits: dict[str, list[str]] = {}
    anon: dict[str, list[str]] = {}
    unknown: list[str] = []
    for value, kind in indicators[:25]:
        info = pack.query("Inteligencia: TIP y GeoIP", "get_intel", {"indicator": value},
                          lambda v=value: data.get_intel(v)) or {}
        entry = {"indicator": value, "type": kind, "tip": info.get("tip"), "geo": info.get("geo")}
        if kind == "hash":
            entry["sandbox"] = pack.query("Inteligencia: sandbox", "get_sandbox", {"sha256": value},
                                          lambda v=value: data.get_sandbox(v))
        pack.intel.append(entry)
        tip, geo, sbx = entry["tip"], entry["geo"], entry.get("sandbox")
        if tip:
            label = f"{tip.get('reputation')} ({tip.get('malware_family') or 's/familia'}, confianza {tip.get('confidence')})"
            tip_hits.setdefault(label, []).append(value)
        if sbx:
            pack.find("Inteligencia", f"sandbox de {sbx.get('file_name')}: {sbx.get('verdict')} "
                      f"(score {sbx.get('score')}, {sbx.get('malware_family') or 's/familia'})", "sandbox_informes.jsonl",
                      notable=sbx.get("verdict") == "malicious")
        kinds = [k[3:] for k in ("is_tor", "is_vpn_provider", "is_hosting", "is_residential_proxy")
                 if geo and str(geo.get(k)) == "True"]
        if kinds:
            anon.setdefault(", ".join(kinds), []).append(f"{value} ({geo.get('as_org')}, {geo.get('country')})")
        if not tip and kind != "hash" and not geo:
            unknown.append(value)
    # One line per kind of result, so a list of 10 IPs doesn't bury the important facts.
    for label, values in tip_hits.items():
        pack.find("Inteligencia", f"en el TIP como {label}: {', '.join(values[:8])}"
                  + (f" y {len(values) - 8} más" if len(values) > 8 else ""), "ti_feed.jsonl",
                  notable=label.startswith("malicious"))
    for label, values in anon.items():
        pack.find("Inteligencia", f"{len(values)} origen(es) {label}: {'; '.join(values[:6])}"
                  + (f" y {len(values) - 6} más" if len(values) > 6 else ""), "geoip_asn.csv", notable=True)
    if unknown:
        pack.find("Inteligencia", f"desconocidos en el TIP (desconocido no es limpio): {', '.join(unknown[:8])}",
                  "ti_feed.jsonl")

    start, end = pack.window(24, 24)
    keys = [(u, "user") for u in ents.get("users", [])] + [(h, "host") for h in ents.get("hosts", [])]
    keys += [(ip, "ip") for ip in ents.get("ips", []) if not is_internal(ip)]
    keys += [(d, "domain") for d in ents.get("domains", [])] + [(h, "hash") for h in ents.get("hashes", [])]
    seen: dict[str, dict[str, Any]] = {}
    for value, kind in keys[:15]:
        res = pack.query("Correlación: otras alertas ±24 h", "alerts_for_entity",
                         {"entity": value, "type": kind, "start": start, "end": end},
                         lambda v=value, k=kind: data.alerts_for_entity(v, entity_type=k, start=start, end=end,
                                                                        exclude_alert_id=pack.alert.get("alert_id"),
                                                                        limit=50)) or {}
        for item in res.get("items", []):
            seen.setdefault(item["alert_id"], {**item, "shared": []})["shared"].append(f"{kind}:{value}")
    pack.related_alerts = sorted(seen.values(), key=lambda a: a["created_at"])[:30]
    rules = sorted({a["rule_id"] for a in pack.related_alerts})
    if pack.related_alerts:
        pack.find("Correlación", f"{len(pack.related_alerts)} alertas más sobre las mismas entidades en ±24 h "
                  f"({', '.join(rules[:8])})", "alertas.jsonl",
                  notable=any(r != pack.alert.get("rule_id") for r in rules))


# ---------------------------------------------------------------- deterministic signals for the policy

# Business services whose data is personal or payment data (inventory names, matched case-insensitively).
PERSONAL_DATA_SERVICES = ("pci dss", "crm y datos de clientes", "nóminas")
SENSITIVE_CLASSIFICATION = ("confiden", "restring", "personal", "pii", "client", "rgpd", "gdpr", "crm", "nómina")


def _number(value: Any) -> float:
    """A count from the alert: a number, a numeric string, or a {type: count} dict (summed)."""
    if isinstance(value, dict):
        return sum(_number(v) for v in value.values())
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def personal_data_signals(alert: dict[str, Any], assets: list[dict[str, Any]]) -> list[str]:
    """Facts that prove personal or payment data is involved (politica §2 «datos personales o pagos»).

    The policy accepts the LLM's `personal_data_payments` adjustment only when this list is not empty.
    Only structured fields count (never attacker-written text): DLP matches, a confidential bucket, PCI
    scope, a payment/IBAN request, customer accounts actually taken over or another customer's data
    requested, or an affected asset that holds payment, customer or payroll data."""
    ev = alert.get("evidence") if isinstance(alert.get("evidence"), dict) else {}
    out: list[str] = []
    for key in ("personal_data_matches", "matches"):
        if _number(ev.get(key)) > 0:
            detail = ", ".join(f"{k} {v}" for k, v in ev[key].items()) if isinstance(ev[key], dict) else ev[key]
            out.append(f"DLP: coincidencias de datos personales ({detail})")
    if any(w in str(ev.get("bucket_classification", "")).casefold() for w in SENSITIVE_CLASSIFICATION):
        out.append(f"almacenamiento clasificado como {ev['bucket_classification']}")
    if str(ev.get("pci_scope")).casefold() in ("true", "1", "yes", "sí", "si"):
        out.append("activo en alcance PCI DSS")
    if ev.get("new_iban_country") or ev.get("amount_mentioned"):
        out.append("petición de pago o de cambio de IBAN")
    if _number(ev.get("success_count")) > 0:
        out.append(f"{ev['success_count']} cuentas de cliente con acceso correcto del atacante")
    if ev.get("sequence") and (alert.get("entities") or {}).get("customers"):
        out.append("cuenta de cliente modificada tras un acceso sospechoso")
    asked, own = ev.get("requested_customer_id"), ev.get("authenticated_customer_id")
    if asked and own and asked != own:
        out.append("se pidieron datos de otro cliente")
    for key, value in ev.items():  # SIEM-written context (never the attacker-writable fields)
        if key not in UNTRUSTED_EVIDENCE_KEYS and isinstance(value, str) and "crm" in value.casefold():
            out.append(f"la alerta implica la base de datos de clientes (CRM): {key}")
            break
    for asset in assets:
        service = str(asset.get("business_service") or "")
        if any(w in service.casefold() for w in PERSONAL_DATA_SERVICES):
            out.append(f"activo afectado {asset.get('hostname')}: {service}")
    return list(dict.fromkeys(out))
