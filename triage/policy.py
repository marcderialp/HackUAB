"""B1 policy engine: Tarvia's SOC policy as deterministic code (the
organizers' policy document is not part of this repository; docs/design.md summarizes the decisions).

The LLM proposes facts (verdict, adjustment reasons, flags); this module decides what the policy
says: final severity (matrix + adjustments), SLA, mandatory escalation and who must approve each
containment action. It never calls the LLM or the database, so it is cheap and fully testable.

Team decisions applied (docs/design.md, policy decisions):
- D-1 identity criticality = what the identity can access.
- D-2 the +1 for VIP/privileged applies only if that privilege did not already set the column.
- D-3 a target that does not exist or was not really affected counts as Baja.
- D-4 block_ioc / purge_email: N1-allowed, but a human confirms with one click.
- D-5 when a runbook sets an explicit severity for a case, it is a minimum over the matrix result
  (it can raise the severity, never lower it). Example: RB-01, unverified IBAN change -> critical.
"""
from __future__ import annotations

import csv
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
SERVICES_CSV = ROOT / "02_inventario" / "servicios_negocio.csv"
MADRID = ZoneInfo("Europe/Madrid")

SEVERITIES = ("informational", "low", "medium", "high", "critical")
CRITICALITIES = ("Baja", "Media", "Alta", "Crítica")
VERDICTS = ("true_positive", "benign_true_positive", "false_positive", "needs_more_info")

# SOC policy §2: rows = rule severity, columns = Baja, Media, Alta, Crítica.
MATRIX: dict[str, tuple[str, str, str, str]] = {
    "informational": ("informational", "informational", "low", "low"),
    "low": ("informational", "low", "low", "medium"),
    "medium": ("low", "medium", "medium", "high"),
    "high": ("medium", "high", "high", "critical"),
    "critical": ("high", "critical", "critical", "critical"),
}

# Shared with the LLM output (LLMVerdict.adjustments[].reason_type). Do not rename without the team.
ADJUSTMENT_DELTAS: dict[str, int] = {
    "confirmed_execution": +1,  # execution or access confirmed, not just attempted
    "vip_privileged": +1,  # computed here from the identities (D-2); LLM proposals are ignored
    "personal_data_payments": +1,  # personal data or payments involved; LLM proposals need code signals
    "blocked_no_effect": -1,  # a control blocked it before any effect and there was no later activity
}
ADJUSTMENT_REASONS = tuple(ADJUSTMENT_DELTAS)

# D-1: service and external accounts take the criticality of the business service they serve.
SERVICE_ACCOUNT_SERVICE: dict[str, str] = {
    "svc_backup": "Copias de seguridad",
    "svc_sql": "CRM y datos de clientes",
    "svc_sccm": "Puesto de trabajo",
    "svc_jenkins": "Integración continua",
    "svc_ecom_api": "Tienda online y app",
    "svc_wms": "Gestión de almacén (WMS)",
    "ext.logisoft": "Gestión de almacén (WMS)",
}
UNKNOWN_SERVICE_ACCOUNT_CRITICALITY = "Alta"  # no known service (e.g. svc_scanner, svc_print_upd): be prudent
UNKNOWN_ENTITY_CRITICALITY = "Media"  # nothing found in the inventory (external or unmanaged)

ACTIONS = (
    "isolate_host", "disable_user", "revoke_sessions", "reset_password",
    "block_ioc", "purge_email", "disable_access_key",
)
N1_EXECUTABLE = ("block_ioc", "purge_email")  # politica §4; D-4 still asks for a human click
# Steps in the ticket's workflow (schemas.ActionType). They change nothing on any system and never
# reach the containment API, so they need no approval, even when the alert involves OT.
WORKFLOW_ACTIONS = ("close", "escalate", "notify", "investigate", "tune_rule")
# Legitimate services with dual use: never blocked globally without N2 (politica §4). Domains match the
# target's host exactly or as a parent domain (mega.nz, www.mega.nz; not notmega.nz); products match as a word.
DUAL_USE_DOMAINS = ("mega.nz", "mega.io", "mega.co.nz", "anydesk.com", "anydesk.net")
DUAL_USE_PRODUCTS = ("anydesk",)
DUAL_USE_SERVICES = DUAL_USE_DOMAINS + DUAL_USE_PRODUCTS  # kept for callers that list them
OT_ZONE = "LOGISTICS-OT"
OT_ASSET_TYPES = ("PLC", "HMI")


# ---------------------------------------------------------------- normalization helpers

_CRIT_ALIASES = {
    "baja": "Baja", "low": "Baja",
    "media": "Media", "medium": "Media",
    "alta": "Alta", "high": "Alta",
    "crítica": "Crítica", "critica": "Crítica", "critical": "Crítica",
}


def norm_criticality(value: Any) -> str | None:
    if value is None:
        return None
    return _CRIT_ALIASES.get(str(value).strip().casefold())


def norm_severity(value: Any) -> str:
    sev = str(value).strip().casefold()
    if sev not in SEVERITIES:
        raise ValueError(f"unknown severity: {value!r}")
    return sev


def _crank(criticality: str) -> int:
    return CRITICALITIES.index(criticality)


def _srank(severity: str) -> int:
    return SEVERITIES.index(severity)


def _shift(severity: str, delta: int) -> str:
    return SEVERITIES[max(0, min(len(SEVERITIES) - 1, _srank(severity) + delta))]


def _true(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in ("true", "1", "yes", "sí", "si")


def _base_name(name: str) -> str:
    """'Tienda online y app (canal principal)' -> 'tienda online y app'."""
    return name.split(" (")[0].strip().casefold()


_TIME_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S",
                 "%d/%m/%Y %H:%M", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d")


def parse_utc(value: Any) -> datetime | None:
    """Best-effort timestamp -> aware UTC datetime, or None if it can't be read.

    Dataset times are ISO UTC; live alerts may bring 'Z', a space instead of 'T', dd/mm/yyyy, or epoch
    seconds/milliseconds. Naive values are taken as UTC (the data's convention)."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, datetime):
        out = value
    elif isinstance(value, (int, float)):
        seconds = value / 1000 if value > 1e11 else value  # epoch milliseconds vs seconds
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.isdigit():
            return parse_utc(int(text))
        out = None
        try:
            out = datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
        except ValueError:
            for fmt in _TIME_FORMATS:
                try:
                    out = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
        if out is None:
            return None
    else:
        return None
    return out.replace(tzinfo=timezone.utc) if out.tzinfo is None else out.astimezone(timezone.utc)


def to_local(value: str | datetime) -> datetime:
    """UTC timestamp -> Europe/Madrid. DST ends 25 Oct 2026, so never use a fixed +2.
    Raises ValueError if the value can't be read as a time (see parse_utc)."""
    parsed = parse_utc(value)
    if parsed is None:
        raise ValueError(f"unreadable timestamp: {value!r}")
    return parsed.astimezone(MADRID)


# ---------------------------------------------------------------- business services

@lru_cache(maxsize=1)
def business_services() -> dict[str, dict[str, str]]:
    with open(SERVICES_CSV, encoding="utf-8") as f:
        return {row["servicio"]: row for row in csv.DictReader(f)}


def find_service(name: str | None) -> dict[str, str] | None:
    """Match a service name tolerantly (CMDB names add notes in parentheses)."""
    if not name:
        return None
    key = _base_name(name)
    for service_name, row in business_services().items():
        base = _base_name(service_name)
        if key == base or key.startswith(base) or base.startswith(key):
            return row
    return None


def service_criticality(name: str | None) -> str | None:
    row = find_service(name)
    return norm_criticality(row["criticidad"]) if row else None


def service_owner(name: str | None) -> str | None:
    row = find_service(name)
    return row["responsable"] if row else None


# ---------------------------------------------------------------- criticality (matrix column)

@dataclass
class Criticality:
    level: str
    source: str
    reason: str
    from_privilege: bool = False  # True when the level comes from the identity's privilege (used by D-2)


def asset_criticality(asset: dict[str, Any]) -> Criticality:
    """CMDB criticality, raised to its business services' criticality if those are higher."""
    host = asset.get("hostname", "?")
    best = norm_criticality(asset.get("criticality")) or UNKNOWN_ENTITY_CRITICALITY
    reason = f"CMDB {best}"
    services = [asset.get("business_service")] + [s.get("servicio") for s in asset.get("services", []) or []]
    for name in filter(None, services):
        crit = service_criticality(name)
        if crit and _crank(crit) > _crank(best):
            best, reason = crit, f"servicio «{find_service(name)['servicio']}» {crit}"
    return Criticality(best, f"activo:{host}", reason)


def identity_criticality(user: dict[str, Any]) -> Criticality:
    """D-1: what the identity can access."""
    username = (user.get("username") or str(user.get("upn", "")).split("@")[0]).casefold()
    account_type = str(user.get("account_type") or "user").casefold()
    source = f"identidad:{username}"
    if username.startswith("adm.") or account_type == "admin":
        return Criticality("Crítica", source, "cuenta de administración (Identidad y directorio activo)", True)
    if account_type in ("service", "external") or username.startswith("svc_") or username.startswith("ext."):
        service = SERVICE_ACCOUNT_SERVICE.get(username)
        crit = service_criticality(service)
        if crit:
            return Criticality(crit, source, f"cuenta de servicio de «{find_service(service)['servicio']}»")
        return Criticality(UNKNOWN_SERVICE_ACCOUNT_CRITICALITY, source,
                           "cuenta de servicio sin servicio de negocio conocido (Alta por prudencia)")
    return Criticality("Media", source, "usuario estándar (Puesto de trabajo)")


def _is_vip_or_privileged(user: dict[str, Any]) -> bool:
    return _true(user.get("vip")) or _true(user.get("privileged"))


def _is_ot(asset: dict[str, Any]) -> bool:
    return asset.get("zone") == OT_ZONE or str(asset.get("type", "")) in OT_ASSET_TYPES


# ---------------------------------------------------------------- input / output

@dataclass
class TriageFacts:
    """What the pipeline knows about one alert (or one grouped ticket)."""
    rule_severity: str
    verdict: str = "needs_more_info"
    assets: list[dict[str, Any]] = field(default_factory=list)  # data.get_asset() rows
    identities: list[dict[str, Any]] = field(default_factory=list)  # data.get_user() rows
    services: list[str] = field(default_factory=list)  # business services hit directly (e.g. cloud, SaaS)
    customers_involved: bool = False  # e-commerce customers affected -> online store (Crítica)
    target_affected: bool = True  # D-3: False if the target doesn't exist or wasn't really affected
    adjustments: list[dict[str, Any]] = field(default_factory=list)  # [{"reason_type", "reason"}] from the LLM
    approved_change: str | None = None  # id of a matched change/flow (B2), e.g. "CHG-2026-2107"
    # Facts from structured fields proving personal or payment data is involved (EvidencePack
    # signals.personal_data_payments). Without them the LLM's personal_data_payments is ignored.
    personal_data_signals: list[str] = field(default_factory=list)
    # D-5: severity a runbook sets explicitly for this case; acts as a minimum, never lowers
    runbook_severity: str | None = None
    runbook_reason: str = ""  # e.g. "RB-01: petición de cambio de IBAN no verificada"
    # politica §5 mandatory-escalation facts
    malicious_execution: bool = False
    credential_theft: bool = False
    persistence: bool = False
    personal_data_exfil: bool = False
    financial_fraud: bool = False
    attack_chain: bool = False
    created_at: str | datetime | None = None  # alert created_at (UTC)


@dataclass
class PolicyDecision:
    severity: str
    severity_rationale: str
    severity_calc: dict[str, Any]
    sla: dict[str, Any]
    escalation: dict[str, Any]
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def ticket_fields(self) -> dict[str, Any]:
        """Fields of ticket_salida.schema.json that the policy owns."""
        return {
            "severity": self.severity,
            "severity_rationale": self.severity_rationale,
            "escalation": {
                "escalate": self.escalation["escalate"],
                "to": self.escalation["to"],
                "reason": "; ".join(self.escalation["reasons"]),
            },
        }


# ---------------------------------------------------------------- severity

def _column(facts: TriageFacts) -> tuple[Criticality, Criticality, list[Criticality]]:
    """Return (column used, column ignoring privilege-derived levels, all candidates)."""
    if not facts.target_affected:
        crit = Criticality("Baja", "objetivo no afectado", "el objetivo no existe o no se vio afectado (D-3)")
        return crit, crit, [crit]
    candidates = [asset_criticality(a) for a in facts.assets]
    candidates += [identity_criticality(u) for u in facts.identities]
    for name in facts.services:
        crit = service_criticality(name)
        if crit:
            candidates.append(Criticality(crit, f"servicio:{find_service(name)['servicio']}", "servicio de negocio"))
    if facts.customers_involved:
        candidates.append(Criticality("Crítica", "clientes", "clientes de la tienda online"))
    if not candidates:
        crit = Criticality(UNKNOWN_ENTITY_CRITICALITY, "sin inventario",
                           "ninguna entidad en la CMDB ni en el directorio (Media por defecto)")
        return crit, crit, [crit]
    used = max(candidates, key=lambda c: _crank(c.level))
    non_priv = [c for c in candidates if not c.from_privilege] or [
        Criticality("Media", c.source, "sin el privilegio: usuario estándar") for c in candidates
    ]
    without_privilege = max(non_priv, key=lambda c: _crank(c.level))
    return used, without_privilege, candidates


def _adjustments(facts: TriageFacts, used: Criticality, without_privilege: Criticality
                 ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    applied: dict[str, dict[str, Any]] = {}
    ignored: list[dict[str, Any]] = []
    for adj in facts.adjustments:
        reason_type = adj.get("reason_type")
        if reason_type not in ADJUSTMENT_DELTAS:
            ignored.append({**adj, "why": "tipo de ajuste desconocido"})
        elif reason_type == "vip_privileged":
            ignored.append({**adj, "why": "se calcula de forma determinista desde las identidades (D-2)"})
        elif reason_type == "personal_data_payments" and not facts.personal_data_signals:
            ignored.append({**adj, "why": "ningún hecho estructurado confirma datos personales o de pago "
                                          "(DLP, clasificación, PCI, IBAN, cuentas de cliente, activo con esos datos)"})
        elif reason_type == "personal_data_payments" and reason_type not in applied:
            applied[reason_type] = {"reason_type": reason_type, "delta": ADJUSTMENT_DELTAS[reason_type],
                                    "reason": f"{adj.get('reason', '')} [confirmado: "
                                              f"{'; '.join(facts.personal_data_signals[:3])}]"}
        elif reason_type not in applied:
            applied[reason_type] = {"reason_type": reason_type, "delta": ADJUSTMENT_DELTAS[reason_type],
                                    "reason": adj.get("reason", "")}
    special = [u for u in facts.identities if _is_vip_or_privileged(u)]
    if special and facts.target_affected:
        names = ", ".join(sorted({str(u.get("username") or u.get("upn")) for u in special}))
        if _crank(used.level) > _crank(without_privilege.level):
            ignored.append({"reason_type": "vip_privileged", "reason": names,
                            "why": "el privilegio ya fijó la columna de la matriz (D-2)"})
        else:
            applied["vip_privileged"] = {"reason_type": "vip_privileged", "delta": +1,
                                         "reason": f"identidad VIP o privilegiada: {names}"}
    return list(applied.values()), ignored


def evaluate(facts: TriageFacts) -> PolicyDecision:
    """Apply the SOC policy §2, §3 and §5 to one alert or grouped ticket."""
    rule = norm_severity(facts.rule_severity)
    verdict = facts.verdict if facts.verdict in VERDICTS else "needs_more_info"
    warnings: list[str] = []
    if facts.verdict not in VERDICTS:
        warnings.append(f"veredicto desconocido {facts.verdict!r}: se trata como needs_more_info")

    used, without_privilege, candidates = _column(facts)
    matrix_result = MATRIX[rule][_crank(used.level)]
    applied, ignored = _adjustments(facts, used, without_privilege)
    raw = sum(a["delta"] for a in applied)
    net = max(-1, min(1, raw))  # "máximo un nivel arriba o abajo en total"
    after = _shift(matrix_result, net)

    if verdict == "false_positive":
        final, verdict_rule = "informational", "falso positivo: informational"
    elif verdict == "benign_true_positive":
        final = "low" if _srank(after) >= _srank("medium") else "informational"
        verdict_rule = f"actividad autorizada{f' ({facts.approved_change})' if facts.approved_change else ''}: {final}"
    else:
        final, verdict_rule = after, "sin cambio por veredicto"
        if facts.approved_change:
            warnings.append(f"coincide con {facts.approved_change} pero el veredicto es {verdict}: "
                            "comprobar que la actividad encaja con el cambio")

    runbook_floor = None
    if facts.runbook_severity:
        floor = norm_severity(facts.runbook_severity)
        applies = verdict in ("true_positive", "needs_more_info") and _srank(floor) > _srank(final)
        runbook_floor = {"severity": floor, "reason": facts.runbook_reason, "applied": applies}
        if applies:
            final = floor  # D-5: the runbook's explicit severity is a minimum

    calc = {
        "rule_severity": rule,
        "criticality": used.level,
        "criticality_source": used.source,
        "criticality_reason": used.reason,
        "criticality_candidates": [asdict(c) for c in candidates],
        "matrix_result": matrix_result,
        "adjustments_applied": applied,
        "adjustments_ignored": ignored,
        "net_adjustment": net,
        "after_adjustments": after,
        "verdict": verdict,
        "verdict_rule": verdict_rule,
        "runbook_floor": runbook_floor,
        "final": final,
    }
    return PolicyDecision(
        severity=final,
        severity_rationale=_rationale(calc, raw),
        severity_calc=calc,
        sla=sla_for(final, facts.created_at),
        escalation=_escalation(facts, verdict, final),
        warnings=warnings,
    )


def _rationale(calc: dict[str, Any], raw: int) -> str:
    parts = [f"Regla {calc['rule_severity']} sobre {calc['criticality']} "
             f"({calc['criticality_source']}: {calc['criticality_reason']}) = {calc['matrix_result']}"]
    for adj in calc["adjustments_applied"]:
        parts.append(f"{adj['delta']:+d} {adj['reason_type']} ({adj['reason']})" if adj["reason"]
                     else f"{adj['delta']:+d} {adj['reason_type']}")
    if raw != calc["net_adjustment"]:
        parts.append(f"ajuste total limitado a {calc['net_adjustment']:+d}")
    if calc["adjustments_applied"]:
        parts.append(f"= {calc['after_adjustments']}")
    if calc["verdict_rule"] != "sin cambio por veredicto":
        parts.append(calc["verdict_rule"])
    floor = calc.get("runbook_floor")
    if floor and floor["applied"]:
        parts.append(f"mínimo fijado por el runbook ({floor['reason']}): {floor['severity']}" if floor["reason"]
                     else f"mínimo fijado por el runbook: {floor['severity']}")
    return "; ".join(parts) + f". Final: {calc['final']}."


# ---------------------------------------------------------------- SLA (§3)

SLA_TABLE: dict[str, dict[str, Any]] = {
    "critical": {"minutes": 15, "escalation": "Inmediato a N2 de guardia por teléfono",
                 "notify": ["Responsable SOC", "CISO"]},
    "high": {"minutes": 30, "escalation": "A N2 en la misma jornada", "notify": ["Responsable SOC"]},
    "medium": {"minutes": 240, "escalation": "Si tras el triaje hay indicios de compromiso", "notify": []},
    "low": {"minutes": 1440, "escalation": "No", "notify": []},
    "informational": {"minutes": 1440, "escalation": "No (revisión en lote diaria)", "notify": []},
}


def sla_for(severity: str, created_at: str | datetime | None = None) -> dict[str, Any]:
    row = SLA_TABLE[norm_severity(severity)]
    out = {"severity": severity, "triage_within_minutes": row["minutes"],
           "escalation_path": row["escalation"], "notify": list(row["notify"]), "due": None, "due_local": None}
    if created_at is not None:
        # Add the minutes in UTC: aware arithmetic in Europe/Madrid is wall-clock arithmetic and would
        # stretch or shrink the deadline across the 25 Oct DST change. Convert only to display.
        start = parse_utc(created_at)
        if start is None:
            raise ValueError(f"unreadable timestamp: {created_at!r}")
        due = start + timedelta(minutes=row["minutes"])
        out["due"] = due.isoformat().replace("+00:00", "Z")
        out["due_local"] = due.astimezone(MADRID).isoformat()
    return out


# ---------------------------------------------------------------- escalation (§5)

def _escalation(facts: TriageFacts, verdict: str, severity: str) -> dict[str, Any]:
    reasons: list[str] = []
    notify: list[str] = list(SLA_TABLE[severity]["notify"])
    ot = any(_is_ot(a) for a in facts.assets)
    if verdict in ("false_positive", "benign_true_positive"):
        return {"escalate": False, "to": "", "reasons": [], "notify": []}
    if verdict == "true_positive" and severity in ("high", "critical"):
        reasons.append(f"true_positive de severidad {severity}")
    if facts.malicious_execution:
        reasons.append("ejecución confirmada de código malicioso")
    if facts.credential_theft:
        reasons.append("robo de credenciales")
    if facts.persistence:
        reasons.append("persistencia")
    if facts.personal_data_exfil:
        reasons.append("posible salida de datos personales (implica DPO, plazo 72 h AEPD/CNPD)")
        notify.append("DPO")
    if facts.financial_fraud:
        reasons.append("fraude económico")
    if facts.attack_chain:
        reasons.append("varias alertas forman una cadena de ataque")
    if verdict == "needs_more_info" and severity in ("high", "critical"):
        # every LLM error ends as needs_more_info: a serious alert must not wait unseen in the queue
        reasons.append(f"sin veredicto automático en una alerta de severidad {severity}: requiere un analista")
    if ot and verdict in ("true_positive", "needs_more_info"):
        reasons.append("red OT implicada: solo escalar, nunca actuar (RB-08)")
        notify.append("Responsable de Operaciones")
    escalate = bool(reasons)
    to = ""
    if escalate:
        to = "N2 de guardia (teléfono)" if severity == "critical" else "N2"
        if ot:
            to += " + Responsable de Operaciones"
    return {"escalate": escalate, "to": to, "reasons": reasons, "notify": sorted(set(notify))}


# ---------------------------------------------------------------- containment approvals (§4, D-4)

def _target_host(target: str) -> str:
    """'https://www.Mega.nz/file/x' -> 'www.mega.nz'; a bare domain or IP comes back lower-cased."""
    text = str(target).strip().casefold()
    if "://" in text:
        text = text.split("://", 1)[1]
    return text.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0].rstrip(".")


def is_dual_use(target: str) -> bool:
    """True if blocking `target` would block a dual-use service globally (domain or product name)."""
    host = _target_host(target)
    if any(host == d or host.endswith("." + d) for d in DUAL_USE_DOMAINS):
        return True
    words = re.split(r"[^a-z0-9]+", str(target).casefold())
    return any(p in words for p in DUAL_USE_PRODUCTS)


def action_policy(action: str, target: str, asset: dict[str, Any] | None = None,
                  user: dict[str, Any] | None = None) -> dict[str, Any]:
    """Who may run `action` on `target`. Every action needs a human click in the UI (D-4)."""
    out: dict[str, Any] = {"action": action, "target": target, "allowed": True, "n1_may_execute": False,
                           "requires_approval": True, "approvers": ["N2"], "human_confirmation_required": True,
                           "notes": []}
    if action in WORKFLOW_ACTIONS:
        return {**out, "n1_may_execute": True, "requires_approval": False, "approvers": [],
                "human_confirmation_required": False,
                "notes": ["Paso del flujo de trabajo: no ejecuta ninguna acción de contención."]}
    if action not in ACTIONS:
        return {**out, "allowed": False, "approvers": [], "notes": [f"acción no soportada: {action}"]}
    if asset and _is_ot(asset):
        return {**out, "allowed": False, "approvers": ["Responsable de Operaciones"],
                "notes": ["Nunca actuar sobre la red OT desde el SOC: solo escalar a Operaciones."]}

    if action in N1_EXECUTABLE:
        out.update(n1_may_execute=True, requires_approval=False, approvers=[])
        out["notes"].append("El N1 puede ejecutarla; aun así, un analista la confirma con un clic (D-4).")
        if action == "block_ioc" and is_dual_use(target):
            out.update(n1_may_execute=False, requires_approval=True, approvers=["N2"])
            out["notes"].append("Servicio de uso dual: no se bloquea globalmente sin N2.")
        return out

    if action == "isolate_host" and asset:
        host = str(asset.get("hostname", target))
        kind = str(asset.get("type", ""))
        service = asset.get("business_service")
        owner = service_owner(service) or "responsable del servicio (no registrado)"
        if kind == "TPV" or host.startswith("POS-") or kind == "Frontal web" or host.startswith("WEB-ECOM"):
            out["approvers"] = ["N2", f"Negocio ({owner})"]
            out["notes"].append("TPV o frontal web: impacto directo en ventas.")
        elif kind != "Portátil" and asset.get("zone") != "HQ-USERS":
            out["approvers"] = ["N2", owner]
            out["notes"].append(f"Servidor: aprueba también el responsable del servicio «{service}».")
    elif action == "isolate_host":
        out["notes"].append("Equipo no encontrado en la CMDB: confirmar qué es antes de aislar.")
    if action == "disable_user" and user is not None and str(user.get("account_type")) == "service":
        out["notes"].append("Cuenta de servicio: deshabilitarla puede parar un proceso de negocio.")
    return out


def recommended_action(action: str, target: str, justification: str, asset: dict[str, Any] | None = None,
                       user: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """ticket_salida.schema.json `recommended_actions` item, or None if the policy forbids the action."""
    policy = action_policy(action, target, asset, user)
    if not policy["allowed"]:
        return None
    return {"action": action, "target": target, "requires_approval": policy["requires_approval"],
            "justification": justification, "approvers": policy["approvers"]}


def actions_for(items: Iterable[tuple[str, str]], asset_lookup=None, user_lookup=None) -> list[dict[str, Any]]:
    """Convenience: evaluate many (action, target) pairs with optional lookups (e.g. data.get_asset)."""
    out = []
    for action, target in items:
        asset = asset_lookup(target) if asset_lookup and action == "isolate_host" else None
        user = user_lookup(target) if user_lookup and action == "disable_user" else None
        out.append(action_policy(action, target, asset, user))
    return out
