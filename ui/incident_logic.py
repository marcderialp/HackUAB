"""E5 logic: turn incidents and their tickets into rows. No Streamlit here, so it can be tested directly."""
from __future__ import annotations

import hashlib
from typing import Any, Callable, Iterable

from triage.normalize import utc_to_madrid
from triage.store import SEVERITIES, effective
from ui.queue_logic import SEVERITY_LABELS, VERDICT_LABELS

STAGE_LABELS = {"grouped": "Agrupado", "investigated": "Investigado"}
NO_TICKETS = "Sin triar"


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def local_time(value: Any) -> str:
    try:
        return utc_to_madrid(value).strftime("%d/%m %H:%M") if value else "—"
    except (ValueError, TypeError, AttributeError):
        return "—"


def tickets_by_alert(tickets: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Each alert's ticket. A ticket covers every alert it lists."""
    found: dict[str, dict[str, Any]] = {}
    for ticket in tickets:
        for alert_id in as_list(ticket.get("alert_ids")):
            found.setdefault(alert_id, ticket)
    return found


def incident_tickets(incident: dict[str, Any], by_alert: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {by_alert[a]["ticket_id"]: by_alert[a] for a in as_list(incident.get("alert_ids")) if a in by_alert}
    return list(unique.values())


def worst_severity(tickets: Iterable[dict[str, Any]]) -> str | None:
    """The most severe conclusion, counting a person's correction."""
    ranks = [SEVERITIES.index(final["severity"]) for final in (effective(t) for t in tickets) if final["severity"] in SEVERITIES]
    return SEVERITIES[max(ranks)] if ranks else None


def incident_row(incident: dict[str, Any], by_alert: dict[str, dict[str, Any]]) -> dict[str, Any]:
    tickets = incident_tickets(incident, by_alert)
    alert_ids = as_list(incident.get("alert_ids"))
    triaged = sum(1 for alert_id in alert_ids if alert_id in by_alert)
    entities = [str(e) for e in as_list(incident.get("shared_entities"))]
    rules = [str(r) for r in as_list(incident.get("rule_ids"))]
    return {
        "incident_id": incident["incident_id"], "title": str(incident.get("title", "")),
        "stage": incident.get("stage", "investigated"), "severity": worst_severity(tickets),
        "alerts": len(alert_ids), "triaged": triaged, "rules": rules, "entities": entities,
        "first_seen": incident.get("first_seen") or "", "last_seen": incident.get("last_seen") or "",
        "search_text": " ".join([incident["incident_id"], str(incident.get("title", "")), *rules, *entities,
                                 *map(str, alert_ids)]).lower(),
    }


def build_rows(incidents: Iterable[dict[str, Any]], tickets: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Most severe first, then the largest, then the oldest. Untriaged incidents go after triaged ones."""
    by_alert = tickets_by_alert(tickets)
    rows = [incident_row(incident, by_alert) for incident in incidents]

    def order(row: dict[str, Any]) -> tuple:
        severity = SEVERITIES.index(row["severity"]) if row["severity"] else -1
        return (-severity, -row["alerts"], str(row["first_seen"]), row["incident_id"])

    return sorted(rows, key=order)


def filter_rows(rows: Iterable[dict[str, Any]], text: str) -> list[dict[str, Any]]:
    needle = text.strip().lower()
    return [row for row in rows if needle in row["search_text"]]


def summarize(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "incidents": len(rows), "alerts": sum(r["alerts"] for r in rows), "triaged": sum(r["triaged"] for r in rows),
        "urgent": sum(1 for r in rows if r["severity"] in ("critical", "high")),
    }


def display_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "Severidad": SEVERITY_LABELS.get(row["severity"], NO_TICKETS),
        "Qué pasa": row["title"],
        "Alertas": row["alerts"],
        "Triadas": f"{row['triaged']} de {row['alerts']}",
        "Reglas": ", ".join(row["rules"]),
        "Desde": local_time(row["first_seen"]),
        "Hasta": local_time(row["last_seen"]),
        "Etapa": STAGE_LABELS.get(row["stage"], str(row["stage"])),
        "Incidente": row["incident_id"],
    }


def selection_key(rows: Iterable[dict[str, Any]]) -> str:
    """Widget key for the table: the same only while the same incidents are in the same order."""
    ids = "\n".join(row["incident_id"] for row in rows)
    return "incident_table_" + hashlib.sha256(ids.encode("utf-8")).hexdigest()[:16]


def alert_rows(incident: dict[str, Any], by_alert: dict[str, dict[str, Any]],
               get_alert: Callable[[str], dict[str, Any] | None]) -> list[dict[str, Any]]:
    """One row per alert, in time order. An alert missing from the queue still gets its row."""
    rows = []
    for alert_id in as_list(incident.get("alert_ids")):
        alert = as_dict(get_alert(alert_id))
        ticket = by_alert.get(alert_id)
        final = effective(ticket) if ticket else {}
        rows.append({
            "_sort": str(alert.get("created_at") or "9999"),
            "Cuándo": local_time(alert.get("created_at")),
            "Alerta": alert_id,
            "Regla": str(alert.get("rule_id") or "—"),
            "Qué detectó": str(alert.get("rule_name") or "No está en la cola de alertas"),
            "Severidad de la regla": SEVERITY_LABELS.get(alert.get("severity"), str(alert.get("severity") or "—")),
            "Veredicto": VERDICT_LABELS.get(final.get("verdict"), NO_TICKETS),
            "Severidad final": SEVERITY_LABELS.get(final.get("severity"), "—"),
            "Ticket": ticket["ticket_id"] if ticket else "",
        })
    rows.sort(key=lambda row: (row["_sort"], row["Alerta"]))
    return [{k: v for k, v in row.items() if k != "_sort"} for row in rows]


def entity_rows(incident: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    for entity in as_list(incident.get("shared_entities")):
        kind, _, value = str(entity).partition(":")
        rows.append({"Tipo": kind, "Valor": value} if value else {"Tipo": "—", "Valor": kind})
    return rows


def report_sections(incident: dict[str, Any]) -> dict[str, Any]:
    """The level 3 report, when an incident has one. Grouped incidents leave all of this empty."""
    scope = as_dict(incident.get("scope"))
    return {
        "facts": [(label, str(incident[key])) for label, key in (
            ("Paciente cero", "patient_zero"), ("Acceso inicial", "initial_access"), ("Causa raíz", "root_cause"),
        ) if incident.get(key)],
        "timeline": [{"Cuándo": local_time(as_dict(e).get("timestamp")), "Evento": str(as_dict(e).get("event_id", "")),
                      "Qué pasó": str(as_dict(e).get("description", "")), "MITRE": str(as_dict(e).get("mitre", ""))}
                     for e in as_list(incident.get("timeline"))],
        "scope": [{"Alcance": label, "Detalle": ", ".join(map(str, value)) if isinstance(value, list) else str(value)}
                  for label, value in (("Usuarios", scope.get("users")), ("Equipos", scope.get("hosts")),
                                       ("Datos", scope.get("data")), ("Impacto", scope.get("business_impact"))) if value],
        "containment": [{"Acción": str(as_dict(a).get("action", "")), "Objetivo": str(as_dict(a).get("target", "")),
                         "Aprueba": str(as_dict(a).get("approver", "")), "Impacto": str(as_dict(a).get("business_impact", ""))}
                        for a in as_list(incident.get("containment_plan"))],
        "lists": [(label, [str(i) for i in as_list(incident.get(key))]) for label, key in (
            ("Notificaciones", "notifications"), ("Huecos de detección", "detection_gaps"), ("Preguntas abiertas", "open_questions"),
        ) if as_list(incident.get(key))],
    }
