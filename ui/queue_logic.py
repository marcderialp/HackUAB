"""Turn tickets into sorted, filtered queue rows. No Streamlit here, so it can be tested directly."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

from triage.normalize import utc_to_madrid
from triage.store import SEVERITIES, VERDICTS, effective

SEVERITY_LABELS = {
    "critical": "🔴 Crítica", "high": "🟠 Alta", "medium": "🟡 Media",
    "low": "🔵 Baja", "informational": "⚪ Informativa",
}
VERDICT_LABELS = {
    "true_positive": "Verdadero positivo", "benign_true_positive": "Positivo benigno",
    "false_positive": "Falso positivo", "needs_more_info": "Falta información",
}
REVIEW_LABELS = {
    "pending": "Pendiente", "accepted": "Aceptado", "overridden": "Corregido", "stale": "⚠️ Revisar de nuevo",
}
SLA_LABELS = {"in_time": "En plazo", "late": "Fuera de plazo", "unknown": "Sin dato"}
ROUTING_LABELS = {"cluster": "Grupo", "deep_dive": "Análisis profundo", "live": "En directo", "": "—"}


def sla_info(ticket: dict[str, Any]) -> dict[str, Any]:
    """Return a ticket's triage deadline and whether triage finished within its SLA window.

    The dataset is a replay of past weeks, so comparing deadlines with today's clock would mark every
    ticket as overdue. The state compares the triage time with the window the policy allows instead.
    """
    sla = ticket.get("sla") if isinstance(ticket.get("sla"), dict) else {}
    due = sla.get("due") or ticket.get("sla_due")
    minutes = sla.get("triage_within_minutes")
    seconds = ticket.get("triage_seconds")
    if isinstance(minutes, (int, float)) and isinstance(seconds, (int, float)):
        state = "in_time" if seconds <= minutes * 60 else "late"
    else:
        state = "unknown"
    return {"due": due, "due_sort": _due_sort_key(due), "due_local": _local_text(sla.get("due_local"), due), "state": state}


def _due_sort_key(due: Any) -> str:
    # ISO text in UTC sorts by time. Anything missing sorts last.
    return due if isinstance(due, str) and due else "9999"


def _local_text(due_local: Any, due: Any) -> str:
    try:
        if isinstance(due_local, str) and due_local:
            return datetime.fromisoformat(due_local).strftime("%d/%m %H:%M")
        if isinstance(due, str) and due:
            return utc_to_madrid(due).strftime("%d/%m %H:%M")
    except ValueError:
        pass
    return "—"


def review_state(ticket: dict[str, Any]) -> str:
    review = ticket.get("human_review") or {}
    if review.get("stale"):
        return "stale"
    return review.get("status") or "pending"


def queue_row(ticket: dict[str, Any]) -> dict[str, Any]:
    final = effective(ticket)
    sla = sla_info(ticket)
    affected = ticket.get("affected") if isinstance(ticket.get("affected"), dict) else {}
    alert_ids = ticket.get("alert_ids") or []
    search_parts = [
        ticket.get("ticket_id"), ticket.get("title"), ticket.get("incident_id"), *alert_ids,
        *affected.get("users", []), *affected.get("hosts", []),
    ]
    return {
        "ticket_id": ticket.get("ticket_id", ""),
        "title": ticket.get("title", ""),
        "severity": final["severity"],
        "verdict": final["verdict"],
        "changed_by_human": final["decided_by"] != "ai",
        "confidence": ticket.get("confidence"),
        "alerts": len(alert_ids),
        "review": review_state(ticket),
        "escalated": bool((ticket.get("escalation") or {}).get("escalate")),
        "escalated_to": (ticket.get("escalation") or {}).get("to") or "",
        "due_sort": sla["due_sort"],
        "due_local": sla["due_local"],
        "sla_state": sla["state"],
        "routing": ticket.get("routing") or "",
        "injection": bool(ticket.get("injection_flags")),
        "incident_id": ticket.get("incident_id") or "",
        "search_text": " ".join(str(part) for part in search_parts if part).lower(),
    }


def sort_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Most severe first, then the nearest deadline."""
    rank = {severity: index for index, severity in enumerate(SEVERITIES)}
    return sorted(rows, key=lambda r: (-rank.get(r["severity"], -1), r["due_sort"], r["ticket_id"]))


def build_rows(tickets: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sort_rows(queue_row(ticket) for ticket in tickets)


@dataclass
class Filters:
    """An empty selection means "show everything" for that filter."""

    severities: set[str] = field(default_factory=set)
    verdicts: set[str] = field(default_factory=set)
    reviews: set[str] = field(default_factory=set)
    sla_states: set[str] = field(default_factory=set)
    routings: set[str] = field(default_factory=set)
    only_escalated: bool = False
    only_injection: bool = False
    text: str = ""


def filter_rows(rows: Iterable[dict[str, Any]], filters: Filters) -> list[dict[str, Any]]:
    needle = filters.text.strip().lower()
    result = []
    for row in rows:
        if filters.severities and row["severity"] not in filters.severities:
            continue
        if filters.verdicts and row["verdict"] not in filters.verdicts:
            continue
        if filters.reviews and row["review"] not in filters.reviews:
            continue
        if filters.sla_states and row["sla_state"] not in filters.sla_states:
            continue
        if filters.routings and row["routing"] not in filters.routings:
            continue
        if filters.only_escalated and not row["escalated"]:
            continue
        if filters.only_injection and not row["injection"]:
            continue
        if needle and needle not in row["search_text"]:
            continue
        result.append(row)
    return result


def summarize(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "tickets": len(rows),
        "alerts": sum(row["alerts"] for row in rows),
        "pending": sum(1 for row in rows if row["review"] in ("pending", "stale")),
        "escalated": sum(1 for row in rows if row["escalated"]),
        "urgent": sum(1 for row in rows if row["severity"] in ("critical", "high")),
        "injection": sum(1 for row in rows if row["injection"]),
    }


def display_row(row: dict[str, Any]) -> dict[str, Any]:
    """The columns shown in the table, in Spanish."""
    verdict = VERDICT_LABELS.get(row["verdict"], str(row["verdict"]))
    escalated = f"Sí: {row['escalated_to']}" if row["escalated"] and row["escalated_to"] else ("Sí" if row["escalated"] else "No")
    return {
        "Severidad": SEVERITY_LABELS.get(row["severity"], str(row["severity"])),
        "Veredicto": f"{verdict} ✎" if row["changed_by_human"] else verdict,
        "Qué pasa": f"⚠️ {row['title']}" if row["injection"] else row["title"],
        "Confianza": row["confidence"],
        "Alertas": row["alerts"],
        "Revisión": REVIEW_LABELS.get(row["review"], str(row["review"])),
        "Escalado": escalated,
        "Vence": row["due_local"],
        "SLA": SLA_LABELS[row["sla_state"]],
        "Ruta": ROUTING_LABELS.get(row["routing"], str(row["routing"])),
        "Ticket": row["ticket_id"],
    }


def selection_key(rows: Iterable[dict[str, Any]]) -> str:
    """Widget key for the queue table: the same only while the same tickets are in the same order."""
    ids = "\n".join(str(row["ticket_id"]) for row in rows)
    return "queue_table_" + hashlib.sha256(ids.encode("utf-8")).hexdigest()[:16]


def spanish_number(value: int) -> str:
    return f"{value:,}".replace(",", ".")


__all__ = [
    "Filters", "REVIEW_LABELS", "ROUTING_LABELS", "SEVERITIES", "SEVERITY_LABELS", "SLA_LABELS", "VERDICTS",
    "VERDICT_LABELS", "build_rows", "display_row", "filter_rows", "queue_row", "review_state", "selection_key",
    "sla_info", "sort_rows", "spanish_number", "summarize",
]
