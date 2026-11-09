"""Turn a ticket into what the detail page shows. No Streamlit here, so it can be tested directly.

Everything tolerates missing fields, because only the official fields are guaranteed on a ticket.
"""
from __future__ import annotations

import json
from typing import Any

from triage import policy
from ui.queue_logic import SEVERITY_LABELS, VERDICT_LABELS


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def severity_steps(ticket: dict[str, Any]) -> list[dict[str, str]]:
    """The severity calculation, step by step, as the policy engine worked it out."""
    calc = as_dict(ticket.get("severity_calc"))
    if not calc:
        return []
    source = calc.get("criticality_source") or ""
    reason = calc.get("criticality_reason") or ""
    steps = [
        ("Severidad de la regla", calc.get("rule_severity")),
        ("Criticidad usada", " · ".join(str(part) for part in (calc.get("criticality"), source, reason) if part)),
        ("Resultado de la matriz", calc.get("matrix_result")),
        ("Ajuste total", calc.get("net_adjustment")),
        ("Tras los ajustes", calc.get("after_adjustments")),
        ("Regla por veredicto", calc.get("verdict_rule")),
        ("Severidad final", calc.get("final", ticket.get("severity"))),
    ]
    return [{"Paso": name, "Valor": _severity_text(value)} for name, value in steps if value not in (None, "")]


def _severity_text(value: Any) -> str:
    return SEVERITY_LABELS.get(value, str(value)) if isinstance(value, str) else str(value)


def adjustment_rows(ticket: dict[str, Any]) -> list[dict[str, str]]:
    """Adjustments the policy applied or ignored, and why. Ignored ones show the LLM can't force a change."""
    calc = as_dict(ticket.get("severity_calc"))
    rows = []
    for item in as_list(calc.get("adjustments_applied")) or as_list(calc.get("adjustments")):
        item = as_dict(item)
        delta = item.get("delta", "")
        rows.append({"Ajuste": f"{delta:+d}" if isinstance(delta, int) else str(delta), "Estado": "Aplicado",
                     "Tipo": str(item.get("reason_type", "")), "Motivo": str(item.get("reason", ""))})
    for item in as_list(calc.get("adjustments_ignored")):
        item = as_dict(item)
        rows.append({"Ajuste": "—", "Estado": "Ignorado", "Tipo": str(item.get("reason_type", "")),
                     "Motivo": str(item.get("why") or item.get("reason") or "")})
    return rows


def sla_text(ticket: dict[str, Any]) -> dict[str, str]:
    sla = as_dict(ticket.get("sla"))
    minutes = sla.get("triage_within_minutes")
    return {
        "plazo": f"{minutes} min" if isinstance(minutes, (int, float)) else "—",
        "escalado": str(sla.get("escalation_path") or "—"),
        "notificar": ", ".join(str(n) for n in as_list(sla.get("notify"))) or "—",
    }


def decision_panel(ticket: dict[str, Any]) -> dict[str, list[str]]:
    """What the AI and code already decided, and what is left for a person."""
    verdict = VERDICT_LABELS.get(ticket.get("verdict"), str(ticket.get("verdict")))
    severity = SEVERITY_LABELS.get(ticket.get("severity"), str(ticket.get("severity")))
    confidence = ticket.get("confidence")
    confidence_text = f" (confianza {confidence:.0%})" if isinstance(confidence, (int, float)) else ""
    automatic = [
        f"La IA propone el veredicto: {verdict}{confidence_text}.",
        f"Las reglas del SOC, no la IA, calculan la severidad: {severity}.",
    ]
    escalation = as_dict(ticket.get("escalation"))
    if escalation.get("escalate"):
        destination = f" a {escalation['to']}" if escalation.get("to") else ""
        automatic.append(f"Las reglas indican escalar{destination}.")
    else:
        automatic.append("Las reglas no piden escalar.")

    review = as_dict(ticket.get("human_review"))
    human = []
    if review.get("stale"):
        human.append("La conclusión de la IA cambió tras la última revisión: vuelve a revisarla.")
    elif review.get("status") in (None, "pending"):
        human.append("Aceptar o corregir el veredicto y la severidad.")
    else:
        human.append(f"Revisado por {review.get('reviewer')}. Puedes volver a revisarlo.")
    containment = [a for a in as_list(ticket.get("recommended_actions"))
                   if as_dict(a).get("action") in policy.ACTIONS]
    if containment:
        human.append(f"Aprobar o rechazar {len(containment)} acciones de contención. La IA no puede ejecutarlas.")
    else:
        human.append("No hay acciones de contención que aprobar.")
    open_questions = as_list(ticket.get("open_questions"))
    if open_questions:
        human.append(f"Resolver {len(open_questions)} preguntas abiertas que la IA no pudo responder.")
    return {"automatic": automatic, "human": human}


def evidence_items(ticket: dict[str, Any]) -> list[dict[str, str]]:
    items = []
    for item in as_list(ticket.get("evidence")):
        item = as_dict(item)
        items.append({"source": str(item.get("source") or "—"), "event_id": str(item.get("event_id") or ""),
                      "finding": str(item.get("finding") or "")})
    return items


def enrichment_rows(ticket: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"Indicador": str(as_dict(i).get("indicator", "")), "Tipo": str(as_dict(i).get("type", "")),
         "Fuente": str(as_dict(i).get("source", "")), "Resultado": str(as_dict(i).get("result", ""))}
        for i in as_list(ticket.get("enrichment"))
    ]


def trace_rows(ticket: dict[str, Any]) -> list[dict[str, Any]]:
    """Each query the system made, which is the demo's "what did it check"."""
    return [
        {"Paso": str(as_dict(t).get("step", "")), "Herramienta": str(as_dict(t).get("tool", "")),
         "Parámetros": json.dumps(as_dict(t).get("params", {}), ensure_ascii=False),
         "Resultados": as_dict(t).get("result_count"), "ms": as_dict(t).get("ms")}
        for t in as_list(ticket.get("trace"))
    ]


def injection_rows(ticket: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"field": str(as_dict(flag).get("field", "—")) if isinstance(flag, dict) else "—",
         "excerpt": str(as_dict(flag).get("excerpt", "")) if isinstance(flag, dict) else str(flag)}
        for flag in as_list(ticket.get("injection_flags"))
    ]


def affected_rows(ticket: dict[str, Any]) -> list[dict[str, str]]:
    affected = as_dict(ticket.get("affected"))
    labels = {"users": "Usuarios", "hosts": "Equipos", "business_services": "Servicios", "customers": "Clientes"}
    return [{"Tipo": label, "Afectados": ", ".join(str(v) for v in as_list(affected.get(key)))}
            for key, label in labels.items() if as_list(affected.get(key))]
