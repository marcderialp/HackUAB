"""E3: where a person accepts or corrects the AI, and approves or rejects containment."""
from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

from triage.store import SEVERITIES, VERDICTS, Store
from ui.common import md_escape
from ui.containment import (
    ContainmentFailed, ContainmentRefused, approve_and_execute, build_override, check_action, containment_log,
    is_containment, latest_decision, reject,
)
from ui.queue_logic import SEVERITY_LABELS, VERDICT_LABELS

ACTION_LABELS = {
    "isolate_host": "Aislar equipo", "disable_user": "Deshabilitar usuario", "revoke_sessions": "Revocar sesiones",
    "reset_password": "Restablecer contraseña", "block_ioc": "Bloquear indicador", "purge_email": "Eliminar correo",
    "disable_access_key": "Deshabilitar clave de acceso", "close": "Cerrar", "escalate": "Escalar",
    "notify": "Notificar", "investigate": "Investigar", "tune_rule": "Ajustar la regla",
}
DECISION_LABELS = {"approved": "Aprobada", "rejected": "Rechazada", "executed": "Ejecutada", "failed": "Falló"}
NAME_KEY = "analyst_name_saved"
FLASH_KEY = "human_action_flash"


def _flash(kind: str, message: str) -> None:
    st.session_state[FLASH_KEY] = (kind, message)


def show_flash() -> None:
    flash = st.session_state.pop(FLASH_KEY, None)
    if flash:
        # st.text keeps API errors and targets from being rendered as Markdown.
        (st.success if flash[0] == "ok" else st.error)("Hecho." if flash[0] == "ok" else "No se ha hecho.")
        st.text(flash[1])


def analyst_name() -> str:
    name = st.text_input("Tu nombre (queda registrado en cada decisión)", value=st.session_state.get(NAME_KEY, ""))
    st.session_state[NAME_KEY] = name
    return name


def render_review(store: Store, ticket: dict[str, Any], name: str) -> None:
    st.subheader("Revisar la conclusión de la IA")
    current = ticket.get("human_review") or {}
    if current.get("stale"):
        st.warning("La conclusión de la IA cambió después de esta revisión. Vuelve a revisarla.")
    with st.form("review_form"):
        override = current.get("override") or {}
        left, right = st.columns(2)
        verdict = left.selectbox(
            "Veredicto", VERDICTS, index=VERDICTS.index(override.get("verdict", ticket["verdict"])),
            format_func=VERDICT_LABELS.get,
        )
        severity = right.selectbox(
            "Severidad", SEVERITIES, index=SEVERITIES.index(override.get("severity", ticket["severity"])),
            format_func=SEVERITY_LABELS.get,
        )
        reason = st.text_input("Motivo (obligatorio para corregir)")
        accept_col, correct_col = st.columns(2)
        accepted = accept_col.form_submit_button("✅ Aceptar lo que propone la IA", width="stretch")
        corrected = correct_col.form_submit_button("✏️ Guardar mi corrección", width="stretch")
    if accepted or corrected:
        try:
            if accepted:
                store.record_review(ticket["ticket_id"], "accepted", name, reason=reason)
                _flash("ok", "Has aceptado la conclusión de la IA.")
            else:
                changes = build_override(ticket, verdict, severity)
                if not changes:
                    raise ValueError("No has cambiado ni el veredicto ni la severidad.")
                store.record_review(ticket["ticket_id"], "overridden", name, reason=reason, override=changes)
                _flash("ok", "Corrección guardada. El veredicto original de la IA se conserva para la evaluación.")
        except ValueError as error:
            _flash("error", _plain_reason(str(error)))
        st.rerun()


def _plain_reason(message: str) -> str:
    return {
        "reviewer is required": "Escribe tu nombre: cada decisión necesita una persona responsable.",
        "reason is required": "Escribe el motivo de la corrección.",
        "approver is required": "Escribe tu nombre: cada decisión necesita una persona responsable.",
    }.get(message, message)


def render_actions(store: Store, ticket: dict[str, Any], name: str) -> None:
    items = [a for a in ticket.get("recommended_actions", []) if isinstance(a, dict)]
    containment = [a for a in items if is_containment(a.get("action"))]
    steps = [a for a in items if not is_containment(a.get("action"))]

    st.subheader("Contención propuesta")
    if not containment:
        st.caption("La IA no propone acciones de contención en este ticket.")
    for index, item in enumerate(containment):
        _render_action(store, ticket, item, index, name)
    if steps:
        st.caption("Otros pasos propuestos. No ejecutan nada sobre ningún sistema.")
        for item in steps:
            st.text(f"• {ACTION_LABELS.get(item.get('action'), item.get('action'))}: {item.get('target', '')}. {item.get('justification', '')}")


def _render_action(store: Store, ticket: dict[str, Any], item: dict[str, Any], index: int, name: str) -> None:
    action, target = item["action"], str(item.get("target", ""))
    check = check_action(action, target)
    decision = latest_decision(ticket, action, target)
    with st.container(border=True):
        st.caption(md_escape(ACTION_LABELS.get(action, action)))
        st.text(target)
        if item.get("justification"):
            st.text(item["justification"])
        for note in check.get("notes", []):
            st.caption(md_escape(note))
        if decision:
            st.caption(f"{DECISION_LABELS[decision['decision']]} por {md_escape(decision['approver'])} · {md_escape(decision['timestamp'])}")
            if decision["decision"] in ("failed", "rejected") and decision.get("reason"):
                st.text(decision["reason"])
        if not check["allowed"]:
            st.error("La política bloquea esta acción, así que no se puede ejecutar desde aquí.", icon="🚫")
            return
        if decision and decision["decision"] == "executed":
            st.success("Ejecutada en la API simulada.")
            return
        needed = ", ".join(check.get("approvers", []))
        st.caption(f"Aprobación necesaria: {needed}" if check["requires_approval"] else "La política no pide más aprobadores, pero necesita tu clic.")
        with st.form(f"action_form_{index}"):
            reason = st.text_input("Motivo (obligatorio para rechazar)", key=f"action_reason_{index}")
            approve_col, reject_col = st.columns(2)
            approved = approve_col.form_submit_button("Aprobar y ejecutar", type="primary", width="stretch")
            rejected = reject_col.form_submit_button("Rechazar", width="stretch")
        if approved:
            try:
                approve_and_execute(store, ticket["ticket_id"], action, target, name, reason or str(item.get("justification", "")))
                _flash("ok", f"{ACTION_LABELS.get(action, action)}: {target}. Ejecutada en la API simulada.")
            except (ContainmentRefused, ContainmentFailed) as error:
                _flash("error", str(error))
            st.rerun()
        if rejected:
            try:
                reject(store, ticket["ticket_id"], action, target, name, reason)
                _flash("ok", f"Acción rechazada: {target}. No se ha enviado nada a la API.")
            except ValueError as error:
                _flash("error", _plain_reason(str(error)))
            st.rerun()


def render_history(store: Store, ticket: dict[str, Any]) -> None:
    history = store.review_history(ticket["ticket_id"])
    with st.expander(f"Historial de decisiones humanas ({len(history)})"):
        if history:
            st.dataframe(pd.DataFrame([{
                "Cuándo": h["timestamp"], "Quién": h.get("reviewer") or h.get("approver"),
                "Decisión": h.get("status") or DECISION_LABELS.get(h.get("decision"), h.get("decision")),
                "Acción": h.get("action", ""), "Objetivo": h.get("target", ""), "Motivo": h.get("reason", ""),
            } for h in history]), hide_index=True, width="stretch")
        else:
            st.caption("Aún no hay decisiones.")


def render_containment_log() -> None:
    with st.expander("Registro de contención de la API simulada"):
        try:
            log = containment_log()
        except ContainmentFailed as error:
            st.text(str(error))
            return
        if log:
            st.dataframe(pd.DataFrame([{
                "Cuándo": e.get("timestamp"), "Acción": e.get("action"), "Objetivo": e.get("target"),
                "Ticket": e.get("ticket_id"), "Resultado": e.get("result"),
            } for e in log]), hide_index=True, width="stretch")
        else:
            st.caption("Aún no se ha ejecutado ninguna acción.")
