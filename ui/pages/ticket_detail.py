"""E2: everything behind one ticket, and what the AI decided versus what a person decides.

Ticket and alert text can quote the attacker, so it only appears through st.text, st.json and
dataframes, which never render Markdown.
"""
import pandas as pd
import streamlit as st

from triage import data
from ui.common import SELECTED_KEY, link_to_queue, md_escape, page_store
from ui.detail_logic import (
    adjustment_rows, affected_rows, as_dict, decision_panel, enrichment_rows, evidence_items, injection_rows,
    severity_steps, sla_text, trace_rows,
)
from ui.human_actions import analyst_name, render_actions, render_containment_log, render_history, render_review, show_flash
from ui.queue_logic import REVIEW_LABELS, SEVERITY_LABELS, VERDICT_LABELS, review_state

store, _ = page_store()

ticket_id = st.query_params.get("ticket") or st.session_state.get(SELECTED_KEY)
ticket = store.get_ticket(ticket_id) if ticket_id else None
link_to_queue()
if not ticket:
    st.title("Detalle del ticket")
    st.info("Selecciona un ticket en la cola para verlo aquí.")
    st.stop()
st.session_state[SELECTED_KEY] = ticket["ticket_id"]


def table(rows, **kwargs):
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", **kwargs)


st.caption(ticket["ticket_id"])
st.subheader("Qué pasa")
st.text(ticket["title"])

columns = st.columns([1.5, 0.6, 1.1, 1.1])
columns[0].metric("Veredicto de la IA", VERDICT_LABELS.get(ticket["verdict"], ticket["verdict"]))
columns[1].metric("Confianza", f"{ticket['confidence']:.0%}")
columns[2].metric("Severidad", SEVERITY_LABELS.get(ticket["severity"], ticket["severity"]))
columns[3].metric("Revisión humana", REVIEW_LABELS.get(review_state(ticket), review_state(ticket)))

injections = injection_rows(ticket)
if injections:
    st.error(
        f"**Intento de inyección detectado ({len(injections)}).** Texto del atacante dirigido al sistema. "
        "Se trata como evidencia y no se obedece.",
        icon="⚠️",
    )
    for flag in injections:
        st.caption(f"Campo: {md_escape(flag['field'])}")
        st.text(flag["excerpt"])

panel = decision_panel(ticket)
ai_side, human_side = st.columns(2)
with ai_side:
    with st.container(border=True):
        st.subheader("🤖 Ya decidido automáticamente")
        for line in panel["automatic"]:
            st.text(f"• {line}")
with human_side:
    with st.container(border=True):
        st.subheader("🧑 Te toca decidir")
        for line in panel["human"]:
            st.text(f"• {line}")

st.subheader("Resumen")
st.text(ticket["summary"])

st.divider()
show_flash()
name = analyst_name()
render_review(store, ticket, name)
render_actions(store, ticket, name)
render_history(store, ticket)
render_containment_log()
st.divider()

left, right = st.columns(2)
with left:
    st.subheader("Cálculo de la severidad")
    steps = severity_steps(ticket)
    if steps:
        table(steps)
    else:
        st.caption("Este ticket no incluye el cálculo.")
    adjustments = adjustment_rows(ticket)
    if adjustments:
        st.caption("Ajustes propuestos por la IA y límites de la política")
        table(adjustments)
    if ticket.get("severity_rationale"):
        st.caption("Justificación")
        st.text(ticket["severity_rationale"])
with right:
    st.subheader("Plazo y afectados")
    sla = sla_text(ticket)
    table([{"Plazo de triaje": sla["plazo"], "Escalado": sla["escalado"], "Notificar": sla["notificar"]}])
    affected = affected_rows(ticket)
    if affected:
        table(affected)
    else:
        st.caption("El ticket no indica afectados.")
    escalation = as_dict(ticket.get("escalation"))
    if escalation.get("reason"):
        st.caption(f"Motivo de escalado ({escalation.get('to') or 'sin destino'})")
        st.text(escalation["reason"])

st.subheader("Evidencias")
evidence = evidence_items(ticket)
if not evidence:
    st.caption("Este ticket no cita eventos.")
for index, item in enumerate(evidence):
    with st.container(border=True):
        st.caption(f"{md_escape(item['source'])} · {md_escape(item['event_id'])}")
        st.text(item["finding"])
        if item["event_id"] and st.toggle("Ver el evento original", key=f"event_{index}_{item['event_id']}"):
            try:
                found = data.get_event(item["event_id"])
            except FileNotFoundError:
                found = None
                st.caption("La base de datos no está creada: ejecuta python -m triage.loader")
            if found:
                st.json(found["event"], expanded=True)
            else:
                st.caption("Evento no encontrado en los logs.")

enrichment = enrichment_rows(ticket)
if enrichment:
    st.subheader("Inteligencia consultada")
    table(enrichment)
    st.caption("Un indicador sin coincidencias es desconocido, no limpio.")

if ticket.get("mitre"):
    st.subheader("MITRE ATT&CK")
    st.text(", ".join(str(t) for t in ticket["mitre"]))

if ticket.get("open_questions"):
    st.subheader("Preguntas abiertas")
    for question in ticket["open_questions"]:
        st.text(f"• {question}")

st.subheader("Qué consultó el sistema")
trace = trace_rows(ticket)
if trace:
    table(trace, column_config={"Parámetros": st.column_config.TextColumn(width="large")})
else:
    st.caption("Este ticket no incluye la traza.")

alert_ids = ticket["alert_ids"]
with st.expander(f"Alerta original ({len(alert_ids)} en este ticket)"):
    alert = ticket.get("live_alert") if isinstance(ticket.get("live_alert"), dict) else None
    if alert:
        st.caption("Alerta tal como se recibió en el triaje en directo.")
    else:
        try:
            alert = data.get_alert(alert_ids[0])
        except FileNotFoundError:
            st.caption("La base de datos no está creada: ejecuta python -m triage.loader")
    if alert:
        st.json(alert, expanded=True)
    else:
        st.caption(f"{alert_ids[0]} no está en la cola de alertas.")
    if len(alert_ids) > 1:
        st.caption("Todas las alertas del ticket")
        st.text(", ".join(alert_ids))
