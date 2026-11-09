"""E1: the triage queue, most urgent first, with filters."""
import pandas as pd
import streamlit as st

from ui.common import SELECTED_KEY, page_store
from ui.queue_logic import (
    REVIEW_LABELS, ROUTING_LABELS, SEVERITIES, SEVERITY_LABELS, SLA_LABELS, VERDICT_LABELS, VERDICTS,
    Filters, build_rows, display_row, filter_rows, selection_key, spanish_number, summarize,
)

st.title("Cola de triaje")
store, _ = page_store()
tickets = store.load_tickets()
skipped = store.health()["skipped_lines"]
if skipped:
    st.error(f"Se han ignorado {skipped} líneas dañadas en los ficheros de resultados. Revísalos.")

if not tickets:
    st.info("Aún no hay tickets. Ejecuta el triaje, o elige «Datos ficticios» en el panel lateral.")
    st.stop()

all_rows = build_rows(tickets)


def pick(label: str, options: dict[str, str]) -> set[str]:
    return set(st.sidebar.multiselect(label, list(options), format_func=options.get, placeholder="Todos"))


st.sidebar.header("Filtros")
filters = Filters(
    text=st.sidebar.text_input("Buscar", placeholder="Usuario, equipo, alerta, ticket…"),
    severities=pick("Severidad", {s: SEVERITY_LABELS[s] for s in reversed(SEVERITIES)}),
    verdicts=pick("Veredicto", {v: VERDICT_LABELS[v] for v in VERDICTS}),
    reviews=pick("Revisión humana", REVIEW_LABELS),
    sla_states=pick("SLA", SLA_LABELS),
    routings=pick("Ruta", {k: v for k, v in ROUTING_LABELS.items() if k}),
    only_escalated=st.sidebar.checkbox("Solo escalados"),
    only_injection=st.sidebar.checkbox("Solo con intento de inyección"),
)
rows = filter_rows(all_rows, filters)
totals = summarize(rows)

columns = st.columns(5)
columns[0].metric("Tickets", spanish_number(totals["tickets"]), help=f"De {spanish_number(len(all_rows))} en total")
columns[1].metric("Alertas cubiertas", spanish_number(totals["alerts"]))
columns[2].metric("Decisión humana pendiente", spanish_number(totals["pending"]))
columns[3].metric("Escalados", spanish_number(totals["escalated"]))
columns[4].metric("Críticos y altos", spanish_number(totals["urgent"]))

if not rows:
    st.info("Ningún ticket coincide con estos filtros.")
    st.stop()

st.caption(
    "Ordenado por severidad y después por vencimiento (hora de Madrid). ⚠️ = intento de inyección detectado. "
    "✎ = corregido por una persona. SLA indica si el triaje terminó dentro del plazo de la política."
)
table = pd.DataFrame([display_row(row) for row in rows])
event = st.dataframe(
    table,
    hide_index=True,
    width="stretch",
    height=520,
    on_select="rerun",
    selection_mode="single-row",
    # The selection is a row number. A new key whenever the rows change clears it, so a ticket arriving
    # during a run or a new filter can't make it point at another ticket.
    key=selection_key(rows),
    column_config={
        "Severidad": st.column_config.TextColumn(width=115),
        "Veredicto": st.column_config.TextColumn(width=145),
        "Qué pasa": st.column_config.TextColumn(width=300),
        "Confianza": st.column_config.ProgressColumn(format="percent", min_value=0, max_value=1, width=80),
        "Alertas": st.column_config.NumberColumn(width=55),
        "Revisión": st.column_config.TextColumn(width=95),
        "Escalado": st.column_config.TextColumn(width=120),
        "Vence": st.column_config.TextColumn(width=90),
        "SLA": st.column_config.TextColumn(width=95),
    },
)

selected_rows = event.selection.rows
if selected_rows and selected_rows[0] < len(rows):
    st.session_state[SELECTED_KEY] = rows[selected_rows[0]]["ticket_id"]

selected = store.get_ticket(st.session_state.get(SELECTED_KEY, ""))
if selected and any(row["ticket_id"] == selected["ticket_id"] for row in rows):
    st.divider()
    st.caption(selected["ticket_id"])
    # Ticket text can quote the attacker, so it is shown as plain text and never rendered as Markdown.
    st.text(selected["title"])
    st.text(selected["summary"])
    if st.button("Abrir ticket", type="primary"):
        st.switch_page("pages/ticket_detail.py")
else:
    st.caption("Selecciona una fila para ver su resumen.")
