"""E5: alerts grouped into incidents, what links them and how each one was triaged.

Incident, ticket and alert text can quote the attacker, so it only appears through st.text and dataframes.
"""
import pandas as pd
import streamlit as st

from triage import data
from ui.common import SELECTED_KEY, page_store
from ui.incident_logic import (
    STAGE_LABELS, alert_rows, build_rows, display_row, entity_rows, filter_rows, report_sections, selection_key,
    summarize, tickets_by_alert,
)
from ui.queue_logic import SEVERITY_LABELS, spanish_number

SELECTED_INCIDENT_KEY = "selected_incident"

st.title("Incidentes")
store, _ = page_store("incidents.jsonl")
incidents = store.load_incidents()
tickets = store.load_tickets()
skipped = store.health()["skipped_lines"]
if skipped:
    st.error(f"Se han ignorado {skipped} líneas dañadas en los ficheros de resultados. Revísalos.")
if not incidents:
    st.info("Aún no hay incidentes. Ejecuta la correlación, o elige «Datos ficticios» en el panel lateral.")
    st.stop()


def table(rows, **kwargs):
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", **kwargs)


all_rows = build_rows(incidents, tickets)
rows = filter_rows(all_rows, st.sidebar.text_input("Buscar", placeholder="Regla, entidad, alerta, incidente…"))
totals = summarize(rows)

columns = st.columns(4)
columns[0].metric("Incidentes", spanish_number(totals["incidents"]), help=f"De {spanish_number(len(all_rows))} en total")
columns[1].metric("Alertas agrupadas", spanish_number(totals["alerts"]))
columns[2].metric("Alertas ya triadas", spanish_number(totals["triaged"]))
columns[3].metric("Críticos y altos", spanish_number(totals["urgent"]))

if not rows:
    st.info("Ningún incidente coincide con la búsqueda.")
    st.stop()

st.caption(
    "Alertas agrupadas porque comparten entidades cercanas en el tiempo: indican una relación, no prueban un ataque. "
    "La severidad es la más alta de sus tickets. Hora de Madrid."
)
event = st.dataframe(
    pd.DataFrame([display_row(row) for row in rows]),
    hide_index=True,
    width="stretch",
    on_select="rerun",
    selection_mode="single-row",
    # The selection is a row number. A new key whenever the rows change clears it, so it can't move to another incident.
    key=selection_key(rows),
    column_config={
        "Severidad": st.column_config.TextColumn(width=110),
        "Qué pasa": st.column_config.TextColumn(width="large"),
        "Alertas": st.column_config.NumberColumn(width=60),
        "Triadas": st.column_config.TextColumn(width=75),
    },
)

selected_rows = event.selection.rows
if selected_rows and selected_rows[0] < len(rows):
    st.session_state[SELECTED_INCIDENT_KEY] = rows[selected_rows[0]]["incident_id"]

row = next((r for r in rows if r["incident_id"] == st.session_state.get(SELECTED_INCIDENT_KEY)), None)
if row is None:
    st.caption("Selecciona una fila para ver el incidente.")
    st.stop()

incident = next(i for i in incidents if i["incident_id"] == row["incident_id"])
by_alert = tickets_by_alert(tickets)

st.divider()
st.caption(f"{row['incident_id']} · {STAGE_LABELS.get(row['stage'], row['stage'])}")
st.text(row["title"])
if row["severity"]:
    st.text(f"Severidad: {SEVERITY_LABELS.get(row['severity'], row['severity'])} · Triadas: {row['triaged']} de {row['alerts']}")
else:
    st.text(f"Aún sin triar: ninguna de sus {row['alerts']} alertas tiene ticket.")

entities = entity_rows(incident)
if entities:
    st.subheader("Qué las une")
    table(entities)

report = report_sections(incident)
for label, value in report["facts"]:
    st.caption(label)
    st.text(value)
if report["timeline"]:
    st.subheader("Cronología del incidente")
    table(report["timeline"])
if report["scope"]:
    st.subheader("Alcance")
    table(report["scope"])
if report["containment"]:
    st.subheader("Plan de contención propuesto")
    st.caption("Solo es una propuesta. Cada acción se aprueba y ejecuta desde el ticket.")
    table(report["containment"])
for label, items in report["lists"]:
    st.caption(label)
    for item in items:
        st.text(f"• {item}")


def lookup_alert(alert_id):
    try:
        return data.get_alert(alert_id)
    except FileNotFoundError:
        return None


st.subheader("Alertas, por orden de aparición")
if not data.DB_PATH.exists():
    st.caption("La base de datos no está creada: ejecuta python -m triage.loader")
alerts = alert_rows(incident, by_alert, lookup_alert)
table(alerts, column_config={"Qué detectó": st.column_config.TextColumn(width="large")})

ticket_ids = list(dict.fromkeys(a["Ticket"] for a in alerts if a["Ticket"]))
if ticket_ids:
    chosen = st.selectbox("Ticket", ticket_ids)
    if st.button("Abrir ticket", type="primary"):
        st.session_state[SELECTED_KEY] = chosen
        st.switch_page("pages/ticket_detail.py")
