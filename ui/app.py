"""Tarvia SOC console. Run from the repo root: streamlit run ui/app.py"""
import sys
from pathlib import Path

import streamlit as st

# Streamlit puts only ui/ on the path; the pages also import from `triage` and `ui`.
ROOT = str(Path(__file__).resolve().parents[1])
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from ui.style import apply as apply_style  # noqa: E402

st.set_page_config(page_title="Tarvia SOC", page_icon=":material/shield:", layout="wide")
apply_style()

page = st.navigation([
    st.Page("pages/alert_queue.py", title="Cola de triaje", icon=":material/inbox:", default=True),
    st.Page("pages/ticket_detail.py", title="Detalle del ticket", icon=":material/manage_search:"),
    st.Page("pages/live_triage.py", title="Triaje en directo", icon=":material/bolt:"),
    st.Page("pages/incidents.py", title="Incidentes", icon=":material/hub:"),
])
page.run()
