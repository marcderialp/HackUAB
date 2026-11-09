"""E4: triage alerts the system hasn't seen (the common alerts of the defence), one at a time.

Alerts and tickets can quote the attacker, so their text only appears through st.text and dataframes.
The work happens in ui.live_logic.LiveRun; this page only starts it and shows how it is going.
"""
import pandas as pd
import streamlit as st

from ui.common import REAL_SOURCE, SELECTED_KEY, SOURCE_KEY, real_store
from ui.live_logic import (
    LiveNotReady, LiveRun, clear_run, current_run, load_triage_fn, parse_input, start_run, summarize, time_estimate,
)
from ui.queue_logic import SEVERITY_LABELS, VERDICT_LABELS

STATUS_LABELS = {"ok": "✅ Triada", "no_ai": "⚠️ Sin respuesta de la IA", "error": "❌ Falló"}
MAX_PROBLEMS_SHOWN = 10


def show_progress(run: LiveRun) -> None:
    done, total = len(run.results), len(run.items)
    st.progress(done / total, text=f"{done} de {total} alertas")


def show_results(results: list[dict]) -> None:
    if not results:
        return
    st.dataframe(pd.DataFrame([{
        "Alerta": r["alert_id"], "Estado": STATUS_LABELS[r["status"]],
        "Veredicto": VERDICT_LABELS.get(r["verdict"], r["verdict"] or ""),
        "Severidad": SEVERITY_LABELS.get(r["severity"], r["severity"] or ""),
        "Escalado": {True: "Sí", False: "No"}.get(r["escalate"], ""),
        "Segundos": r["seconds"], "Ticket": r["ticket_id"] or "", "Detalle": r["error"],
    } for r in results]), hide_index=True, width="stretch")


def render_form() -> None:
    st.caption("Pega alertas en JSON o JSONL, o identificadores de alerta, o sube un fichero. Se trian de una en una.")
    triage_fn = None
    try:
        triage_fn = load_triage_fn()
    except LiveNotReady as error:
        st.warning("El modo en directo aún no está conectado, así que no se puede triar. Este sistema nunca inventa un veredicto.", icon="🔌")
        st.text(str(error))

    pasted = st.text_area("Alertas", height=220, placeholder='{"alert_id": "ALR-…", "rule_id": "…"}\nALR-20261013-700001')
    uploaded = st.file_uploader("O sube un fichero", type=["json", "jsonl", "txt"])
    text = pasted
    if uploaded is not None:
        try:
            text = uploaded.getvalue().decode("utf-8-sig")
        except UnicodeDecodeError:
            st.error("El fichero no está en UTF-8.")
            text = ""

    parsed = parse_input(text)
    if parsed.problems:
        st.warning(f"Entradas con problemas: {len(parsed.problems)}. Las demás sí se pueden triar.")
        for problem in parsed.problems[:MAX_PROBLEMS_SHOWN]:
            st.text(f"• {problem}")
    count = len(parsed.items)
    if count:
        st.caption(f"Alertas listas: {count} · tiempo estimado: {time_estimate(count)}")
    if st.button("Iniciar triaje", type="primary", disabled=not count or triage_fn is None):
        start_run(parsed.items, triage_fn, real_store())
        st.rerun()


@st.fragment(run_every=1)
def render_running() -> None:
    run = current_run()
    if run is None or not run.running:
        st.rerun()  # the whole page, to show the summary
    show_progress(run)
    if run.stopping:
        st.caption("Se detendrá al terminar la alerta en curso.")
    else:
        st.button("Detener después de esta alerta", on_click=run.stop)
    alert_id = run.current_alert
    if alert_id:
        # The id passed the check in parse_input, so it carries no Markdown.
        st.info(f"Triando {alert_id}…", icon="⏳")
    show_results(list(run.results))
    st.caption("Cada ticket se guarda al terminar. Puedes cambiar de página: el triaje sigue en marcha.")


def render_summary(run: LiveRun) -> None:
    results, total = list(run.results), len(run.items)
    show_progress(run)
    show_results(results)
    totals = summarize(results)
    message = f"Triadas: {totals['ok']} · Sin respuesta de la IA: {totals['no_ai']} · Fallidas: {totals['error']}"
    if len(results) < total:
        st.warning(f"Detenido. Sin triar: {total - len(results)}. {message}")
    elif totals["error"] or totals["no_ai"]:
        st.warning(f"Terminado. {message}")
    else:
        st.success(f"Terminado. {message}")

    tickets = [r["ticket_id"] for r in results if r["ticket_id"]]
    if tickets:
        chosen = st.selectbox("Ticket", tickets)
        if st.button("Abrir ticket", type="primary"):
            st.session_state[SELECTED_KEY] = chosen
            st.session_state[SOURCE_KEY] = REAL_SOURCE
            st.switch_page("pages/ticket_detail.py")
    st.button("Nueva tanda", on_click=clear_run)


st.title("Triaje en directo")
current = current_run()
if current is None:
    render_form()
elif current.running:
    render_running()
else:
    render_summary(current)
