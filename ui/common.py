"""What the console pages share: choosing the data source and opening its store."""
from __future__ import annotations

from pathlib import Path

import streamlit as st
from streamlit.errors import StreamlitPageNotFoundError

from triage.loader import ROOT
from triage.store import Store

FIXTURES_DIR = ROOT / "ui" / "fixtures"
SELECTED_KEY = "selected_ticket"
SOURCE_KEY = "data_source_choice"
REAL_SOURCE = "Resultados reales"


_MARKDOWN_SPECIAL = set("\\`*_{}[]()#+-.!|<>~$:=")


def md_escape(value: object) -> str:
    """Make text safe inside st.caption/st.markdown: every Markdown character becomes literal.

    For short values written by the AI, the attacker or a person (field names, event ids, approver
    names). Longer text goes through st.text instead, which never renders Markdown."""
    return "".join("\\" + ch if ch in _MARKDOWN_SPECIAL else ch for ch in str(value)).replace("\n", " ")


@st.cache_resource(show_spinner=False)
def _open_store(root: str) -> Store:
    # One Store per folder, so its read cache survives Streamlit's reruns.
    return Store(root)


def _real_dir() -> Path:
    return Store().root


def real_store() -> Store:
    """Where real tickets go, whatever data source the sidebar shows."""
    return _open_store(str(_real_dir()))


def page_store(results_file: str = "tickets.jsonl") -> tuple[Store, bool]:
    """Show the data source choice. Returns the store and whether its data is fake.

    A page defaults to real results if its own file exists. Only a person's choice carries across pages.
    """
    real = _real_dir()
    real_is_fixtures = real.resolve() == FIXTURES_DIR.resolve()
    has_real = (real / results_file).exists() and not real_is_fixtures
    options = [REAL_SOURCE, "Datos ficticios"]
    default = options[0] if has_real else options[1]
    saved = st.session_state.get(SOURCE_KEY, default)
    source = st.sidebar.radio(
        "Datos", options, index=options.index(saved),
        help="Los datos ficticios sirven para probar la consola. No describen hechos reales.",
    )
    if source == default:
        st.session_state.pop(SOURCE_KEY, None)
    else:
        st.session_state[SOURCE_KEY] = source
    fake = source == options[1] or real_is_fixtures
    if fake:
        st.warning("**Datos ficticios.** Estos tickets son inventados, solo para probar la consola.", icon=":material/warning:")
    return _open_store(str(FIXTURES_DIR if fake else real)), fake


def link_to_queue() -> None:
    try:
        st.page_link("pages/alert_queue.py", label="Volver a la cola", icon=":material/arrow_back:")
    except StreamlitPageNotFoundError:
        pass  # The page is running on its own, without the navigation in app.py.
