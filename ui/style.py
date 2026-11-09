"""One small stylesheet for the whole console (loaded once from app.py).

Visual only: spacing, type and card chrome on top of the theme in .streamlit/config.toml. It never changes what a
page shows or does, and uses only stable `data-testid` hooks so a Streamlit update can at worst ignore it.
"""
import streamlit as st

CSS = """
<style>
:root { --teal: #5eead4; --mute: #8693a1; --line: rgba(255,255,255,.10); --card: #101722; }
/* page frame: narrower measure, more air */
[data-testid="stMainBlockContainer"] { max-width: 1560px; padding-top: 2.6rem; padding-bottom: 4rem; }
[data-testid="stHeader"] { background: transparent; }
/* type */
h1 { font-weight: 300 !important; letter-spacing: -0.02em; font-size: 2.3rem !important; padding-bottom: .4rem; }
h2, h3 { font-weight: 400 !important; letter-spacing: -0.01em; }
[data-testid="stCaptionContainer"] { color: var(--mute); }
/* KPI cards */
[data-testid="stMetric"] { background: var(--card); border: 1px solid var(--line); border-radius: .8rem; padding: 1rem 1.1rem; }
[data-testid="stMetricLabel"] p { font-size: .82rem; letter-spacing: .01em; color: var(--mute); white-space: normal; }
[data-testid="stMetricValue"] { font-weight: 200; letter-spacing: -0.03em; font-variant-numeric: tabular-nums; }
/* sidebar: quiet, with a hairline */
[data-testid="stSidebar"] { border-right: 1px solid var(--line); }
[data-testid="stSidebar"] h2 { font-size: .75rem; letter-spacing: .18em; text-transform: uppercase; color: var(--mute); font-weight: 500 !important; }
[data-testid="stSidebarNav"] a, [data-testid="stSidebarNavLink"] { border-radius: .5rem; }
/* tables, dividers, expanders, alerts */
[data-testid="stDataFrame"] { border: 1px solid var(--line); border-radius: .8rem; overflow: hidden; }
hr { border-color: var(--line) !important; margin: 1.6rem 0 !important; }
[data-testid="stExpander"] details { border: 1px solid var(--line); border-radius: .8rem; background: var(--card); }
[data-testid="stAlert"] { border-radius: .8rem; }
/* buttons */
.stButton > button, [data-testid="stPageLink"] a { border-radius: .6rem; font-weight: 500; transition: border-color .2s, background .2s; }
.stButton > button[kind="primary"] { color: #04211d; }
/* keep keyboard focus visible */
:focus-visible { outline: 2px solid var(--teal) !important; outline-offset: 2px; }
@media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
</style>
"""


def apply() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
