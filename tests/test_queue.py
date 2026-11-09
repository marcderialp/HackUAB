import time

import pytest
from streamlit.testing.v1 import AppTest

from triage.loader import ROOT
from triage.policy import sla_for
from triage.store import Store
from ui.queue_logic import (
    Filters, build_rows, display_row, filter_rows, queue_row, review_state, sla_info, spanish_number, summarize,
)


def make_ticket(ticket_id="TKT-1", **extra):
    ticket = {
        "ticket_id": ticket_id, "alert_ids": ["ALR-1"], "title": "Título", "verdict": "true_positive",
        "confidence": 0.9, "severity": "high", "summary": "Resumen", "evidence": [],
        "recommended_actions": [], "escalation": {"escalate": False},
    }
    ticket.update(extra)
    return ticket


def test_most_severe_first_then_nearest_deadline():
    rows = build_rows([
        make_ticket("LOW", severity="low", sla={"due": "2026-10-01T00:00:00Z"}),
        make_ticket("HIGH-LATER", severity="high", sla={"due": "2026-10-09T00:00:00Z"}),
        make_ticket("HIGH-SOON", severity="high", sla={"due": "2026-10-08T00:00:00Z"}),
        make_ticket("HIGH-NONE", severity="high"),
        make_ticket("CRIT", severity="critical"),
    ])
    assert [r["ticket_id"] for r in rows] == ["CRIT", "HIGH-SOON", "HIGH-LATER", "HIGH-NONE", "LOW"]


def test_sla_uses_the_policy_engine_format():
    sla = sla_for("high", "2026-10-09T09:00:00.000Z")
    info = sla_info(make_ticket(sla=sla, triage_seconds=60))
    assert info["state"] == "in_time" and info["due"] == sla["due"]
    assert info["due_local"] == "09/10 11:30"  # Madrid is UTC+2 on this date.
    assert sla_info(make_ticket(sla=sla, triage_seconds=31 * 60))["state"] == "late"


def test_sla_also_reads_the_plan_field_name_and_converts_to_madrid():
    info = sla_info(make_ticket(sla_due="2026-10-28T10:00:00.000Z"))
    assert info["due_local"] == "28/10 11:00"  # UTC+1 after the clocks change on 25 Oct.
    assert info["state"] == "unknown"


def test_sla_missing_or_malformed_is_shown_as_unknown():
    assert sla_info(make_ticket()) == {"due": None, "due_sort": "9999", "due_local": "—", "state": "unknown"}
    assert sla_info(make_ticket(sla="x"))["state"] == "unknown"
    assert sla_info(make_ticket(sla={"due_local": "not a date"}))["due_local"] == "—"


def test_queue_shows_the_human_override_not_the_ai_value(tmp_path):
    store = Store(tmp_path)
    store.save_ticket(make_ticket())
    store.record_review("TKT-1", "overridden", "Ana", reason="Cambio aprobado", override={"severity": "low", "verdict": "benign_true_positive"})
    row = queue_row(store.get_ticket("TKT-1"))
    assert row["severity"] == "low" and row["verdict"] == "benign_true_positive"
    assert row["changed_by_human"] and row["review"] == "overridden"
    assert display_row(row)["Veredicto"].endswith("✎")


def test_review_state_flags_stale_reviews(tmp_path):
    store = Store(tmp_path)
    store.save_ticket(make_ticket())
    assert review_state(store.get_ticket("TKT-1")) == "pending"
    store.record_review("TKT-1", "accepted", "Ana")
    assert review_state(store.get_ticket("TKT-1")) == "accepted"
    store.save_ticket(make_ticket(severity="critical"))
    assert review_state(store.get_ticket("TKT-1")) == "stale"


ROWS = build_rows([
    make_ticket("A", severity="critical", routing="live", injection_flags=[{"field": "x"}],
                escalation={"escalate": True, "to": "N2"}, affected={"users": ["Blanca.Xirau"], "hosts": ["WS-1"]}),
    make_ticket("B", severity="low", verdict="false_positive", routing="cluster", alert_ids=["ALR-7", "ALR-8"],
                sla={"triage_within_minutes": 1}, triage_seconds=5),
    make_ticket("C", severity="low", verdict="needs_more_info", title="Otra cosa"),
])


@pytest.mark.parametrize(
    "filters, expected",
    [
        (Filters(), ["A", "B", "C"]),
        (Filters(severities={"low"}), ["B", "C"]),
        (Filters(severities={"low"}, verdicts={"false_positive"}), ["B"]),
        (Filters(verdicts={"needs_more_info", "false_positive"}), ["B", "C"]),
        (Filters(reviews={"accepted"}), []),
        (Filters(sla_states={"in_time"}), ["B"]),
        (Filters(sla_states={"unknown"}), ["A", "C"]),
        (Filters(routings={"live"}), ["A"]),
        (Filters(only_escalated=True), ["A"]),
        (Filters(only_injection=True), ["A"]),
        (Filters(text="  blanca.xirau "), ["A"]),
        (Filters(text="ws-1"), ["A"]),
        (Filters(text="alr-8"), ["B"]),
        (Filters(text="otra"), ["C"]),
        (Filters(text="nada"), []),
    ],
)
def test_filters(filters, expected):
    assert [row["ticket_id"] for row in filter_rows(ROWS, filters)] == expected


def test_summary_counts():
    assert summarize(ROWS) == {"tickets": 3, "alerts": 4, "pending": 3, "escalated": 1, "urgent": 1, "injection": 1}


def test_minimal_ticket_displays_without_errors():
    shown = display_row(queue_row(make_ticket(confidence=0.5)))
    assert shown["Ruta"] == "—" and shown["Vence"] == "—" and shown["SLA"] == "Sin dato" and shown["Escalado"] == "No"


def test_injection_is_marked_in_the_visible_title_column():
    shown = display_row(queue_row(make_ticket(injection_flags=[{"field": "x"}])))
    assert shown["Qué pasa"] == "⚠️ Título"
    assert display_row(queue_row(make_ticket()))["Qué pasa"] == "Título"


def test_spanish_number():
    assert spanish_number(11061) == "11.061" and spanish_number(5) == "5"


def test_full_run_builds_quickly():
    tickets = [make_ticket(f"TKT-{n}", alert_ids=[f"ALR-{n}"]) for n in range(11061)]
    started = time.perf_counter()
    rows = build_rows(tickets)
    table = [display_row(row) for row in filter_rows(rows, Filters(severities={"high"}))]
    elapsed = time.perf_counter() - started
    assert len(table) == 11061 and elapsed < 1


# The real page, run through Streamlit's test runner.
@pytest.fixture
def app(monkeypatch, tmp_path):
    monkeypatch.setenv("TARVIA_OUT", str(tmp_path / "empty"))
    return AppTest.from_file(str(ROOT / "ui" / "app.py"), default_timeout=30)


def text_of(app_run):
    return " ".join(str(item.value) for item in [*app_run.warning, *app_run.info, *app_run.caption, *app_run.text])


def test_page_defaults_to_fake_data_with_a_warning_when_no_results_exist(app):
    app.run()
    assert not app.exception
    assert app.sidebar.radio[0].value == "Datos ficticios"
    assert "Datos ficticios" in app.warning[0].value
    assert len(app.dataframe) == 1 and len(app.dataframe[0].value) == 9
    table = app.dataframe[0].value
    assert table.iloc[0]["Severidad"] == "🔴 Crítica"
    assert table["Qué pasa"].str.contains("[FICTICIO]", regex=False).all()


def test_page_says_so_when_real_results_are_empty(app):
    app.run()
    app.sidebar.radio[0].set_value("Resultados reales").run()
    assert not app.exception
    assert not app.warning
    assert "Aún no hay tickets" in app.info[0].value


def test_page_filters_and_handles_no_matches(app):
    app.run()
    app.sidebar.multiselect[0].set_value(["critical"]).run()
    assert not app.exception and len(app.dataframe[0].value) == 1
    app.sidebar.text_input[0].set_value("no existe nada así").run()
    assert not app.exception and not app.dataframe
    assert "Ningún ticket coincide" in app.info[0].value


def test_page_prefers_real_results_and_shows_no_fake_warning(monkeypatch, tmp_path):
    monkeypatch.setenv("TARVIA_OUT", str(tmp_path))
    Store(tmp_path).save_ticket(make_ticket(title="Ticket real"))
    app = AppTest.from_file(str(ROOT / "ui" / "app.py"), default_timeout=30)
    app.run()
    assert not app.exception and not app.warning
    assert app.sidebar.radio[0].value == "Resultados reales"
    assert list(app.dataframe[0].value["Qué pasa"]) == ["Ticket real"]


def test_selected_ticket_text_is_plain_never_rendered_as_markdown(monkeypatch, tmp_path):
    attack = "![x](http://malo.example/robo.png) [pulsa aquí](http://malo.example)"
    monkeypatch.setenv("TARVIA_OUT", str(tmp_path))
    Store(tmp_path).save_ticket(make_ticket(title=attack, summary=attack))
    app = AppTest.from_file(str(ROOT / "ui" / "app.py"), default_timeout=30)
    app.session_state["selected_ticket"] = "TKT-1"
    app.run()
    assert not app.exception
    assert [item.value for item in app.text] == [attack, attack]
    assert not any("malo.example" in item.value for item in app.markdown)


def test_selection_hidden_by_a_filter_shows_no_summary(monkeypatch, tmp_path):
    monkeypatch.setenv("TARVIA_OUT", str(tmp_path))
    Store(tmp_path).save_ticket(make_ticket())
    app = AppTest.from_file(str(ROOT / "ui" / "app.py"), default_timeout=30)
    app.session_state["selected_ticket"] = "TKT-1"
    app.run()
    assert len(app.text) == 2
    app.sidebar.multiselect[0].set_value(["low"]).run()
    assert not app.exception and not app.text


def test_page_warns_about_damaged_results(monkeypatch, tmp_path):
    monkeypatch.setenv("TARVIA_OUT", str(tmp_path))
    Store(tmp_path).save_ticket(make_ticket())
    with open(tmp_path / "tickets.jsonl", "a", encoding="utf-8") as handle:
        handle.write("{broken}\n")
    app = AppTest.from_file(str(ROOT / "ui" / "app.py"), default_timeout=30)
    app.run()
    assert not app.exception
    assert "dañadas" in app.error[0].value


def test_selection_key_changes_whenever_the_rows_do():
    from ui.queue_logic import selection_key

    one, two, new = {"ticket_id": "TKT-1"}, {"ticket_id": "TKT-2"}, {"ticket_id": "TKT-3"}
    assert selection_key([one, two]) == selection_key([one, two])
    assert selection_key([one, two]) != selection_key([new, one, two])
    assert selection_key([one, two]) != selection_key([two, one])
    assert selection_key([one]) != selection_key([two])
