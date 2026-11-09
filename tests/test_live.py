"""E4: the live-triage page, with a stand-in for C7 (the real function doesn't exist yet)."""
import json
import threading
import time

import pytest
from streamlit.testing.v1 import AppTest

from triage.loader import ROOT
from triage.store import Store
from ui.live_logic import (
    MAX_ALERTS, LiveNotReady, clear_run, current_run, load_triage_fn, parse_input, start_run, summarize, time_estimate,
    triage_one,
)

PAGE = str(ROOT / "ui" / "pages" / "live_triage.py")
STUB = """
CALLS = []

def triage(alert):
    alert_id = alert["alert_id"] if isinstance(alert, dict) else alert
    CALLS.append(alert_id)
    if alert_id.endswith("BOOM"):
        raise RuntimeError("fallo simulado")
    ticket = {"ticket_id": "TKT-" + alert_id, "alert_ids": [alert_id], "title": "Título ![x](http://malo.example/a.png)",
              "verdict": "true_positive", "confidence": 0.9, "severity": "high", "summary": "Resumen", "evidence": [],
              "recommended_actions": [], "escalation": {"escalate": True, "to": "N2", "reason": "motivo"}}
    return ticket
"""


def make_ticket(alert_id="ALR-1", **extra):
    return {"ticket_id": "TKT-" + alert_id, "alert_ids": [alert_id], "title": "T", "verdict": "true_positive",
            "confidence": 0.9, "severity": "high", "summary": "R", "evidence": [], "recommended_actions": [],
            "escalation": {"escalate": False}, **extra}


# Reading the input
def test_parse_one_object_an_array_and_jsonl():
    assert [i["alert_id"] for i in parse_input('{"alert_id": "ALR-1"}').items] == ["ALR-1"]
    assert [i["alert_id"] for i in parse_input('[{"alert_id": "ALR-1"}, "ALR-2"]').items] == ["ALR-1", "ALR-2"]
    jsonl = '{"alert_id": "ALR-1", "rule_id": "R"}\n\n{"alert_id": "ALR-2"}\n'
    parsed = parse_input(jsonl)
    assert [i["alert_id"] for i in parsed.items] == ["ALR-1", "ALR-2"] and not parsed.problems
    assert parsed.items[0]["payload"]["rule_id"] == "R"


def test_parse_ids_separated_in_any_way():
    parsed = parse_input("ALR-1, ALR-2\nALR-3;ALR-4  ALR-5")
    assert [i["payload"] for i in parsed.items] == ["ALR-1", "ALR-2", "ALR-3", "ALR-4", "ALR-5"]


def test_multi_line_json_and_a_byte_order_mark_work():
    assert parse_input('﻿{\n  "alert_id": "ALR-1"\n}').items[0]["alert_id"] == "ALR-1"


def test_a_bad_entry_is_reported_and_the_rest_still_run():
    parsed = parse_input('{"alert_id": "ALR-1"}\n{broken\n{"rule_id": "sin id"}\n[1]')
    assert [i["alert_id"] for i in parsed.items] == ["ALR-1"]
    assert len(parsed.problems) == 3


@pytest.mark.parametrize("bad", ["![x](http://malo.example)", "<script>", "*negrita*", "a" * 129])
def test_ids_that_could_carry_markup_are_refused(bad):
    parsed = parse_input(json.dumps({"alert_id": bad}))
    assert not parsed.items and parsed.problems


def test_repeated_alerts_run_once():
    parsed = parse_input("ALR-1\nALR-1")
    assert len(parsed.items) == 1 and "repetida" in parsed.problems[0]


def test_empty_input_and_the_batch_limit():
    assert not parse_input("  \n").items and not parse_input("").problems
    parsed = parse_input(" ".join(f"ALR-{n}" for n in range(MAX_ALERTS + 5)))
    assert len(parsed.items) == MAX_ALERTS and "descartado 5" in parsed.problems[0]


def test_time_estimate_uses_the_measured_latency():
    assert time_estimate(1) == "unos 10–25 segundos"
    assert time_estimate(10) == "unos 2–4 minutos"


# Triaging one alert
def test_ticket_is_saved_and_reported(tmp_path):
    store = Store(tmp_path)
    result = triage_one({"alert_id": "ALR-1", "payload": "ALR-1"}, lambda _: make_ticket(), store)
    assert result["status"] == "ok" and result["ticket_id"] == "TKT-ALR-1" and result["severity"] == "high"
    assert store.get_ticket("TKT-ALR-1")


def test_failure_stays_on_its_row(tmp_path):
    def boom(_):
        raise RuntimeError("sin red")

    result = triage_one({"alert_id": "ALR-1", "payload": "ALR-1"}, boom, Store(tmp_path))
    assert result["status"] == "error" and "sin red" in result["error"]


def test_ticket_for_another_alert_is_not_saved(tmp_path):
    store = Store(tmp_path)
    result = triage_one({"alert_id": "ALR-1", "payload": "ALR-1"}, lambda _: make_ticket("ALR-2"), store)
    assert result["status"] == "error" and not store.load_tickets()


def test_invalid_ticket_is_not_saved(tmp_path):
    store = Store(tmp_path)
    result = triage_one({"alert_id": "ALR-1", "payload": "ALR-1"}, lambda _: make_ticket(verdict="quizas"), store)
    assert result["status"] == "error" and "formato" in result["error"] and not store.load_tickets()


def test_llm_failure_is_saved_but_not_counted_as_triaged(tmp_path):
    ticket = make_ticket(verdict="needs_more_info", model_info={"status": "timeout"})
    result = triage_one({"alert_id": "ALR-1", "payload": "ALR-1"}, lambda _: ticket, Store(tmp_path))
    assert result["status"] == "no_ai" and "timeout" in result["error"]
    assert summarize([result]) == {"ok": 0, "no_ai": 1, "error": 0}


def test_missing_function_is_reported(monkeypatch):
    monkeypatch.setenv("TARVIA_LIVE_FN", "triage.no_such_module:triage_live")
    with pytest.raises(LiveNotReady, match="no_such_module"):
        load_triage_fn()


# The background run
def wait_for(condition, seconds=5):
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.01)


def blocking_fn():
    calls, release = [], threading.Event()

    def triage(alert_id):
        calls.append(alert_id)
        assert release.wait(5)
        return make_ticket(alert_id)

    return triage, calls, release


ITEMS = [{"alert_id": f"ALR-{n}", "payload": f"ALR-{n}"} for n in (1, 2, 3)]


def test_stop_records_the_alert_in_progress_and_runs_no_more(tmp_path):
    triage, calls, release = blocking_fn()
    store = Store(tmp_path)
    run = start_run(ITEMS, triage, store)
    wait_for(lambda: calls)
    run.stop()
    release.set()
    run.join(5)
    assert calls == ["ALR-1"] and [r["alert_id"] for r in run.results] == ["ALR-1"]
    assert [t["ticket_id"] for t in store.load_tickets()] == ["TKT-ALR-1"]


def test_a_second_start_cannot_triage_anything_twice(tmp_path):
    triage, calls, release = blocking_fn()
    run = start_run(ITEMS, triage, Store(tmp_path))
    wait_for(lambda: calls)
    assert start_run(ITEMS, triage, Store(tmp_path)) is run
    clear_run()
    assert current_run() is run
    release.set()
    run.join(5)
    assert calls == ["ALR-1", "ALR-2", "ALR-3"] and len(run.results) == 3


def test_current_alert_and_clearing_a_finished_run(tmp_path):
    triage, calls, release = blocking_fn()
    run = start_run(ITEMS[:1], triage, Store(tmp_path))
    wait_for(lambda: calls)
    assert run.running and run.current_alert == "ALR-1"
    release.set()
    run.join(5)
    assert not run.running and run.current_alert is None
    clear_run()
    assert current_run() is None


# The page
@pytest.fixture(autouse=True)
def no_run_left_behind():
    yield
    run = current_run()
    if run:
        run.stop()
        run.join(10)
    clear_run()


@pytest.fixture
def stub(monkeypatch, tmp_path):
    (tmp_path / "live_stub_e4.py").write_text(STUB, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setenv("TARVIA_LIVE_FN", "live_stub_e4:triage")
    monkeypatch.setenv("TARVIA_OUT", str(tmp_path / "out"))
    return tmp_path / "out"


def open_page():
    app = AppTest.from_file(PAGE, default_timeout=30)
    app.run()
    return app


def start(app, text):
    app.text_area[0].set_value(text).run()
    assert not app.button[0].disabled
    app.button[0].click().run()
    current_run().join(10)
    app.run()
    assert not app.exception


def test_without_c7_the_page_refuses_to_triage(monkeypatch, tmp_path):
    monkeypatch.setenv("TARVIA_LIVE_FN", "triage.no_such_module:triage_live")
    monkeypatch.setenv("TARVIA_OUT", str(tmp_path))
    app = open_page()
    assert not app.exception and "no está conectado" in app.warning[0].value
    app.text_area[0].set_value("ALR-1").run()
    assert app.button[0].disabled
    assert not Store(tmp_path).load_tickets()


def test_button_is_off_until_there_is_an_alert(stub):
    app = open_page()
    assert not app.warning and app.button[0].disabled


def test_batch_runs_in_order_and_a_failure_doesnt_stop_it(stub):
    app = open_page()
    start(app, "ALR-1\nALR-BOOM\nALR-3")
    assert "Fallidas: 1" in app.warning[0].value and "Triadas: 2" in app.warning[0].value
    table = app.dataframe[0].value
    assert list(table["Alerta"]) == ["ALR-1", "ALR-BOOM", "ALR-3"]
    assert [t["ticket_id"] for t in Store(stub).load_tickets()] == ["TKT-ALR-1", "TKT-ALR-3"]
    assert list(app.selectbox[0].options) == ["TKT-ALR-1", "TKT-ALR-3"]


def test_full_alert_reaches_the_triage_function(stub):
    app = open_page()
    start(app, '{"alert_id": "ALR-9", "rule_id": "UC-WEB-001"}')
    assert "Terminado" in app.success[0].value
    assert Store(stub).get_ticket("TKT-ALR-9")


def test_page_shows_a_run_in_progress_without_the_form(stub, tmp_path):
    triage, calls, release = blocking_fn()
    start_run(ITEMS, triage, Store(stub))
    wait_for(lambda: calls)
    app = open_page()
    assert not app.exception and not app.text_area
    assert "ALR-1" in app.info[0].value
    assert [b.label for b in app.button] == ["Detener después de esta alerta"]
    app.button[0].click().run()
    assert not app.exception and current_run().stopping and not app.button
    release.set()


def test_stopped_run_says_what_is_left(stub):
    triage, calls, release = blocking_fn()
    run = start_run(ITEMS, triage, Store(stub))
    wait_for(lambda: calls)
    run.stop()
    release.set()
    run.join(5)
    app = open_page()
    assert "Sin triar: 2" in app.warning[0].value and "Triadas: 1" in app.warning[0].value


def test_new_batch_goes_back_to_the_form(stub):
    app = open_page()
    start(app, "ALR-1")
    [b for b in app.button if b.label == "Nueva tanda"][0].click().run()
    assert not app.exception and current_run() is None and app.text_area


def test_attacker_text_is_never_rendered_as_markdown(stub):
    attack = "![x](http://malo.example/a.png)"
    app = open_page()
    app.text_area[0].set_value(json.dumps({"alert_id": attack})).run()
    assert attack not in " ".join(m.value for m in app.markdown)
    start(app, "ALR-1")
    assert not [m.value for m in app.markdown if "![x]" in m.value]


def test_page_is_in_the_navigation():
    assert '"pages/live_triage.py"' in (ROOT / "ui" / "app.py").read_text(encoding="utf-8")


def test_opening_a_ticket_points_at_real_results(stub, monkeypatch):
    switched = []
    monkeypatch.setattr("streamlit.switch_page", switched.append)
    app = open_page()
    start(app, "ALR-1")
    [b for b in app.button if b.label == "Abrir ticket"][0].click().run()
    assert app.session_state["selected_ticket"] == "TKT-ALR-1"
    assert app.session_state["data_source_choice"] == "Resultados reales"
    assert switched == ["pages/ticket_detail.py"]
