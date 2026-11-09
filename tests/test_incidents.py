"""E5: the incidents view."""
import json
import shutil

import pytest
from streamlit.testing.v1 import AppTest

from triage.loader import ROOT
from triage.store import Store, validate_incident
from ui.incident_logic import (
    alert_rows, build_rows, display_row, entity_rows, filter_rows, incident_tickets, local_time, report_sections,
    selection_key, summarize, tickets_by_alert, worst_severity,
)

PAGE = str(ROOT / "ui" / "pages" / "incidents.py")


def make_incident(incident_id="INC-1", alerts=("ALR-1", "ALR-2"), **extra):
    return {"incident_id": incident_id, "stage": "grouped", "title": "Título", "alert_ids": list(alerts),
            "rule_ids": ["UC-NET-006"], "first_seen": "2026-10-11T02:28:31+00:00", "last_seen": "2026-10-29T03:22:44+00:00",
            "shared_entities": ["domain:malo.example", "host:wms01"], **extra}


def make_ticket(ticket_id="TKT-1", alerts=("ALR-1",), severity="high", **extra):
    return {"ticket_id": ticket_id, "alert_ids": list(alerts), "title": "T", "verdict": "true_positive", "confidence": 0.9,
            "severity": severity, "summary": "R", "evidence": [], "recommended_actions": [],
            "escalation": {"escalate": False}, **extra}


# Rows
def test_row_counts_tickets_and_takes_the_worst_severity():
    tickets = [make_ticket("T1", ["ALR-1"], "low"), make_ticket("T2", ["ALR-2"], "critical")]
    row = build_rows([make_incident()], tickets)[0]
    assert row["severity"] == "critical" and row["triaged"] == 2 and row["alerts"] == 2


def test_incident_with_no_tickets_says_so():
    row = build_rows([make_incident()], [])[0]
    assert row["severity"] is None and row["triaged"] == 0
    shown = display_row(row)
    assert shown["Severidad"] == "Sin triar" and shown["Triadas"] == "0 de 2"


def test_one_ticket_covering_two_alerts_counts_once_as_a_ticket():
    by_alert = tickets_by_alert([make_ticket("T1", ["ALR-1", "ALR-2"])])
    assert len(incident_tickets(make_incident(), by_alert)) == 1
    assert build_rows([make_incident()], [make_ticket("T1", ["ALR-1", "ALR-2"])])[0]["triaged"] == 2


def test_a_persons_correction_counts_for_the_severity():
    ticket = make_ticket(severity="low", human_review={"status": "overridden", "override": {"severity": "critical"}})
    assert worst_severity([ticket]) == "critical"


def test_order_is_severity_then_size_with_untriaged_last():
    incidents = [make_incident("INC-SMALL", ["A"]), make_incident("INC-BIG", ["B", "C", "D"]), make_incident("INC-LOW", ["E"]),
                 make_incident("INC-HIGH", ["F"])]
    tickets = [make_ticket("T1", ["E"], "low"), make_ticket("T2", ["F"], "high")]
    assert [r["incident_id"] for r in build_rows(incidents, tickets)] == ["INC-HIGH", "INC-LOW", "INC-BIG", "INC-SMALL"]


def test_search_covers_rules_entities_and_alerts():
    rows = build_rows([make_incident("INC-1"), make_incident("INC-2", ["ALR-9"], shared_entities=["ip:10.0.0.1"])], [])
    assert [r["incident_id"] for r in filter_rows(rows, "ALR-9")] == ["INC-2"]
    assert [r["incident_id"] for r in filter_rows(rows, "MALO.example")] == ["INC-1"]
    assert len(filter_rows(rows, " ")) == 2 and not filter_rows(rows, "nada")


def test_totals():
    rows = build_rows([make_incident("INC-1"), make_incident("INC-2", ["ALR-9"])], [make_ticket()])
    assert summarize(rows) == {"incidents": 2, "alerts": 3, "triaged": 1, "urgent": 1}


def test_selection_key_changes_whenever_the_rows_do():
    one, two = {"incident_id": "INC-1"}, {"incident_id": "INC-2"}
    assert selection_key([one, two]) == selection_key([one, two])
    assert selection_key([one, two]) != selection_key([two, one])
    assert selection_key([one]) != selection_key([one, two])


def test_time_is_madrid_and_bad_values_dont_crash():
    assert local_time("2026-10-11T02:28:31+00:00") == "11/10 04:28"
    assert local_time("2026-10-29T03:22:44Z") == "29/10 04:22"  # after the clock change
    for bad in (None, "", "ayer", 5):
        assert local_time(bad) == "—"


def test_alert_rows_are_in_time_order_and_keep_missing_alerts():
    alerts = {"ALR-1": {"created_at": "2026-10-12T00:00:00Z", "rule_id": "R1", "rule_name": "Segunda", "severity": "low"},
              "ALR-2": {"created_at": "2026-10-11T00:00:00Z", "rule_id": "R2", "rule_name": "Primera", "severity": "high"}}
    incident = make_incident(alerts=["ALR-1", "ALR-2", "ALR-GONE"])
    rows = alert_rows(incident, tickets_by_alert([make_ticket()]), alerts.get)
    assert [r["Alerta"] for r in rows] == ["ALR-2", "ALR-1", "ALR-GONE"]
    assert rows[1]["Ticket"] == "TKT-1" and rows[1]["Veredicto"] == "Verdadero positivo"
    assert rows[0]["Ticket"] == "" and rows[0]["Veredicto"] == "Sin triar"
    assert rows[2]["Qué detectó"] == "No está en la cola de alertas"


def test_entities_are_split_by_type():
    assert entity_rows(make_incident(shared_entities=["domain:a:b", "suelto"])) == [
        {"Tipo": "domain", "Valor": "a:b"}, {"Tipo": "—", "Valor": "suelto"}]
    assert entity_rows({"incident_id": "X"}) == []


def test_odd_shapes_dont_crash():
    odd = {"incident_id": "X", "title": "T", "alert_ids": ["A"], "shared_entities": "no-lista", "rule_ids": None,
           "scope": "no-dict", "timeline": ["no-dict"], "containment_plan": 5, "notifications": "no-lista"}
    row = build_rows([odd], [])[0]
    assert row["entities"] == [] and display_row(row)["Reglas"] == ""
    report = report_sections(odd)
    assert report["scope"] == [] and report["containment"] == [] and report["lists"] == []


def test_grouped_incident_has_no_report():
    report = report_sections(make_incident())
    assert not any(report.values())


# The page
@pytest.fixture
def real_out(monkeypatch, tmp_path):
    monkeypatch.setenv("TARVIA_OUT", str(tmp_path))
    return tmp_path


def open_page(selected=None):
    app = AppTest.from_file(PAGE, default_timeout=30)
    if selected:
        app.session_state["selected_incident"] = selected
    app.run()
    assert not app.exception
    return app


def text_of(app):
    return [t.value for t in app.text]


def test_empty_state(real_out):
    app = AppTest.from_file(PAGE, default_timeout=30)
    app.session_state["data_source_choice"] = "Resultados reales"
    app.run()
    assert not app.exception and "Aún no hay incidentes" in app.info[0].value


def test_incident_shows_when_selected_and_opens_on_alerts(real_out):
    store = Store(real_out)
    store.save_incident(make_incident())
    store.save_ticket(make_ticket())
    app = open_page("INC-1")
    assert not app.warning  # real data, no fake data warning
    assert "Título" in text_of(app) and app.selectbox[0].options == ["TKT-1"]
    table = app.dataframe[0].value
    assert list(table["Incidente"]) == ["INC-1"] and list(table["Severidad"]) == ["🟠 Alta"]


def test_each_page_defaults_to_real_results_by_its_own_file(real_out):
    Store(real_out).save_incident(make_incident())
    assert not open_page().warning
    queue = AppTest.from_file(str(ROOT / "ui" / "pages" / "alert_queue.py"), default_timeout=30)
    queue.run()
    assert not queue.exception and "Datos ficticios" in queue.warning[0].value  # incidents alone aren't tickets


def test_a_persons_choice_of_fake_data_is_kept(real_out):
    Store(real_out).save_incident(make_incident())
    app = open_page()
    app.sidebar.radio[0].set_value("Datos ficticios").run()
    assert app.session_state["data_source_choice"] == "Datos ficticios" and "Datos ficticios" in app.warning[0].value


def test_nothing_selected_shows_only_the_list(real_out):
    Store(real_out).save_incident(make_incident())
    app = open_page()
    assert "Título" not in text_of(app) and not app.button and any("Selecciona" in c.value for c in app.caption)


def test_selection_hidden_by_the_search_shows_no_detail(real_out):
    Store(real_out).save_incident(make_incident())
    app = open_page("INC-1")
    app.sidebar.text_input[0].set_value("nada").run()
    assert not app.exception and "Título" not in text_of(app) and "Ningún incidente" in app.info[0].value


def test_opening_a_ticket(real_out, monkeypatch):
    switched = []
    monkeypatch.setattr("streamlit.switch_page", switched.append)
    store = Store(real_out)
    store.save_incident(make_incident())
    store.save_ticket(make_ticket())
    app = open_page("INC-1")
    app.button[0].click().run()
    assert app.session_state["selected_ticket"] == "TKT-1" and switched == ["pages/ticket_detail.py"]


def test_investigated_incident_from_the_fixtures_shows_its_report():
    app = AppTest.from_file(PAGE, default_timeout=30)
    app.session_state["data_source_choice"] = "Datos ficticios"
    app.session_state["selected_incident"] = "INC-FICTICIO-01"
    app.run()
    assert not app.exception and app.warning
    assert "usuario.ficticio en FIX-HOST-01" in text_of(app)
    assert {"Cronología del incidente", "Alcance", "Plan de contención propuesto"} <= {s.value for s in app.subheader}


def test_attacker_text_is_never_rendered_as_markdown(real_out):
    attack = "![x](http://malo.example/robo.png)"
    Store(real_out).save_incident(make_incident(title=attack, shared_entities=[f"domain:{attack}"], patient_zero=attack))
    app = open_page("INC-1")
    assert attack in text_of(app)
    for element in (*app.markdown, *app.caption, *app.subheader):
        assert "![x]" not in element.value


def test_damaged_lines_are_reported(real_out):
    Store(real_out).save_incident(make_incident())
    with open(real_out / "incidents.jsonl", "a", encoding="utf-8") as handle:
        handle.write("{roto}\n")
    assert "dañadas" in open_page().error[0].value


def test_real_incidents_load_and_stay_valid(tmp_path):
    # Read copies, so a pipeline run writing out/ can't change them mid-test and nothing here writes there.
    for name in ("incidents.jsonl", "tickets.jsonl"):
        if (ROOT / "out" / name).exists():
            shutil.copyfile(ROOT / "out" / name, tmp_path / name)
    text = (tmp_path / "incidents.jsonl").read_text(encoding="utf-8")
    lines = [line for line in text[: text.rfind("\n") + 1].splitlines() if line.strip()]  # skip a half-written last line
    assert lines and not [problem for line in lines for problem in validate_incident(json.loads(line))]
    store = Store(tmp_path)  # what the console shows: the latest version of each incident, with the real tickets
    incidents = store.load_incidents()
    rows = build_rows(incidents, store.load_tickets())
    assert store.health()["skipped_lines"] == 0
    assert len(rows) == len(incidents) and all(display_row(row)["Severidad"] for row in rows)


def test_page_is_in_the_navigation():
    assert '"pages/incidents.py"' in (ROOT / "ui" / "app.py").read_text(encoding="utf-8")
