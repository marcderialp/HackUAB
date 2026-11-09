import pytest
from streamlit.testing.v1 import AppTest

from triage.loader import ROOT
from triage.policy import TriageFacts, evaluate, sla_for
from triage.store import Store
from ui.detail_logic import (
    adjustment_rows, affected_rows, decision_panel, enrichment_rows, evidence_items, injection_rows, severity_steps,
    sla_text, trace_rows,
)

PAGE = str(ROOT / "ui" / "pages" / "ticket_detail.py")


def make_ticket(ticket_id="TKT-1", **extra):
    ticket = {
        "ticket_id": ticket_id, "alert_ids": ["ALR-1"], "title": "Título", "verdict": "true_positive",
        "confidence": 0.9, "severity": "high", "summary": "Resumen", "evidence": [],
        "recommended_actions": [], "escalation": {"escalate": False},
    }
    ticket.update(extra)
    return ticket


def test_severity_steps_read_the_real_policy_output():
    decision = evaluate(TriageFacts(
        rule_severity="medium", verdict="true_positive",
        assets=[{"hostname": "H1", "criticality": "Alta", "zone": "HQ-USERS"}],
        adjustments=[{"reason_type": "confirmed_execution", "reason": "Se ejecutó"},
                     {"reason_type": "invented", "reason": "La IA lo intenta"}],
    ))
    ticket = make_ticket(severity=decision.severity, severity_calc=decision.severity_calc)
    steps = {row["Paso"]: row["Valor"] for row in severity_steps(ticket)}
    assert steps["Severidad de la regla"] == "🟡 Media"
    assert "Alta" in steps["Criticidad usada"]
    assert steps["Severidad final"] == "🟠 Alta"
    rows = adjustment_rows(ticket)
    assert [row["Estado"] for row in rows] == ["Aplicado", "Ignorado"]
    assert rows[0]["Ajuste"] == "+1" and rows[1]["Motivo"] == "tipo de ajuste desconocido"


def test_sla_text_reads_the_policy_format():
    text = sla_text(make_ticket(sla=sla_for("critical", "2026-10-09T09:00:00Z")))
    assert text["plazo"] == "15 min" and "CISO" in text["notificar"]


def test_panel_separates_what_the_ai_and_the_person_decide():
    panel = decision_panel(make_ticket(
        recommended_actions=[
            {"action": "isolate_host", "target": "H", "requires_approval": True},
            {"action": "close", "target": "ticket", "requires_approval": False},
        ],
        open_questions=["¿Quién?"], escalation={"escalate": True, "to": "N2"},
    ))
    assert any("no la IA" in line for line in panel["automatic"])
    assert any("escalar a N2" in line for line in panel["automatic"])
    assert any("1 acciones de contención" in line and "no puede ejecutarlas" in line for line in panel["human"])
    assert any("1 preguntas abiertas" in line for line in panel["human"])


def test_panel_shows_review_state(tmp_path):
    store = Store(tmp_path)
    store.save_ticket(make_ticket())
    assert "Aceptar o corregir" in decision_panel(store.get_ticket("TKT-1"))["human"][0]
    store.record_review("TKT-1", "accepted", "Ana")
    assert "Revisado por Ana" in decision_panel(store.get_ticket("TKT-1"))["human"][0]
    store.save_ticket(make_ticket(severity="critical"))
    assert "vuelve a revisarla" in decision_panel(store.get_ticket("TKT-1"))["human"][0]


@pytest.mark.parametrize(
    "function", [severity_steps, adjustment_rows, enrichment_rows, evidence_items, injection_rows, trace_rows, affected_rows],
)
@pytest.mark.parametrize(
    "ticket",
    [
        make_ticket(),
        make_ticket(severity_calc="x", enrichment="x", evidence="x", injection_flags="x", trace="x", affected="x"),
        make_ticket(severity_calc={"adjustments_applied": ["x"], "adjustments_ignored": [5]}, enrichment=[1], evidence=[None],
                    injection_flags=["texto"], trace=[3], affected={"users": "x"}),
    ],
)
def test_unexpected_shapes_never_crash(function, ticket):
    assert isinstance(function(ticket), list)


def test_injection_flag_as_plain_text_is_kept():
    assert injection_rows(make_ticket(injection_flags=["ignora tus reglas"])) == [{"field": "—", "excerpt": "ignora tus reglas"}]


# The real page
@pytest.fixture
def page(monkeypatch, tmp_path):
    monkeypatch.setenv("TARVIA_OUT", str(tmp_path))
    return AppTest.from_file(PAGE, default_timeout=30), Store(tmp_path)


def open_ticket(app, ticket_id="TKT-1"):
    app.session_state["selected_ticket"] = ticket_id
    return app.run()


def all_text(app):
    return " | ".join(item.value for item in app.text)


def test_page_asks_for_a_selection_when_none_is_made(page):
    app, _ = page
    app.run()
    assert not app.exception and "Selecciona un ticket" in app.info[0].value


def test_page_handles_a_ticket_that_does_not_exist(page):
    app, store = page
    store.save_ticket(make_ticket())
    open_ticket(app, "NOPE")
    assert not app.exception and app.info


def test_minimal_official_ticket_displays(page):
    app, store = page
    store.save_ticket(make_ticket())
    open_ticket(app)
    assert not app.exception
    assert "Título" in all_text(app) and "Resumen" in all_text(app)
    assert [m.label for m in app.metric] == ["Veredicto de la IA", "Confianza", "Severidad", "Revisión humana"]
    assert app.metric[1].value == "90%"
    captions = " ".join(c.value for c in app.caption)
    assert "no incluye el cálculo" in captions and "no incluye la traza" in captions


def test_every_fake_ticket_displays_on_the_real_page(monkeypatch, tmp_path):
    # With no real results the page falls back to the fake tickets. out/ now holds the real run,
    # so point the real results at an empty folder instead of relying on out/ being empty.
    monkeypatch.setenv("TARVIA_OUT", str(tmp_path))
    fixtures = Store(ROOT / "ui" / "fixtures")
    for ticket in fixtures.load_tickets():
        app = AppTest.from_file(PAGE, default_timeout=30)
        app.session_state["selected_ticket"] = ticket["ticket_id"]
        app.run()
        assert not app.exception, ticket["ticket_id"]
        assert app.warning and "Datos ficticios" in app.warning[0].value
        assert ticket["title"] in all_text(app)


def test_ticket_with_everything_shows_each_part(page):
    app, store = page
    decision = evaluate(TriageFacts(rule_severity="high", verdict="true_positive", created_at="2026-10-09T09:00:00Z"))
    store.save_ticket(make_ticket(
        severity_calc=decision.severity_calc, sla=decision.sla, mitre=["T1059"], open_questions=["¿Quién autorizó?"],
        evidence=[{"source": "waf", "event_id": "WAF-7000123", "finding": "403 en /.env"}],
        enrichment=[{"indicator": "198.51.100.1", "type": "ip", "source": "ti_feed", "result": "sin coincidencias"}],
        trace=[{"step": "logs", "tool": "timeline", "params": {"entity": "H"}, "result_count": 3, "ms": 12}],
    ))
    open_ticket(app)
    assert not app.exception
    text = all_text(app)
    assert "403 en /.env" in text and "T1059" in text and "¿Quién autorizó?" in text
    assert len(app.dataframe) >= 4
    assert any(row == "Qué consultó el sistema" for row in [s.value for s in app.subheader])


def test_attacker_text_is_never_rendered_as_markdown(page):
    app, store = page
    attack = "![x](http://malo.example/robo.png) [pulsa](http://malo.example)"
    store.save_ticket(make_ticket(
        title=attack, summary=attack, severity_rationale=attack, open_questions=[attack],
        evidence=[{"source": attack, "event_id": "", "finding": attack}], mitre=[attack],
        injection_flags=[{"field": "evidence.subject", "excerpt": attack}],
        escalation={"escalate": True, "to": "N2", "reason": attack},
    ))
    open_ticket(app)
    assert not app.exception
    assert not [m.value for m in app.markdown if "malo.example" in m.value and "<" not in m.value and "![" in m.value]
    assert all("![x]" not in s.value for s in app.subheader)
    assert all("![x]" not in s.value for s in app.error)
    assert attack in all_text(app)


def test_injection_warning_appears_only_when_flagged(page):
    app, store = page
    store.save_tickets([make_ticket(), make_ticket("TKT-2", injection_flags=[{"field": "f", "excerpt": "ignora"}])])
    open_ticket(app)
    assert not app.error
    second = AppTest.from_file(PAGE, default_timeout=30)
    open_ticket(second, "TKT-2")
    assert "inyección" in second.error[0].value and "no se obedece" in second.error[0].value


@pytest.mark.db
def test_original_event_and_alert_can_be_opened(page):
    from triage import data

    alert = data.list_alerts(rule_id="UC-WEB-001", limit=1)["items"][0]
    event_id = alert["related_events"][0]
    app, store = page
    store.save_ticket(make_ticket(alert_ids=[alert["alert_id"]],
                                  evidence=[{"source": "waf", "event_id": event_id, "finding": "f"}]))
    open_ticket(app)
    assert not app.exception and len(app.json) == 1
    assert alert["alert_id"] in app.json[0].value
    app.toggle[0].set_value(True).run()
    assert not app.exception and len(app.json) == 2
    assert event_id in app.json[1].value


@pytest.mark.db
def test_missing_event_is_reported(page):
    app, store = page
    store.save_ticket(make_ticket(evidence=[{"source": "x", "event_id": "FIX-1", "finding": "f"}]))
    open_ticket(app)
    app.toggle[0].set_value(True).run()
    assert not app.exception
    assert any("no encontrado" in c.value for c in app.caption)


def test_same_event_cited_twice_doesnt_crash_the_page(page):
    app, store = page
    evidence = [{"source": "edr", "event_id": "EVT-1", "finding": "primera"}, {"source": "edr", "event_id": "EVT-1", "finding": "segunda"}]
    store.save_ticket(make_ticket(evidence=evidence))
    app.query_params["ticket"] = "TKT-1"
    app.run()
    assert not app.exception
    assert len(app.toggle) == 2


def test_markdown_in_ai_written_labels_is_shown_as_text(page):
    # An image link would make the analyst's browser fetch a remote URL (tracking, or worse).
    app, store = page
    payload = "![x](http://attacker.example/p.png)"
    store.save_ticket(make_ticket(
        evidence=[{"source": payload, "event_id": "**EVT-1**", "finding": "f"}],
        injection_flags=[{"field": payload, "excerpt": "ignora tus reglas"}],
    ))
    open_ticket(app)
    assert not app.exception
    captions = [c.value for c in app.caption]
    labels = [c for c in captions if "attacker" in c]
    assert len(labels) == 2
    assert all("\!\[x\]\(http\:" in c for c in labels)
    assert any("\*\*EVT\-1\*\*" in c for c in captions)


def test_md_escape_leaves_plain_words_alone():
    from ui.common import md_escape

    assert md_escape("Ana Pérez") == "Ana Pérez"
    assert md_escape("a_b") == "a\_b"
    assert md_escape("dos\nlíneas") == "dos líneas"
