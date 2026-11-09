"""E3: human decisions and containment, against a real running SOC API."""
import ast
import os
import re
import socket
import subprocess
import sys
import time

import pytest
import requests
from streamlit.testing.v1 import AppTest

from triage.loader import ROOT
from triage.store import Store
from ui import containment as c

PAGE = str(ROOT / "ui" / "pages" / "ticket_detail.py")
pytestmark = pytest.mark.db


def make_ticket(ticket_id="TKT-1", actions=None, **extra):
    ticket = {
        "ticket_id": ticket_id, "alert_ids": ["ALR-1"], "title": "Título", "verdict": "true_positive",
        "confidence": 0.9, "severity": "high", "summary": "Resumen", "evidence": [],
        "recommended_actions": actions or [], "escalation": {"escalate": False},
    }
    ticket.update(extra)
    return ticket


def action(name="isolate_host", target="WS-BCN-2005", approval=True):
    return {"action": name, "target": target, "requires_approval": approval, "justification": "Motivo de la IA"}


@pytest.fixture(scope="module")
def api(tmp_path_factory):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    log = tmp_path_factory.mktemp("api") / "containment.jsonl"
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.soc_api:app", "--port", str(port), "--log-level", "warning"],
        cwd=ROOT, env={**os.environ, "SOC_CONTAINMENT_LOG": str(log)},
    )
    url = f"http://127.0.0.1:{port}"
    for _ in range(120):
        try:
            requests.get(url + "/containment/log", timeout=1)
            break
        except requests.RequestException:
            time.sleep(0.25)
    yield {"url": url, "log": log}
    server.terminate()
    server.wait(timeout=20)


@pytest.fixture
def store(tmp_path, api, monkeypatch):
    monkeypatch.setenv("SOC_API_URL", api["url"])
    monkeypatch.setenv("TARVIA_OUT", str(tmp_path))
    return Store(tmp_path)


def logged(api):
    return requests.get(api["url"] + "/containment/log", timeout=5).json()


def decisions(store, ticket_id="TKT-1"):
    return [d["decision"] for d in store.get_ticket(ticket_id)["action_decisions"]]


# The rules
def test_approval_needed_action_runs_end_to_end(store, api):
    store.save_ticket(make_ticket(actions=[action()]))
    before = len(logged(api))
    result = c.approve_and_execute(store, "TKT-1", "isolate_host", "WS-BCN-2005", "Ana", "Equipo comprometido")
    assert result["result"] == "ok (simulado)"
    entries = logged(api)
    assert len(entries) == before + 1 and entries[-1]["target"] == "WS-BCN-2005" and entries[-1]["ticket_id"] == "TKT-1"
    ticket = store.get_ticket("TKT-1")
    assert decisions(store) == ["approved", "executed"]
    assert ticket["executed_actions"][-1]["approver"] == "Ana"


def test_approval_token_is_never_saved(store, api):
    store.save_ticket(make_ticket(actions=[action()]))
    c.approve_and_execute(store, "TKT-1", "isolate_host", "WS-BCN-2005", "Ana", "x")
    assert "APR-" not in (store.root / "reviews.jsonl").read_text(encoding="utf-8")
    assert "approval_token" not in (store.root / "reviews.jsonl").read_text(encoding="utf-8")


def test_no_name_means_nothing_happens(store, api):
    store.save_ticket(make_ticket(actions=[action()]))
    before = len(logged(api))
    with pytest.raises(c.ContainmentRefused):
        c.approve_and_execute(store, "TKT-1", "isolate_host", "WS-BCN-2005", "  ", "x")
    assert len(logged(api)) == before and decisions(store) == []


@pytest.mark.parametrize("target", ["PLC-SORT01", "plc-sort01", "HMI-SORT01"])
def test_ot_is_blocked_before_any_api_call(store, api, target):
    store.save_ticket(make_ticket(actions=[action(target=target)]))
    before = len(logged(api))
    assert c.check_action("isolate_host", target)["allowed"] is False
    with pytest.raises(c.ContainmentRefused, match="OT"):
        c.approve_and_execute(store, "TKT-1", "isolate_host", target, "Ana", "x")
    assert len(logged(api)) == before and decisions(store) == []


@pytest.mark.parametrize("name,target", [
    ("isolate_host", "PLC-SORT01..03"), ("block_ioc", "10.40.17.12"), ("block_ioc", "10.40.16.0/24"), ("isolate_host", "10.40.16.5"),
])
def test_every_form_of_an_ot_target_is_blocked_before_any_api_call(store, api, name, target):
    store.save_ticket(make_ticket(actions=[action(name, target)]))
    before = len(logged(api))
    assert c.check_action(name, target)["allowed"] is False
    with pytest.raises(c.ContainmentRefused, match="OT"):
        c.approve_and_execute(store, "TKT-1", name, target, "Ana", "x")
    assert len(logged(api)) == before and decisions(store) == []


def test_ot_ip_is_blocked_too(store, api):
    ip = requests.get(api["url"] + "/assets/PLC-SORT01", timeout=5).json()["ip"]
    assert c.check_action("isolate_host", ip)["allowed"] is False


def test_failed_safety_lookup_blocks_the_action(store, monkeypatch):
    def broken(_):
        raise RuntimeError("lookup failed")

    monkeypatch.setattr(c.data, "get_asset", broken)
    check = c.check_action("isolate_host", "PLC-SORT01")
    assert check["allowed"] is False and "bloquea" in check["notes"][0]


def test_action_cannot_run_twice(store, api):
    store.save_ticket(make_ticket(actions=[action()]))
    c.approve_and_execute(store, "TKT-1", "isolate_host", "WS-BCN-2005", "Ana", "x")
    before = len(logged(api))
    with pytest.raises(c.ContainmentRefused, match="ya se ejecutó"):
        c.approve_and_execute(store, "TKT-1", "isolate_host", "WS-BCN-2005", "Ana", "x")
    assert len(logged(api)) == before


def test_n1_action_needs_no_other_approver_but_still_goes_through_a_token(store, api):
    store.save_ticket(make_ticket(actions=[action("block_ioc", "malo.example", False)]))
    assert c.check_action("block_ioc", "malo.example")["requires_approval"] is False
    c.approve_and_execute(store, "TKT-1", "block_ioc", "malo.example", "Ana", "x")
    assert decisions(store) == ["approved", "executed"]
    assert store.get_ticket("TKT-1")["executed_actions"][-1]["approver"] == "Ana"


def test_dual_use_service_needs_an_approval(store, api):
    assert c.check_action("block_ioc", "mega.nz")["requires_approval"] is True
    store.save_ticket(make_ticket())
    c.approve_and_execute(store, "TKT-1", "block_ioc", "mega.nz", "Ana", "x")
    assert decisions(store) == ["approved", "executed"]


def test_workflow_steps_are_not_containment(store, api):
    store.save_ticket(make_ticket())
    for step in ("close", "escalate", "format_disk"):
        assert not c.is_containment(step)
        with pytest.raises(c.ContainmentRefused):
            c.approve_and_execute(store, "TKT-1", step, "ticket", "Ana", "x")


def test_api_down_is_recorded_and_explained(store, monkeypatch):
    monkeypatch.setenv("SOC_API_URL", "http://127.0.0.1:9")
    store.save_ticket(make_ticket())
    with pytest.raises(c.ContainmentFailed, match="uvicorn api.soc_api"):
        c.approve_and_execute(store, "TKT-1", "revoke_sessions", "ana", "Ana", "x")
    assert decisions(store) == ["approved", "failed"]
    assert store.get_ticket("TKT-1")["executed_actions"] == []


def test_failed_action_can_be_retried(store, api, monkeypatch):
    store.save_ticket(make_ticket())
    monkeypatch.setenv("SOC_API_URL", "http://127.0.0.1:9")
    with pytest.raises(c.ContainmentFailed):
        c.approve_and_execute(store, "TKT-1", "revoke_sessions", "ana", "Ana", "x")
    monkeypatch.setenv("SOC_API_URL", api["url"])
    c.approve_and_execute(store, "TKT-1", "revoke_sessions", "ana", "Ana", "x")
    assert decisions(store)[-1] == "executed"


def test_reject_needs_a_reason_and_sends_nothing(store, api):
    store.save_ticket(make_ticket())
    before = len(logged(api))
    with pytest.raises(ValueError):
        c.reject(store, "TKT-1", "isolate_host", "H", "Ana", "")
    c.reject(store, "TKT-1", "isolate_host", "H", "Ana", "Falso positivo")
    assert decisions(store) == ["rejected"] and len(logged(api)) == before


def test_build_override_keeps_only_real_changes():
    ticket = make_ticket()
    assert c.build_override(ticket, "true_positive", "high") == {}
    assert c.build_override(ticket, "false_positive", "high") == {"verdict": "false_positive"}
    assert c.build_override(ticket, "true_positive", "low") == {"severity": "low"}


def test_ai_side_cannot_reach_approval_or_containment_code():
    """The human gate depends on this: the API gives an approval token to any caller."""
    offenders = []
    for path in (ROOT / "triage").rglob("*.py"):
        # Parsed, so comments that merely mention an endpoint don't count.
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in ("ui", "api"):
                offenders.append(f"{path.name} imports {node.module}")
            elif isinstance(node, ast.Import) and any(a.name.split(".")[0] in ("ui", "api") for a in node.names):
                offenders.append(f"{path.name} imports ui or api")
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and re.search(r"/(approvals|containment)\b", node.value):
                offenders.append(f"{path.name} mentions {node.value[:40]}")
    assert offenders == []


# The real page
def open_page(ticket_id="TKT-1"):
    app = AppTest.from_file(PAGE, default_timeout=30)
    app.session_state["selected_ticket"] = ticket_id
    return app.run()


def click(app, label):
    next(b for b in app.button if b.label == label).click()
    return app.run()


def test_page_accepts_a_review(store):
    store.save_ticket(make_ticket())
    app = open_page()
    app.text_input[0].set_value("Ana").run()
    click(app, "✅ Aceptar lo que propone la IA")
    assert not app.exception and app.success
    assert store.get_ticket("TKT-1")["human_review"]["reviewer"] == "Ana"
    assert app.metric[3].value == "Aceptado"


def test_page_requires_a_name_for_a_review(store):
    store.save_ticket(make_ticket())
    app = open_page()
    click(app, "✅ Aceptar lo que propone la IA")
    assert not app.exception and app.error
    assert any("Escribe tu nombre" in t.value for t in app.text)
    assert store.get_ticket("TKT-1")["human_review"]["status"] == "pending"


def test_page_correction_needs_a_change_and_a_reason(store):
    store.save_ticket(make_ticket())
    app = open_page()
    app.text_input[0].set_value("Ana").run()
    click(app, "✏️ Guardar mi corrección")
    assert any("No has cambiado" in t.value for t in app.text)
    app.selectbox[1].set_value("low")
    click(app, "✏️ Guardar mi corrección")
    assert any("motivo" in t.value for t in app.text)
    assert store.get_ticket("TKT-1")["human_review"]["status"] == "pending"
    app.selectbox[1].set_value("low")
    app.text_input[1].set_value("Cambio aprobado")
    click(app, "✏️ Guardar mi corrección")
    ticket = store.get_ticket("TKT-1")
    assert not app.exception and ticket["human_review"]["override"] == {"severity": "low"} and ticket["severity"] == "high"


def test_page_approves_and_executes(store, api):
    store.save_ticket(make_ticket(actions=[action()]))
    before = len(logged(api))
    app = open_page()
    app.text_input[0].set_value("Ana").run()
    click(app, "Aprobar y ejecutar")
    assert not app.exception and len(logged(api)) == before + 1
    assert decisions(store) == ["approved", "executed"]
    assert not [b for b in app.button if b.label == "Aprobar y ejecutar"]


def test_page_without_a_name_executes_nothing(store, api):
    store.save_ticket(make_ticket(actions=[action()]))
    before = len(logged(api))
    app = open_page()
    click(app, "Aprobar y ejecutar")
    assert not app.exception and app.error and len(logged(api)) == before


def test_page_offers_no_buttons_for_blocked_ot(store, api):
    store.save_ticket(make_ticket(actions=[action(target="PLC-SORT01")]))
    app = open_page()
    assert not app.exception
    assert not [b for b in app.button if b.label in ("Aprobar y ejecutar", "Rechazar")]
    assert any("bloquea" in e.value for e in app.error)


def test_page_rejects_with_a_reason(store, api):
    store.save_ticket(make_ticket(actions=[action()]))
    before = len(logged(api))
    app = open_page()
    app.text_input[0].set_value("Ana").run()
    click(app, "Rechazar")
    assert any("motivo" in t.value for t in app.text) and decisions(store) == []
    next(t for t in app.text_input if t.label.startswith("Motivo (obligatorio para rechazar)")).set_value("Falso positivo")
    click(app, "Rechazar")
    assert not app.exception and decisions(store) == ["rejected"] and len(logged(api)) == before


def test_page_lists_workflow_steps_without_buttons(store, api):
    store.save_ticket(make_ticket(actions=[{"action": "close", "target": "ticket", "requires_approval": False, "justification": "Sin impacto"}]))
    app = open_page()
    assert not app.exception
    assert any("Cerrar: ticket" in t.value for t in app.text)
    assert not [b for b in app.button if b.label == "Aprobar y ejecutar"]


def test_page_keeps_working_when_the_api_is_down(store, monkeypatch):
    monkeypatch.setenv("SOC_API_URL", "http://127.0.0.1:9")
    store.save_ticket(make_ticket(actions=[action()]))
    app = open_page()
    app.text_input[0].set_value("Ana").run()
    click(app, "Aprobar y ejecutar")
    assert not app.exception and app.error
    assert any("uvicorn api.soc_api" in t.value for t in app.text)
    assert decisions(store) == ["approved", "failed"]


def test_attacker_controlled_target_stays_plain_text(store, api):
    attack = "![x](http://malo.example/a.png)"
    store.save_ticket(make_ticket(actions=[action("block_ioc", attack, False)]))
    app = open_page()
    assert not app.exception
    assert attack in [t.value for t in app.text]
    assert not [m.value for m in app.markdown if "![x]" in m.value]
    assert not [c_.value for c_ in app.caption if "![x]" in c_.value]


def test_every_fake_ticket_still_displays(api, monkeypatch):
    monkeypatch.setenv("SOC_API_URL", api["url"])
    for ticket in Store(ROOT / "ui" / "fixtures").load_tickets():
        app = open_page(ticket["ticket_id"])
        assert not app.exception, ticket["ticket_id"]
