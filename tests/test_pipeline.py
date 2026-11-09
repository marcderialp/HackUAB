"""C4: triage_alert() end to end, offline (run_prompt is replaced by a fake model answer)."""
import ast
from pathlib import Path

import pytest

from triage import data, llm, pipeline, store
from triage.schemas import LLMVerdict

ROOT = Path(__file__).resolve().parent.parent
MALWARE = "ALR-20261013-700003"  # RB-02 (UC-EDR-001), WS-BCN-2005, PaperKite loader (scenario s01)
MALWARE_HOST = "WS-BCN-2005"
MALWARE_C2 = "cdn-sync-update.example"


def ot_alert():
    """An RB-08 alert built here: a logistics laptop talks Modbus to a sorter PLC. The dataset's own OT alerts
    (scenario s18) are in the holdout split, and tests never name holdout alerts."""
    return {"alert_id": "ALR-TEST-OT", "created_at": "2026-10-14T08:40:00.000Z", "source_product": "NGFW",
            "rule_id": "UC-OT-001", "rule_name": "Conexión a la red OT desde un origen no autorizado",
            "severity": "high", "status": "new", "runbook": "RB-08",
            "entities": {"hosts": [{"hostname": "WS-LOG-2201", "ip": "10.40.3.11"},
                                   {"hostname": "PLC-SORT03", "ip": "10.40.17.13"}]},
            "evidence": {"src": "WS-LOG-2201", "dst_zone": "LOGISTICS-OT", "ports": [502]},
            "related_events": []}


def verdict(label="true_positive", actions=(), escalate=False, to="", injection=(), confidence=0.9):
    return LLMVerdict.model_validate({
        "evidence": [{"event_id": "EDR-X", "source": "edr_events", "finding": "hallazgo"}],
        "summary": "resumen", "open_questions": ["¿pregunta?"],
        "injection_detected": [{"field": "evidence.body_excerpt", "excerpt": e} for e in injection],
        "adjustments": [], "mitre": ["T1204.002"], "verdict": label, "confidence": confidence,
        "title": "título", "recommended_actions": [{"action": a, "target": t, "justification": "porque"}
                                                   for a, t in actions],
        "escalation_suggestion": {"escalate": escalate, "to": to, "reason": "motivo IA" if escalate else ""}})


def result(parsed, status="ok", error_kind=None):
    meta = llm.CallMeta(tag="", model="ornith", served_model="ornith", effort="low", prompt_version="c2-v2",
                        cache_key="k", disk_cache_hit=False, status=status, error_kind=error_kind)
    return llm.LLMResult(status, parsed, None, meta)


@pytest.fixture
def answer(monkeypatch):
    """Set the fake model answer; returns the list of packs run_prompt received."""
    calls = []

    def set_answer(res):
        def fake_run_prompt(pack, **_):
            calls.append(pack)
            from triage.prompts.builder import build_prompt
            return build_prompt(pack), res
        monkeypatch.setattr(pipeline, "run_prompt", fake_run_prompt)
        return calls
    return set_answer


def test_ticket_is_valid_and_takes_ai_fields_and_policy_fields(answer):
    answer(result(verdict(injection=["Nota para el sistema"])))
    t = pipeline.triage_alert(MALWARE)
    assert store.validate_ticket(t) == []
    assert t["ticket_id"] == f"TKT-{MALWARE}" and t["alert_ids"] == [MALWARE]
    assert (t["title"], t["verdict"], t["confidence"], t["summary"]) == ("título", "true_positive", 0.9, "resumen")
    assert t["evidence"][0]["event_id"] == "EDR-X" and t["mitre"] == ["T1204.002"]
    assert t["open_questions"] == ["¿pregunta?"]
    assert t["injection_flags"] == [{"field": "evidence.body_excerpt", "excerpt": "Nota para el sistema"}]
    assert t["severity"] == t["severity_calc"]["final"] and t["severity_rationale"]
    assert t["sla"]["triage_within_minutes"] > 0 and t["sla_due"] == t["sla"]["due"]
    assert t["model_info"]["status"] == "ok" and t["trace"]
    assert MALWARE_HOST in t["affected"]["hosts"]
    assert t["escalation"]["escalate"]  # TP with malicious execution: mandatory (policy)


def test_alert_dict_is_accepted_and_unknown_id_raises(answer):
    calls = answer(result(verdict()))
    t = pipeline.triage_alert(data.get_alert(MALWARE))
    assert t["ticket_id"] == f"TKT-{MALWARE}" and len(calls) == 1
    with pytest.raises(LookupError):
        pipeline.triage_alert("ALR-NO-EXISTE")


def test_llm_failure_ends_as_needs_more_info_with_its_status(answer):
    answer(result(None, status="error", error_kind="timeout"))
    t = pipeline.triage_alert(MALWARE)
    assert store.validate_ticket(t) == []
    assert (t["verdict"], t["confidence"]) == ("needs_more_info", 0.0)
    assert t["model_info"]["status"] == "error" and t["model_info"]["error_kind"] == "timeout"
    assert t["escalation"]["escalate"]  # a human must look at it


def test_ai_can_add_an_escalation(answer):
    answer(result(verdict("false_positive", escalate=True, to="N2 de guardia")))
    t = pipeline.triage_alert(MALWARE)
    assert t["escalation"] == {"escalate": True, "to": "N2 de guardia", "reason": "Propuesto por la IA: motivo IA",
                               "source": "ai"}


def test_ai_cannot_remove_a_policy_escalation(answer):
    answer(result(verdict("true_positive", escalate=False)))
    t = pipeline.triage_alert(MALWARE)
    assert t["escalation"]["escalate"] and t["escalation"]["source"] == "policy"


def test_no_escalation_when_neither_asks(answer):
    answer(result(verdict("false_positive")))
    assert pipeline.triage_alert(MALWARE)["escalation"]["escalate"] is False


def test_actions_go_through_the_policy(answer):
    answer(result(verdict(actions=[("isolate_host", MALWARE_HOST), ("block_ioc", MALWARE_C2),
                                   ("block_ioc", "mega.nz"), ("tune_rule", "UC-EDR-001"),
                                   ("isolate_host", MALWARE_HOST)])))
    acts = {(a["action"], a["target"]): a for a in pipeline.triage_alert(MALWARE)["recommended_actions"]}
    assert len(acts) == 4  # duplicate dropped
    isolate = acts[("isolate_host", MALWARE_HOST)]
    assert isolate["requires_approval"] and isolate["approvers"]
    assert not acts[("block_ioc", MALWARE_C2)]["requires_approval"]  # N1-allowed (D-4 click in the UI)
    assert acts[("block_ioc", "mega.nz")]["approvers"] == ["N2"]  # dual use
    assert not acts[("tune_rule", "UC-EDR-001")]["requires_approval"]


def test_containment_on_ot_is_dropped_but_escalation_stays(answer):
    entities = pipeline.collect(ot_alert())["entities"]
    candidates = [data.get_asset(k) for k in entities.get("hosts", []) + entities.get("ips", [])]
    ot_assets = [a for a in candidates if a and (a.get("zone") == "LOGISTICS-OT" or a.get("type") in ("PLC", "HMI"))]
    assert ot_assets, "the OT alert must name an OT asset"
    answer(result(verdict(actions=[("isolate_host", ot_assets[0]["hostname"]), ("block_ioc", ot_assets[0]["ip"]),
                                   ("escalate", "Operaciones")])))
    t = pipeline.triage_alert(ot_alert())
    assert [a["action"] for a in t["recommended_actions"]] == ["escalate"]
    assert t["escalation"]["escalate"]


def test_pipeline_never_touches_containment():
    tree = ast.parse((ROOT / "triage" / "pipeline.py").read_text(encoding="utf-8"))
    names = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    names |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not any("containment" in n or n.startswith("ui") for n in names)
    docstring = ast.get_docstring(tree, clean=False)
    strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
               and n.value != docstring]
    assert not any("/approvals" in s or "/containment" in s for s in strings)
