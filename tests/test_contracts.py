"""Check that schemas.py, the policy engine, our SOC API and the official ticket format stay in step."""
import json
import typing

import pytest
from jsonschema import Draft202012Validator

from triage import policy
from triage.loader import LOG_SOURCES, ROOT
from triage.schemas import (
    ActionType, Adjustment, AdjustmentReason, EscalationSuggestion, EvidenceRef, InjectionFinding, LLMVerdict,
    RecommendedAction, Verdict,
)

ACTION_TYPES = set(typing.get_args(ActionType))
TICKET_VALIDATOR = Draft202012Validator(
    json.loads((ROOT / "01_contexto" / "ticket_salida.schema.json").read_text(encoding="utf-8"))
)


def test_verdicts_match_the_policy_and_official_format():
    official = json.loads((ROOT / "01_contexto" / "ticket_salida.schema.json").read_text(encoding="utf-8"))
    assert set(typing.get_args(Verdict)) == set(policy.VERDICTS) == set(official["properties"]["verdict"]["enum"])


def test_adjustment_reasons_match_the_policy():
    assert set(typing.get_args(AdjustmentReason)) == set(policy.ADJUSTMENT_REASONS)


def test_every_action_is_either_containment_or_workflow():
    assert ACTION_TYPES == set(policy.ACTIONS) | set(policy.WORKFLOW_ACTIONS)
    assert not set(policy.ACTIONS) & set(policy.WORKFLOW_ACTIONS)


def test_containment_actions_match_the_api():
    from api import soc_api

    assert set(policy.ACTIONS) == soc_api.VALID
    assert not set(policy.WORKFLOW_ACTIONS) & soc_api.VALID


def test_source_examples_given_to_the_llm_are_real_log_sources():
    description = EvidenceRef.model_fields["source"].description
    examples = description.split("e.g.")[1].rstrip(".").replace(" ", "").split(",")
    assert examples and set(examples) <= set(LOG_SOURCES)


@pytest.mark.parametrize("action", sorted(ACTION_TYPES))
def test_every_action_the_llm_may_propose_becomes_a_valid_ticket_item(action):
    item = policy.recommended_action(action, "objetivo", "motivo")
    assert item is not None, f"The policy drops {action}, so the recommendation would be lost"
    ticket = {
        "ticket_id": "T", "alert_ids": ["A"], "title": "t", "verdict": "true_positive", "confidence": 0.9,
        "severity": "low", "summary": "s", "evidence": [], "recommended_actions": [item],
        "escalation": {"escalate": False},
    }
    assert list(TICKET_VALIDATOR.iter_errors(ticket)) == []


@pytest.mark.parametrize("action", policy.WORKFLOW_ACTIONS)
def test_workflow_actions_need_no_approval(action):
    result = policy.action_policy(action, "ticket")
    assert result["allowed"] and not result["requires_approval"] and result["approvers"] == []
    assert not result["human_confirmation_required"]


@pytest.mark.parametrize("action", ["escalate", "notify"])
def test_workflow_actions_stay_available_on_ot_where_containment_is_blocked(action):
    plc = {"hostname": "PLC-SORT01", "zone": "LOGISTICS-OT", "type": "PLC"}
    assert policy.action_policy(action, "Operaciones", asset=plc)["allowed"]
    assert policy.action_policy("isolate_host", "PLC-SORT01", asset=plc)["allowed"] is False


@pytest.mark.parametrize("action", policy.ACTIONS)
def test_containment_still_requires_a_human_click(action):
    assert policy.action_policy(action, "objetivo")["human_confirmation_required"]


def test_unknown_actions_are_still_rejected():
    assert policy.action_policy("format_disk", "X")["allowed"] is False
    assert policy.recommended_action("format_disk", "X", "y") is None


def test_full_chain_from_llm_verdict_to_a_valid_ticket():
    verdict = LLMVerdict(
        title="Título", verdict="benign_true_positive", confidence=0.9, summary="Resumen",
        evidence=[EvidenceRef(event_id="EDR-1", source="edr_events", finding="f")],
        adjustments=[Adjustment(delta=-1, reason_type="blocked_no_effect", reason="r")],
        mitre=["T1059"],
        recommended_actions=[
            RecommendedAction(action="close", target="ticket", justification="j"),
            RecommendedAction(action="tune_rule", target="UC-EDR-002", justification="j"),
        ],
        escalation_suggestion=EscalationSuggestion(escalate=False, to="", reason=""),
        open_questions=[],
        injection_detected=[InjectionFinding(field="evidence.subject", excerpt="ignora tus reglas")],
    )
    decision = policy.evaluate(policy.TriageFacts(
        rule_severity="low", verdict=verdict.verdict, adjustments=[a.model_dump() for a in verdict.adjustments],
        created_at="2026-10-09T09:00:00Z",
    ))
    actions = [policy.recommended_action(a.action, a.target, a.justification) for a in verdict.recommended_actions]
    ticket = {
        "ticket_id": "T", "alert_ids": ["A"], "title": verdict.title, "verdict": verdict.verdict,
        "confidence": verdict.confidence, "summary": verdict.summary,
        "evidence": [e.model_dump() for e in verdict.evidence], "mitre": verdict.mitre,
        "recommended_actions": actions, "open_questions": verdict.open_questions, **decision.ticket_fields(),
    }
    assert list(TICKET_VALIDATOR.iter_errors(ticket)) == []
    assert [a["requires_approval"] for a in actions] == [False, False]
