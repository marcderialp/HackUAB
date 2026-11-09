import pytest

from triage import member_policy
from triage.member_policy import MemberChecks

ALERTS = {
    "REP": {"alert_id": "REP", "severity": "low", "created_at": "2026-10-12T10:00:00Z"},
    "SAME": {"alert_id": "SAME", "severity": "low", "created_at": "2026-10-12T11:00:00Z"},
    "VIP": {"alert_id": "VIP", "severity": "low", "created_at": "2026-10-12T12:00:00Z"},
    "OTHER": {"alert_id": "OTHER", "severity": "low", "created_at": "2026-10-12T13:00:00Z"},
}
HOSTS = {"REP": "WS-01", "SAME": "WS-01", "VIP": "WS-01", "OTHER": "WS-01"}
USERS = {"REP": ["plain"], "SAME": ["plain"], "VIP": ["boss"], "OTHER": ["plain"]}
ASSET = {"hostname": "WS-01", "criticality": "Media", "zone": "CORP", "type": "Workstation"}
PEOPLE = {
    "plain": {"username": "plain", "vip": "False", "privileged": "False", "account_type": "user"},
    "boss": {"username": "boss", "vip": "True", "privileged": "False", "account_type": "user"},
}
FLAGS = {"REP": {"approved_change": False}, "SAME": {"approved_change": False},
         "VIP": {"approved_change": False}, "OTHER": {"approved_change": False, "hr_departed": True}}


@pytest.fixture
def checks(monkeypatch):
    monkeypatch.setattr(member_policy, "context_for", lambda alert: {
        "flags": [{"flag": k, "applies": v} for k, v in FLAGS[alert["alert_id"]].items()], "changes": []})
    monkeypatch.setattr(member_policy, "extract_entities",
                        lambda alert: {"users": USERS[alert["alert_id"]], "hosts": [HOSTS[alert["alert_id"]]]})
    monkeypatch.setattr(member_policy, "_assets", lambda alert, ents: [ASSET])
    monkeypatch.setattr(member_policy.data, "get_user", lambda name: PEOPLE[name])
    return MemberChecks(get_alert=ALERTS.__getitem__)


REP_TICKET = {"ticket_id": "T1", "alert_ids": ["REP"], "verdict": "true_positive", "severity": "low"}


def test_member_in_the_same_situation_is_not_pulled_out(checks):
    assert checks.recheck({"alert_id": "SAME"}, REP_TICKET) is None


def test_member_whose_context_differs_is_pulled_out_and_the_reason_names_the_fact(checks):
    reason = checks.recheck({"alert_id": "OTHER"}, REP_TICKET)
    assert "hr_departed" in reason and "differs" in reason


def test_member_with_the_same_facts_inherits_the_decision(checks):
    assert checks.decide({"alert_id": "SAME"}, REP_TICKET) is None


def test_member_involving_a_vip_gets_its_own_policy_decision(checks):
    decision = checks.decide({"alert_id": "VIP"}, REP_TICKET)
    assert decision is not None
    assert decision["severity"] != "low"  # +1 for a VIP identity, applied by the policy engine itself
    assert decision["escalation"]["escalate"] in (True, False) and decision["sla_due"]
    assert any(a["reason_type"] == "vip_privileged" for a in decision["severity_calc"]["adjustments_applied"])
