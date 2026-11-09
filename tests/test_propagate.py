from triage.propagate import propagate


def rep(**extra):
    return {
        "ticket_id": "T1",
        "alert_ids": ["A0"],
        "verdict": "benign_true_positive",
        "severity": "informational",
        "severity_rationale": "base",
        "_pattern": "CcmExec | SYSTEM",
        **extra,
    }


def members(*ids, pattern="CcmExec | SYSTEM"):
    return [{"alert_id": i, "pattern": pattern} for i in ids]


def test_members_join_the_representative_ticket():
    tickets, retriage = propagate(rep(), members("A1", "A2"))
    assert retriage == []
    assert len(tickets) == 1
    assert tickets[0]["alert_ids"] == ["A0", "A1", "A2"]
    assert tickets[0]["routing"] == "cluster"
    assert "_pattern" not in tickets[0]


def test_member_failing_a_recheck_goes_back_to_the_queue():
    mixed = members("A1") + members("A2", pattern="other | pattern")
    tickets, retriage = propagate(rep(), mixed)
    assert tickets[0]["alert_ids"] == ["A0", "A1"]
    assert [m["alert_id"] for m in retriage] == ["A2"]
    assert "differs" in retriage[0]["reason"]


def test_member_with_a_different_severity_gets_its_own_ticket():
    def severity_fn(member, ticket):
        return ("high", "critical asset") if member["alert_id"] == "A2" else None

    tickets, _ = propagate(rep(), members("A1", "A2"), severity_fn=severity_fn)
    by_id = {t["ticket_id"]: t for t in tickets}
    assert by_id["T1"]["alert_ids"] == ["A0", "A1"] and by_id["T1"]["severity"] == "informational"
    [high] = [t for t in tickets if t["ticket_id"].startswith("T1-high-")]
    assert high["alert_ids"] == ["A2"] and high["verdict"] == "benign_true_positive"


def test_input_ticket_is_not_modified():
    original = rep()
    propagate(original, members("A1"))
    assert original["alert_ids"] == ["A0"] and "_pattern" in original


def test_custom_recheck_can_pull_members_out():
    def after_hours(member, ticket):
        return "outside the approved window" if member["alert_id"] == "A1" else None

    tickets, retriage = propagate(rep(), members("A1", "A2"), rechecks=(after_hours,))
    assert tickets[0]["alert_ids"] == ["A0", "A2"]
    assert retriage[0]["reason"] == "outside the approved window"


def test_groups_with_the_same_severity_but_different_escalation_get_different_ids():
    decisions = {
        "A1": {"severity": "high", "severity_rationale": "r1", "escalation": {"escalate": True, "to": "N2", "reason": "x"}},
        "A2": {"severity": "high", "severity_rationale": "r2", "escalation": {"escalate": False, "to": "", "reason": ""}},
    }
    tickets, _ = propagate(rep(), members("A1", "A2"), severity_fn=lambda m, t: decisions[m["alert_id"]])
    ids = [t["ticket_id"] for t in tickets]
    assert len(ids) == 3 and len(set(ids)) == 3  # representative + two groups, no collision


def test_ticket_ids_are_the_same_on_every_run():
    decision = {"severity": "high", "severity_rationale": "r", "escalation": {"escalate": True, "to": "N2", "reason": "x"}}
    first, _ = propagate(rep(), members("A1"), severity_fn=lambda m, t: decision)
    second, _ = propagate(rep(), members("A1"), severity_fn=lambda m, t: decision)
    assert [t["ticket_id"] for t in first] == [t["ticket_id"] for t in second]


def test_member_decision_replaces_severity_escalation_and_sla_of_the_copied_ticket():
    decision = {"severity": "critical", "severity_rationale": "own rationale",
                "escalation": {"escalate": True, "to": "N2 de guardia", "reason": "policy"},
                "sla_due": "2026-10-05T10:15:00Z"}
    base = rep(escalation={"escalate": False, "to": "", "reason": ""})
    tickets, _ = propagate(base, members("A1"), severity_fn=lambda m, t: decision)
    own = next(t for t in tickets if t["alert_ids"] == ["A1"])
    assert own["severity"] == "critical" and own["escalation"]["escalate"] is True
    assert own["sla_due"] == "2026-10-05T10:15:00Z" and own["severity_rationale"] == "own rationale"
    assert tickets[0]["escalation"]["escalate"] is False  # the representative keeps its own


def test_inherit_when_severity_fn_returns_none():
    tickets, retriage = propagate(rep(), members("A1"), severity_fn=lambda m, t: None)
    assert len(tickets) == 1 and tickets[0]["alert_ids"] == ["A0", "A1"] and retriage == []
