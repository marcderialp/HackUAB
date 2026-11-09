from eval.run_eval import evaluate, incidents_as_tickets, normalize, severity_distance, to_markdown


def golden(alert_id, verdict, severity, split="dev", incident=None):
    row = {"alert_id": alert_id, "verdict": verdict, "severity": severity, "split": split}
    if incident:
        row["incident"] = incident
    return row


def ticket(ticket_id, alert_ids, verdict, severity, **extra):
    return {"ticket_id": ticket_id, "alert_ids": alert_ids, "verdict": verdict, "severity": severity, **extra}


def test_severity_distance():
    assert severity_distance("high", "high") == 0
    assert severity_distance("low", "high") == 2
    assert severity_distance("high", "unknown") is None


def test_verdict_metrics_separate_missed_deferred_and_false_alarms():
    gold = [
        golden("A1", "true_positive", "high"),
        golden("A2", "true_positive", "high"),
        golden("A3", "true_positive", "high"),
        golden("A4", "false_positive", "low"),
    ]
    tickets = [
        ticket("T1", ["A1"], "true_positive", "high"),
        ticket("T2", ["A2"], "benign_true_positive", "low"),  # missed attack
        ticket("T3", ["A3"], "needs_more_info", "medium"),  # deferred to a human
        ticket("T4", ["A4"], "true_positive", "medium"),  # false alarm
    ]
    m = evaluate(gold, tickets)["dev"]
    assert m["verdict_accuracy"] == 0.25
    assert (m["missed_true_positives"], m["deferred_true_positives"], m["false_alarms"]) == (1, 1, 1)
    assert m["severity_exact"] == 0.25 and m["severity_within_one"] == 0.75


def test_dev_and_hold_out_are_reported_apart():
    gold = [golden("A1", "true_positive", "high"), golden("A2", "true_positive", "high", split="holdout")]
    tickets = [ticket("T1", ["A1"], "true_positive", "high"), ticket("T2", ["A2"], "false_positive", "low")]
    results = evaluate(gold, tickets)
    assert results["dev"]["verdict_accuracy"] == 1.0
    assert results["holdout"]["verdict_accuracy"] == 0.0


def test_grouping_detects_split_and_mixed_incidents():
    gold = [
        golden("A1", "true_positive", "high", incident="I1"),
        golden("A2", "true_positive", "high", incident="I1"),
        golden("A3", "true_positive", "high", incident="I2"),
        golden("A4", "true_positive", "high", incident="I3"),
    ]
    tickets = [
        ticket("T1", ["A1"], "true_positive", "high"),
        ticket("T2", ["A2"], "true_positive", "high"),  # I1 split over T1 and T2
        ticket("T3", ["A3", "A4"], "true_positive", "high"),  # I2 and I3 mixed
    ]
    g = evaluate(gold, tickets)["dev"]["grouping"]
    assert g["split_across_tickets"] == {"I1": 2}
    assert g["tickets_mixing_incidents"] == 1


def test_missing_tickets_and_cost_are_reported():
    gold = [golden("A1", "true_positive", "high"), golden("A2", "true_positive", "high")]
    tickets = [ticket("T1", ["A1"], "true_positive", "high", model_info={"cost_usd": 0.5, "latency_s": 4})]
    m = evaluate(gold, tickets)["dev"]
    assert m["covered"] == 1 and m["missing"] == ["A2"]
    assert m["cost_usd"] == 0.5 and m["mean_seconds"] == 4
    assert "missed" in to_markdown({"dev": m})


def b4(alert_id, verdict, severity, **extra):
    """A row in the B4 golden set format (made-up values)."""
    return {"alert_id": alert_id, "expected_verdict": verdict, "expected_severity": severity,
            "split": "dev", "status": "verified", **extra}


def test_normalize_accepts_b4_names_and_drops_non_incident_keys():
    row = normalize(b4("A1", "true_positive", "high", incident_key="noise-spam", expected_escalate=True))
    assert (row["verdict"], row["severity"], row["escalate"]) == ("true_positive", "high", True)
    assert row["incident"] is None
    assert normalize(b4("A2", "true_positive", "high", incident_key="bec-x"))["incident"] == "bec-x"
    assert normalize({"alert_id": "A3", "verdict": "false_positive", "split": "hold-out"})["split"] == "holdout"


def test_missed_escalations_and_twins():
    gold = [
        b4("A1", "true_positive", "high", expected_escalate=True, twin_of="A2"),
        b4("A2", "benign_true_positive", "low", expected_escalate=False, twin_of="A1"),
        b4("A3", "true_positive", "high", expected_escalate=True),
    ]
    tickets = [
        ticket("T1", ["A1"], "true_positive", "high", escalation={"escalate": True}),
        ticket("T2", ["A2"], "true_positive", "low", escalation={"escalate": False}),  # twin got the wrong verdict
        ticket("T3", ["A3"], "true_positive", "high", escalation={"escalate": False}),  # should have escalated
    ]
    m = evaluate(gold, tickets)["dev"]
    assert m["should_escalate"] == 2 and m["missed_escalations"] == 1
    assert m["twins"] == {"pairs": 1, "both_correct": 0}


def test_only_verified_skips_draft_labels():
    gold = [b4("A1", "true_positive", "high"), b4("A2", "true_positive", "high", status="to_verify")]
    tickets = [ticket("T1", ["A1", "A2"], "true_positive", "high")]
    assert evaluate(gold, tickets)["dev"]["golden_alerts"] == 2
    assert evaluate(gold, tickets, only_verified=True)["dev"]["golden_alerts"] == 1


def test_grouping_counts_incidents_kept_whole_and_ungrouped_alerts():
    gold = [
        b4("A1", "true_positive", "high", incident_key="I1"),
        b4("A2", "true_positive", "high", incident_key="I1"),
        b4("A3", "true_positive", "high", incident_key="I2"),
        b4("A4", "true_positive", "high", incident_key="I2"),
    ]
    incidents = [{"incident_id": "INC-1", "alert_ids": ["A1", "A2"]}, {"incident_id": "INC-2", "alert_ids": ["A3"]}]
    g = evaluate(gold, incidents_as_tickets(incidents))["dev"]["grouping"]
    assert g["incidents"] == 2 and g["kept_whole"] == 1
    assert g["alerts_without_ticket"] == {"I2": 1}


# --- grouping scored on both splits together, and mixes with benign alerts ---

def test_normalize_keeps_a_background_flag_for_benign_and_noise_keys():
    assert normalize(b4("A1", "false_positive", "low", incident_key="benign-pentest"))["background"] is True
    assert normalize(b4("A2", "true_positive", "high", incident_key="bec-x"))["background"] is False
    assert normalize(b4("A3", "true_positive", "high"))["background"] is False


def test_an_incident_spread_over_both_splits_is_scored_whole_only_when_grouped_whole():
    gold = [b4("A1", "true_positive", "high", incident_key="I1"),
            b4("A2", "true_positive", "high", incident_key="I1", split="holdout")]
    split_up = [{"incident_id": "INC-1", "alert_ids": ["A1"]}, {"incident_id": "INC-2", "alert_ids": ["A2"]}]
    results = evaluate(gold, incidents_as_tickets(split_up))
    # each split alone looks perfect, together the incident is cut in two
    assert results["dev"]["grouping"]["kept_whole"] == 1 and results["holdout"]["grouping"]["kept_whole"] == 1
    assert results["all_splits"]["grouping"]["kept_whole"] == 0
    assert results["all_splits"]["grouping"]["split_across_tickets"] == {"I1": 2}
    whole = [{"incident_id": "INC-1", "alert_ids": ["A1", "A2"]}]
    assert evaluate(gold, incidents_as_tickets(whole))["all_splits"]["grouping"]["kept_whole"] == 1


def test_a_ticket_mixing_an_incident_with_benign_alerts_is_counted():
    gold = [b4("A1", "true_positive", "high", incident_key="I1"),
            b4("A2", "benign_true_positive", "low", incident_key="benign-chg-1057", split="holdout")]
    merged = [{"incident_id": "INC-1", "alert_ids": ["A1", "A2"]}]
    g = evaluate(gold, incidents_as_tickets(merged))["all_splits"]["grouping"]
    assert g["tickets_mixing_with_benign"] == 1
    separate = [{"incident_id": "INC-1", "alert_ids": ["A1"]}, {"incident_id": "INC-2", "alert_ids": ["A2"]}]
    assert evaluate(gold, incidents_as_tickets(separate))["all_splits"]["grouping"]["tickets_mixing_with_benign"] == 0
    assert "mixing an incident with benign" in to_markdown(evaluate(gold, incidents_as_tickets(merged)))


# --- confidence: a correct BTP with 0.0 must not go unnoticed ---

def test_confidence_report_separates_right_wrong_low_and_missing():
    gold = [b4(f"A{i}", "benign_true_positive", "low") for i in range(1, 6)]
    tickets = [
        ticket("T1", ["A1"], "benign_true_positive", "low", confidence=0.9),
        ticket("T2", ["A2"], "benign_true_positive", "low", confidence=0.0),   # right but 0.0
        ticket("T3", ["A3"], "true_positive", "high", confidence=0.8),         # wrong
        ticket("T4", ["A4"], "benign_true_positive", "low"),                   # no confidence
        ticket("T5", ["A5"], "benign_true_positive", "low", confidence=0.7),
    ]
    c = evaluate(gold, tickets)["dev"]["confidence"]
    assert c["correct_but_low"] == ["A2"]
    assert c["missing"] == 1
    assert c["mean_when_right"] == round((0.9 + 0.0 + 0.7) / 3, 3)
    assert c["mean_when_wrong"] == 0.8
    assert "correct but under" in to_markdown(evaluate(gold, tickets))


def test_confidence_report_with_no_tickets_does_not_crash():
    c = evaluate([b4("A1", "true_positive", "high")], [])["dev"]["confidence"]
    assert c == {"mean_when_right": None, "mean_when_wrong": None, "missing": 0, "correct_but_low": []}
