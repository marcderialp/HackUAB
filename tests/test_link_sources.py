import pandas as pd

from triage.link_sources import (
    approved_change_covers, benign_ticket_alert_ids, entities_from_findings, user_host_pivots,
)

TS = pd.Timestamp("2026-10-13T08:00:00Z")


def test_ips_and_emails_cited_in_findings_become_entities():
    findings = [
        {"fact": "en 72 h, uso de claves desde fuera del runner: 203.0.113.77 (AKIA...) x186; 172.16.20.31 x11"},
        {"fact": "6 correos de Avisos@M365-Buzon-Lleno.example a 6 buzones"},
        {"fact": "sin entidades aqui"},
    ]
    rows = entities_from_findings("A1", TS, findings)
    assert ("A1", "ip", "203.0.113.77", TS) in rows and ("A1", "ip", "172.16.20.31", TS) in rows
    assert ("A1", "email", "avisos@m365-buzon-lleno.example", TS) in rows  # lower-cased
    assert len(rows) == 3


def test_findings_without_text_do_not_crash():
    assert entities_from_findings("A1", TS, []) == []
    assert entities_from_findings("A1", TS, [{"check": "x"}]) == []


def test_user_host_pivot_skips_busy_hosts_and_asks_for_a_day_either_side():
    calls = []

    def fake(user, start, end):
        calls.append((user, start, end))
        return [{"value": "wms01", "events": 1, "first_seen": "2026-10-13T01:52:00.000Z"},
                {"value": "jump01", "events": 900, "first_seen": "2026-10-13T01:00:00.000Z"}]

    rows = user_host_pivots("A1", TS, ["ext.logisoft"], hosts_for_user=fake)
    assert [(r[1], r[2]) for r in rows] == [("host", "wms01")]
    assert calls[0][1] == TS - pd.Timedelta(days=1) and calls[0][2] == TS + pd.Timedelta(days=1)


def test_approved_change_covers_only_when_it_applies():
    assert approved_change_covers({"flags": [{"flag": "approved_change", "applies": True}]})
    assert not approved_change_covers({"flags": [{"flag": "approved_change", "applies": None}]})  # only "possible"
    assert not approved_change_covers({"flags": [{"flag": "approved_change", "applies": False}]})
    assert not approved_change_covers({"flags": []})


def test_benign_and_false_positive_tickets_are_excluded_but_attacks_are_not():
    tickets = [
        {"verdict": "benign_true_positive", "alert_ids": ["A1", "A2"]},
        {"verdict": "false_positive", "alert_ids": ["A3"]},
        {"verdict": "true_positive", "alert_ids": ["A4"]},
        {"verdict": "needs_more_info", "alert_ids": ["A5"]},
    ]
    assert benign_ticket_alert_ids(tickets) == {"A1", "A2", "A3"}


def test_benign_tickets_still_name_their_alerts_after_a_human_override_is_applied():
    """correlate passes {**ticket, **effective(ticket)}: effective() alone has no alert_ids (the bug it fixed)."""
    from triage.store import effective

    ticket = {"alert_ids": ["A1"], "verdict": "true_positive", "human_review": {"override": {"verdict": "false_positive"}, "reviewer": "x"}}
    assert benign_ticket_alert_ids([{**ticket, **effective(ticket)}]) == {"A1"}
    assert benign_ticket_alert_ids([effective(ticket)]) == set()
