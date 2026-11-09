"""D6 v2: extra evidence for the incident graph (joins incidents the alerts alone split, keeps authorized activity out).

The alert graph in correlate.py only sees the entities in the alerts. Three more sources:

  * Entities cited in the collectors' findings (B3): the poisoned-package alert's finding names the
    IP that later used the stolen key; the second phishing wave's finding names the first wave's
    sender. The findings are written by code from the logs, so reading their `fact` text is safe.
  * User -> host pivots from the logs: the hosts a user touched within a day of the alert (the
    vendor's VPN login and the server that later tunnels DNS). Hosts with more than MAX_PIVOT_EVENTS
    events are skipped: a busy host links nothing.
  * Exclusions: alerts an approved change covers, and alerts whose ticket says benign or false
    positive, are authorized or routine activity, not part of an attack incident.
"""
import re

import pandas as pd

from triage import data
from triage.collectors import collect
from triage.context import context_for

BENIGN_VERDICTS = {"benign_true_positive", "false_positive"}
PIVOT_WINDOW = pd.Timedelta(days=1)
MAX_PIVOT_EVENTS = 50
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")


def entities_from_findings(alert_id, ts, findings):
    """(alert_id, type, value, ts) rows for the IPs and e-mail addresses a finding names."""
    text = " ".join(str(f.get("fact", "")) for f in findings)
    rows = [(alert_id, "ip", ip, ts) for ip in sorted(set(_IP.findall(text)))]
    rows += [(alert_id, "email", mail, ts) for mail in sorted({m.lower() for m in _EMAIL.findall(text)})]
    return rows


def user_host_pivots(alert_id, ts, users, hosts_for_user=data.hosts_for_user):
    """(alert_id, 'host', host, event time) rows for the hosts each user touched within a day of the alert."""
    rows = []
    for user in users:
        for host in hosts_for_user(user, ts - PIVOT_WINDOW, ts + PIVOT_WINDOW):
            if host["events"] <= MAX_PIVOT_EVENTS:
                rows.append((alert_id, "host", host["value"], pd.Timestamp(host["first_seen"]).tz_convert("UTC")
                             if pd.Timestamp(host["first_seen"]).tzinfo else pd.Timestamp(host["first_seen"], tz="UTC")))
    return rows


def approved_change_covers(context):
    """True if the alert's context says an approved change really covers it."""
    return any(f["flag"] == "approved_change" and f["applies"] is True for f in context["flags"])


def benign_ticket_alert_ids(tickets):
    """Alert ids whose ticket (with the human's override applied) says benign or false positive."""
    ids = set()
    for ticket in tickets:
        if ticket.get("verdict") in BENIGN_VERDICTS:
            ids.update(ticket.get("alert_ids", []))
    return ids


def enrich(nodes, alert_for=data.get_alert):
    """(extra entity rows as a DataFrame, ids of alerts covered by an approved change) for the graph nodes."""
    rows, approved = [], set()
    for alert_id, created_at in zip(nodes["alert_id"], nodes["created_at"]):
        alert = alert_for(alert_id)
        pack = collect(alert)
        rows += entities_from_findings(alert_id, created_at, pack.get("findings") or [])
        rows += user_host_pivots(alert_id, created_at, pack["entities"].get("users") or [])
        if approved_change_covers(context_for(alert)):
            approved.add(alert_id)
    extra = pd.DataFrame(rows, columns=["alert_id", "entity_type", "entity_value", "ts"])
    return extra, approved
