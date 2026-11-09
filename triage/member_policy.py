"""D5 wiring: real re-checks and a real policy decision for cluster members.

A cluster verdict only holds for members that are in the same situation as the representative. Two checks:

  recheck(member, rep_ticket)   pulls a member out of the cluster when any context fact (approved change,
                                HR events, internal rules; see context.py) differs from the representative's.
                                That member then needs its own triage.
  decide(member, rep_ticket)    runs the policy engine on the member's own assets and identities. Returns None
                                when the member gets the same decision as the representative (it inherits the
                                ticket), or the member's own decision when it differs (own ticket).

The representative is evaluated with the same function and the same assumptions as the member, so a
difference comes from the facts of the alerts, never from information the stand-in ticket happens not to carry.
Plug in with: propagate_clusters(..., rechecks=(changed_pattern, checks.recheck), severity_fn=checks.decide).
"""
from typing import Any

from triage import data
from triage.context import _assets, context_for
from triage.entities import extract_entities
from triage.policy import TriageFacts, evaluate


def _flags(context):
    return {flag["flag"]: flag["applies"] for flag in context["flags"]}


class MemberChecks:
    def __init__(self, get_alert=data.get_alert):
        self._get_alert = get_alert
        self._cache: dict[str, dict[str, Any]] = {}
        self._rep_decisions: dict[str, Any] = {}

    def _alert(self, alert_id):
        alert = self._get_alert(alert_id)
        if alert is None:
            raise LookupError(f"alert {alert_id} not found")
        return alert

    def _context(self, alert_id):
        """(alert, context) of an alert, computed once."""
        if alert_id not in self._cache:
            alert = self._alert(alert_id)
            self._cache[alert_id] = {"alert": alert, "context": context_for(alert)}
        return self._cache[alert_id]

    def recheck(self, member, rep_ticket):
        """Reason to pull the member out of the cluster, or None."""
        rep_id = rep_ticket["alert_ids"][0]
        member_flags = _flags(self._context(member["alert_id"])["context"])
        rep_flags = _flags(self._context(rep_id)["context"])
        different = sorted(name for name in member_flags.keys() | rep_flags.keys()
                           if member_flags.get(name) != rep_flags.get(name))
        return f"context differs from the representative: {', '.join(different)}" if different else None

    def facts_for(self, alert_id, rep_ticket) -> TriageFacts:
        entry = self._context(alert_id)
        alert, context = entry["alert"], entry["context"]
        ents = extract_entities(alert)
        covering = [c for c in context["changes"] if c.get("applies") is True]
        calc = rep_ticket.get("severity_calc") or {}
        floor = calc.get("runbook_floor") or {}
        return TriageFacts(
            rule_severity=alert.get("severity", "low"),
            verdict=rep_ticket.get("verdict", "needs_more_info"),
            assets=_assets(alert, ents),
            identities=[u for u in (data.get_user(name) for name in ents.get("users", [])) if u],
            customers_involved=bool(ents.get("customers")),
            # the representative's judgment about the activity (the policy computes VIP/privileged itself)
            adjustments=list(calc.get("adjustments_applied") or calc.get("adjustments") or []),
            approved_change=covering[0]["change_id"] if covering else None,
            runbook_severity=floor.get("severity") if floor.get("applied") else None,
            runbook_reason=floor.get("reason", ""),
            created_at=alert.get("created_at"),
        )

    def decide(self, member, rep_ticket):
        """None if the member inherits the representative's decision, else its own decision as ticket fields."""
        member_decision = evaluate(self.facts_for(member["alert_id"], rep_ticket))
        rep_id = rep_ticket["alert_ids"][0]
        if rep_id not in self._rep_decisions:
            self._rep_decisions[rep_id] = evaluate(self.facts_for(rep_id, rep_ticket))
        rep_decision = self._rep_decisions[rep_id]
        fields = member_decision.ticket_fields()
        if (fields["severity"], fields["escalation"]["escalate"], fields["escalation"]["to"]) == (
            rep_decision.severity, rep_decision.escalation["escalate"], rep_decision.escalation["to"]
        ):
            return None
        return {**fields, "sla_due": member_decision.sla["due"], "severity_calc": member_decision.severity_calc}
