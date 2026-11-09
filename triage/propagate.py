"""D5: spread a cluster representative's ticket to the cluster members, with per-alert re-checks.

A cluster verdict is only valid for members that really look like the representative. Each member is
re-checked before it inherits the ticket:
  * a re-check returns a reason string when the member must NOT inherit; that member is returned in
    `retriage` and needs its own LLM call (the verdict of the cluster says nothing about it);
  * `severity_fn` (the policy engine; see member_policy.py) decides for the member's own assets and
    identities; members whose severity or escalation differs from the representative's get their own
    ticket, with the policy's severity, rationale, escalation and SLA.
Members that pass share the representative's ticket (policy section 6: one ticket per activity), so
every alert is covered by `alert_ids` and the queue stays small.

Re-checks and `severity_fn` are injected, so this module has no dependency on the policy engine or
the LLM wrapper.
"""
import copy
import hashlib
import json


def changed_pattern(member, rep_ticket):
    """Pull out a member whose signature pattern differs from the representative's."""
    expected = rep_ticket.get("_pattern")
    if expected is not None and member.get("pattern") != expected:
        return "signature pattern differs from the cluster representative"
    return None


DEFAULT_RECHECKS = (changed_pattern,)


def _decision(result):
    """Normalise what severity_fn returns: None, a (severity, rationale) pair or a dict of ticket fields."""
    if result is None:
        return None
    if isinstance(result, dict):
        return result
    severity, rationale = result
    return {"severity": severity, "severity_rationale": rationale}


def _group_key(decision, base):
    escalation = decision.get("escalation") or base.get("escalation") or {}
    return (decision["severity"], bool(escalation.get("escalate")), escalation.get("to") or "")


def propagate(rep_ticket, members, rechecks=DEFAULT_RECHECKS, severity_fn=None):
    """Return (tickets, retriage).

    rep_ticket: the representative's ticket (dict, ticket format) with its own alert_id in alert_ids.
    members: dicts with at least `alert_id` (and `pattern` when changed_pattern is used).
    severity_fn(member, rep_ticket) -> None (inherit), (severity, rationale) or a dict of ticket fields
    (severity, severity_rationale, escalation, sla_due, severity_calc) when the member's own decision differs.
    Returns the tickets covering the representative and every member that inherited, and the members
    that need their own triage.
    """
    base = copy.deepcopy(rep_ticket)
    base.setdefault("alert_ids", [])
    base.pop("_pattern", None)
    base_key = (base.get("severity"), bool((base.get("escalation") or {}).get("escalate")),
                (base.get("escalation") or {}).get("to") or "")
    retriage, groups = [], {}
    for member in members:
        reason = next((r for check in rechecks if (r := check(member, rep_ticket))), None)
        if reason:
            retriage.append({**member, "reason": reason})
            continue
        decision = _decision(severity_fn(member, rep_ticket)) if severity_fn else None
        key = _group_key(decision, base) if decision else base_key
        group = groups.setdefault(key, {"decision": decision, "alert_ids": []})
        group["alert_ids"].append(member["alert_id"])

    tickets = []
    for key, group in groups.items():
        if key == base_key:
            base["alert_ids"] = list(dict.fromkeys(base["alert_ids"] + group["alert_ids"]))
            continue
        extra = copy.deepcopy(base)
        digest = hashlib.sha1(json.dumps(key).encode()).hexdigest()[:6]
        extra["ticket_id"] = f"{base['ticket_id']}-{key[0]}-{digest}"
        extra["alert_ids"] = group["alert_ids"]
        extra.update({k: v for k, v in group["decision"].items() if k != "severity_calc"})
        extra["severity_calc"] = group["decision"].get("severity_calc", extra.get("severity_calc"))
        if extra["severity_calc"] is None:
            del extra["severity_calc"]
        extra["routing"] = "cluster"
        tickets.append(extra)
    base["routing"] = "cluster"
    return [base] + tickets, retriage
