"""C4: triage one alert end to end: evidence -> AI verdict -> policy -> ticket.

    ticket = triage_alert("ALR-20261013-700003")      # or the alert dict (live mode)

1. B3 `collect(alert)` builds the EvidencePack (findings with event ids, intel, context, trace).
2. C2 `run_prompt(pack)` asks the model for an `LLMVerdict` and checks citations and D-6 (one retry).
   Any failure becomes `llm.needs_more_info_verdict(result)`: needs_more_info, confidence 0, escalated.
3. `facts_for(pack, verdict, prompt)` turns the pack and verdict into policy facts (code, no AI).
4. `policy.evaluate(facts)` sets severity, its rationale, the SLA and the mandatory escalation.
5. The ticket follows 01_contexto/ticket_salida.schema.json plus the extensions the console reads (docs/design.md, data contracts).

Who decides what:
- The AI: title, verdict, confidence, summary, evidence, MITRE, open questions, injection findings and
  the actions it proposes. It never sets severity, SLA or approvers.
- The policy: severity, SLA, mandatory escalation, and which proposed actions survive and who approves
  them (`policy.recommended_action`: OT and unsupported actions are dropped, dual use needs N2).
- Escalation = policy OR the AI's suggestion: the AI can add an escalation, never remove one.

Nothing is saved here: the runner and live mode save the ticket through triage/store.py. Nothing is
executed either: containment only happens in the console, after a person's click.
"""
from __future__ import annotations

import time
from typing import Any

from triage import data, llm, policy
from triage.collectors import collect
from triage.facts import facts_for
from triage.prompts.builder import run_prompt

AI_ESCALATION_DEFAULT_TO = "N2"
GEO_FLAGS = (("is_tor", "Tor"), ("is_vpn_provider", "VPN"), ("is_hosting", "hosting"),
             ("is_residential_proxy", "proxy residencial"))


def _match(rows: list[dict[str, Any]], target: str, keys: tuple[str, ...]) -> dict[str, Any] | None:
    wanted = str(target).strip().casefold()
    for row in rows:
        if any(str(row.get(k) or "").strip().casefold() == wanted for k in keys):
            return row
    return None


def _asset_for(pack: dict[str, Any], target: str) -> dict[str, Any] | None:
    """The inventory asset an action targets (hostname or IP), so the policy can see OT and servers."""
    assets = list((pack.get("inventory") or {}).get("assets") or [])
    found = _match(assets, target, ("hostname", "ip", "asset_id"))
    if found is None:
        try:
            found = data.get_asset(target)
        except Exception:  # an unknown or odd target is not a reason to lose the ticket
            found = None
    return found


def _user_for(pack: dict[str, Any], target: str) -> dict[str, Any] | None:
    identities = list((pack.get("inventory") or {}).get("identities") or [])
    return _match(identities, target, ("username", "upn", "user_id"))


def recommended_actions(pack: dict[str, Any], verdict: Any) -> list[dict[str, Any]]:
    """The AI's proposed actions, each passed through the policy; forbidden ones are dropped."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for proposal in getattr(verdict, "recommended_actions", []) or []:
        key = (proposal.action, proposal.target)
        if key in seen:
            continue
        seen.add(key)
        containment = proposal.action in policy.ACTIONS
        asset = _asset_for(pack, proposal.target) if containment else None
        user = _user_for(pack, proposal.target) if proposal.action == "disable_user" else None
        item = policy.recommended_action(proposal.action, proposal.target, proposal.justification, asset, user)
        if item is not None:
            out.append(item)
    return out


def escalation(decision: policy.PolicyDecision, verdict: Any) -> dict[str, Any]:
    """Policy escalation OR the AI's suggestion. The AI can add an escalation, never remove one."""
    esc = decision.ticket_fields()["escalation"]
    suggestion = getattr(verdict, "escalation_suggestion", None)
    ai = bool(suggestion and suggestion.escalate)
    if not ai:
        return {**esc, "source": "policy" if esc["escalate"] else ""}
    ai_reason = f"Propuesto por la IA: {suggestion.reason}" if suggestion.reason else "Propuesto por la IA"
    if esc["escalate"]:
        return {**esc, "reason": "; ".join(r for r in (esc["reason"], ai_reason) if r), "source": "policy+ai"}
    return {"escalate": True, "to": suggestion.to or AI_ESCALATION_DEFAULT_TO, "reason": ai_reason, "source": "ai"}


def affected(pack: dict[str, Any], facts: policy.TriageFacts) -> dict[str, list[Any]]:
    inventory = pack.get("inventory") or {}
    entities = pack.get("entities") or {}
    services = list(facts.services)
    for asset in inventory.get("assets") or []:
        service = asset.get("business_service")
        if service and service not in services:
            services.append(service)
    return {
        "users": list(entities.get("users") or []),
        "hosts": list(entities.get("hosts") or []),
        "business_services": services,
        "customers": list(entities.get("customers") or []),
    }


def enrichment(pack: dict[str, Any]) -> list[dict[str, str]]:
    """One line per indicator the collectors looked up (TIP, sandbox, GeoIP), for the console."""
    rows = []
    for item in pack.get("intel") or []:
        parts, sources = [], []
        for key in ("tip", "sandbox", "geo"):
            hit = item.get(key)
            if not isinstance(hit, dict):
                continue
            sources.append(key)
            verdict = hit.get("reputation") or hit.get("verdict")
            family = hit.get("malware_family")
            if key == "geo":
                flags = [label for k, label in GEO_FLAGS if str(hit.get(k)).casefold() == "true"]
                parts.append(", ".join([str(hit[k]) for k in ("country", "city", "as_org") if hit.get(k)] + flags))
            else:
                parts.append(" ".join(str(v) for v in (verdict, family) if v))
        rows.append({"indicator": str(item.get("indicator", "")), "type": str(item.get("type", "")),
                     "source": "+".join(sources) or "tip",
                     "result": "; ".join(p for p in parts if p) or "sin coincidencias"})
    return rows


def model_info(result: llm.LLMResult[Any]) -> dict[str, Any]:
    """C1 model info plus what the runner needs to log and retry a failed call."""
    meta = result.meta
    return {**meta.model_info(), "error_kind": meta.error_kind, "retry_reason": meta.retry_reason,
            "attempts": meta.attempts, "dropped_citations": meta.dropped_citations}


def build_ticket(pack: dict[str, Any], verdict: Any, result: llm.LLMResult[Any], facts: policy.TriageFacts,
                 decision: policy.PolicyDecision, seconds: float) -> dict[str, Any]:
    alert_id = pack.get("alert_id") or (pack.get("alert") or {}).get("alert_id")
    ticket: dict[str, Any] = {
        "ticket_id": f"TKT-{alert_id}",
        "alert_ids": [alert_id],
        "title": verdict.title,
        "verdict": verdict.verdict,
        "confidence": verdict.confidence,
        "severity": decision.severity,
        "severity_rationale": decision.severity_rationale,
        "affected": affected(pack, facts),
        "summary": verdict.summary,
        "evidence": [e.model_dump() for e in verdict.evidence],
        "enrichment": enrichment(pack),
        "mitre": list(verdict.mitre),
        "recommended_actions": recommended_actions(pack, verdict),
        "executed_actions": [],
        "escalation": escalation(decision, verdict),
        "open_questions": list(verdict.open_questions),
        "triage_seconds": round(seconds, 2),
        # Extensions to the official ticket format (store._TICKET_EXTENSIONS, read by the console)
        "rule_severity": policy.norm_severity(facts.rule_severity),
        "severity_calc": decision.severity_calc,
        "sla": decision.sla,
        "sla_due": decision.sla.get("due"),
        "injection_flags": [f.model_dump() for f in verdict.injection_detected],
        "policy_warnings": list(decision.warnings),
        "model_info": model_info(result),
        "trace": list(pack.get("trace") or []),
    }
    return ticket


def triage_alert(alert: str | dict[str, Any], *, extra_untrusted: list[dict[str, str]] | None = None
                 ) -> dict[str, Any]:
    """Triage one alert (id or alert dict) and return its ticket. Does not save it.

    `extra_untrusted`: more attacker-writable fields ({"field": "evidence.<key>", "text": ...}) to fence,
    beyond the known list; live mode (triage/live.py) passes free text from fields it doesn't know."""
    started = time.monotonic()
    if isinstance(alert, str):
        found = data.get_alert(alert)
        if found is None:
            raise LookupError(f"alert {alert} not found")
        alert = found
    pack = collect(alert)
    if extra_untrusted:
        known = {u.get("field") for u in pack.get("untrusted") or [] if isinstance(u, dict)}
        pack["untrusted"] = list(pack.get("untrusted") or []) + [u for u in extra_untrusted if u["field"] not in known]
    prompt, result = run_prompt(pack)
    verdict = result.parsed if result.ok else llm.needs_more_info_verdict(result)
    facts = facts_for(pack, verdict, prompt)
    decision = policy.evaluate(facts)
    return build_ticket(pack, verdict, result, facts, decision, time.monotonic() - started)
