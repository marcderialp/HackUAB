"""Shared data contracts (docs/design.md, data contracts).

`LLMVerdict` is the model's structured output. It follows the contract in docs/design.md
field-for-field; the enums come from documented sources:
  - AdjustmentReason: the four ±1 reasons in the SOC policy §2, with the
    names used by the B1 policy engine.
  - ActionType: the containment actions accepted by the SOC API (api/soc_api.py)
    (VALID set) plus non-containment workflow actions.
EvidencePack, Ticket and Incident are still to be frozen at CP0. Any change here is
a contract change and must be announced to the team.

The model never outputs final severity, SLA, approvals or executed actions:
the policy engine (triage/policy.py) computes those from this verdict.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal["true_positive", "benign_true_positive", "false_positive", "needs_more_info"]

# SOC policy §2 "Ajustes". Names shared with B1 (triage/policy.py ADJUSTMENT_DELTAS)
# and part of the contract in docs/design.md; renaming one breaks the policy engine.
AdjustmentReason = Literal[
    "confirmed_execution",  # +1: execution/access confirmed, not just attempted
    "vip_privileged",  # +1: affected identity is VIP or privileged
    "personal_data_payments",  # +1: personal data or payments involved
    "blocked_no_effect",  # -1: a control blocked it before effect, no later activity
]

ActionType = Literal[
    # Containment (mock API /containment/{action})
    "block_ioc",
    "purge_email",
    "revoke_sessions",
    "reset_password",
    "isolate_host",
    "disable_user",
    "disable_access_key",
    # Workflow (no API call)
    "close",
    "escalate",
    "notify",  # target = who (e.g. "DPO", "Tesorería", "Operaciones", "Fraude")
    "investigate",  # further manual analysis by N2
    "tune_rule",  # propose a detection-rule exclusion (RB-09)
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceRef(_Strict):
    event_id: str = Field(description="Exact event_id from the evidence pack. Never invented.")
    source: str = Field(description="Log source of the event, e.g. edr_events, proxy, idp_signins.")
    finding: str = Field(description="What this event shows, in Spanish.")


class Adjustment(_Strict):
    delta: Literal[-1, 1]
    reason_type: AdjustmentReason
    reason: str = Field(description="Justification in Spanish, citing evidence.")


class RecommendedAction(_Strict):
    action: ActionType
    target: str = Field(description="Host, user, IOC, message_id, access key, team or 'ticket'.")
    justification: str = Field(description="Why, in Spanish.")


class EscalationSuggestion(_Strict):
    escalate: bool
    to: str = Field(description="e.g. 'N2', 'N2 de guardia', 'Operaciones'; empty if no escalation.")
    reason: str = Field(description="Why, in Spanish; empty if no escalation.")


class InjectionFinding(_Strict):
    field: str = Field(description="Where the attacker-controlled instruction appeared.")
    excerpt: str = Field(description="Short verbatim excerpt of the instruction-like text.")


class LLMVerdict(_Strict):
    """Structured output of a triage LLM call. Text fields in Spanish.

    FIELD ORDER IS PART OF THE CONTRACT. With thinking off, strict JSON-schema decoding writes the
    fields in this order and the JSON is the model's only reasoning, so the facts (evidence, summary,
    open questions, injection, adjustments) come BEFORE the label (verdict, confidence) and the title,
    actions and escalation that depend on it. Consumers read fields by name; only generation order
    depends on this."""

    evidence: list[EvidenceRef]
    summary: str = Field(description="What happened and why, at most 3 sentences, for N2.")
    open_questions: list[str] = Field(description="What could not be resolved and a human should check.")
    injection_detected: list[InjectionFinding]
    adjustments: list[Adjustment] = Field(description="Proposed ±1 severity adjustments; code clamps.")
    mitre: list[str] = Field(description="ATT&CK technique IDs, e.g. T1566.002.")
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    title: str = Field(description="One line saying what happened, not which rule fired; consistent with the verdict.")
    recommended_actions: list[RecommendedAction]
    escalation_suggestion: EscalationSuggestion
