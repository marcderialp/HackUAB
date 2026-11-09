"""C4 helper: EvidencePack + the AI's verdict -> the facts the policy engine needs.

    facts = facts_for(pack, verdict, prompt)      # pure code, no AI call, no I/O
    decision = policy.evaluate(facts)

The AI proposes the verdict and the ±1 adjustments; everything else here comes from structured data
(the alert, the inventory, B2 context, B3 findings and signals) or from the meaning of the rule, so the
same alert always gets the same facts. Mandatory-escalation facts (politica §5) are only set for a
true_positive (or needs_more_info): a benign or false alert never escalates for them.

Mapping (the SOC policy and decisions D-1..D-6 in docs/design.md):
  rule_severity, created_at, assets, identities   alert + inventory (B3)
  verdict, adjustments                            the AI (the policy filters adjustments; personal data
                                                  only with `personal_data_signals`)
  personal_data_signals                           pack["signals"] (B3)
  approved_change                                 a change B2 says applies and the BTP cites (D-6)
  services                                        business services hit directly (AI assistant, cloud)
  customers_involved                              online-store customer accounts actually affected
  target_affected                                 False when a control blocked it and nothing got in (D-3)
  malicious_execution, credential_theft,          rule meaning + evidence + the AI's MITRE techniques
  persistence, personal_data_exfil,
  financial_fraud, attack_chain
  runbook_severity / runbook_reason               D-5: RB-01 payment/IBAN change request -> critical
"""
from __future__ import annotations

from typing import Any

from triage import policy

ESCALATING = ("true_positive", "needs_more_info")

# Rules whose detection itself is the fact, once the activity is judged real (catalogo_casos_de_uso.csv).
CREDENTIAL_RULES = {"UC-EDR-004", "UC-EDR-010", "UC-EML-003", "UC-IDP-003", "UC-IDP-004", "UC-IDP-006",
                    "UC-CLD-001"}
PERSISTENCE_RULES = {"UC-IDP-005", "UC-IDP-008", "UC-CLD-002"}
EXECUTION_RULES = {"UC-EDR-001", "UC-EDR-003", "UC-EDR-005", "UC-EDR-006", "UC-EDR-007", "UC-EDR-011",
                   "UC-EDR-012", "UC-EML-002", "UC-NET-001"}
FRAUD_RULES = {"UC-EML-004", "UC-WEB-003"}
EXFIL_RUNBOOKS = {"RB-04", "RB-06"}

# MITRE ATT&CK techniques (prefix match) that state the same facts when the AI cites them.
CREDENTIAL_TECHNIQUES = ("T1003", "T1110", "T1528", "T1539", "T1552", "T1555", "T1556", "T1557", "T1606",
                         "T1621", "T1056")
PERSISTENCE_TECHNIQUES = ("T1098", "T1136", "T1543", "T1547", "T1053", "T1137", "T1505", "T1564.008", "T1114.003")
EXECUTION_TECHNIQUES = ("T1059", "T1204", "T1218", "T1055", "T1486", "T1490", "T1496", "T1071", "T1219")
EXFIL_TECHNIQUES = ("T1020", "T1030", "T1041", "T1048", "T1052", "T1530", "T1537", "T1567")

AI_SERVICE = "Asistente de compra con IA"
STORE_SERVICE = "Tienda online y app"  # WAF/e-commerce alerts hit it; the AWS account runs its builds (empresa_tarvia.md)
STORE_SOURCES = ("WAF", "ECOM")
SECRET_WORDS = ("key", "token", "secret", "password", "credential")
CRM_SERVICE = "CRM y datos de clientes"


def _evidence(pack: dict[str, Any]) -> dict[str, Any]:
    ev = (pack.get("alert") or {}).get("evidence")
    return ev if isinstance(ev, dict) else {}


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _techniques(verdict: Any, prefixes: tuple[str, ...]) -> bool:
    return any(str(t).upper().startswith(prefixes) for t in getattr(verdict, "mitre", []) or [])


def _adjustment_types(verdict: Any) -> set[str]:
    return {a.reason_type for a in getattr(verdict, "adjustments", []) or []}


def _cited_change(verdict: Any, prompt: Any) -> str | None:
    """The applying (or possible) change the verdict cites; the first applying one otherwise."""
    text = verdict.model_dump_json().casefold() if hasattr(verdict, "model_dump_json") else ""
    for change in tuple(getattr(prompt, "authorized_changes", ())) + tuple(getattr(prompt, "possible_changes", ())):
        if change.casefold() in text:
            return change
    applying = getattr(prompt, "authorized_changes", ())
    return applying[0] if applying else None


def _nothing_got_in(ev: dict[str, Any]) -> bool:
    """D-3: the alert itself says no attempt succeeded (failed spray/stuffing, WAF block)."""
    for key in ("successes", "success_count"):
        if key in ev and _number(ev[key]) == 0:
            return True
    return str(ev.get("action", "")).casefold() in ("blocked", "block", "denied")


def _other_rules_nearby(pack: dict[str, Any]) -> bool:
    own = pack.get("rule_id")
    return any(r.get("rule_id") and r.get("rule_id") != own for r in pack.get("related_alerts") or [])


def facts_for(pack: dict[str, Any], verdict: Any, prompt: Any = None) -> policy.TriageFacts:
    """Facts for `policy.evaluate` from a B3 EvidencePack, an `LLMVerdict` (or `needs_more_info_verdict`)
    and the C2 `TriagePrompt` (for the authorizations B2 found). Never calls the AI."""
    alert = pack.get("alert") or {}
    ev = _evidence(pack)
    rule = pack.get("rule_id") or alert.get("rule_id") or ""
    runbook = pack.get("runbook") or ""
    label = getattr(verdict, "verdict", "needs_more_info")
    adjustments = [a.model_dump() if hasattr(a, "model_dump") else dict(a) for a in getattr(verdict, "adjustments", []) or []]
    adj = _adjustment_types(verdict)
    inventory = pack.get("inventory") or {}
    signals = list(((pack.get("signals") or {}).get("personal_data_payments")) or [])
    real = label in ESCALATING
    blocked = "blocked_no_effect" in adj
    customers = bool((pack.get("entities") or {}).get("customers"))

    services: list[str] = []
    if runbook == "RB-07":
        services.append(AI_SERVICE)
    if runbook == "RB-06" or str(alert.get("source_product", "")).upper() in STORE_SOURCES:
        services.append(STORE_SERVICE)
    if any("crm" in s.casefold() for s in signals) and runbook in EXFIL_RUNBOOKS:
        services.append(CRM_SERVICE)

    facts = policy.TriageFacts(
        rule_severity=pack.get("rule_severity") or alert.get("severity") or "medium",
        verdict=label,
        assets=list(inventory.get("assets") or []),
        identities=list(inventory.get("identities") or []),
        services=services,
        adjustments=adjustments,
        personal_data_signals=signals,
        approved_change=_cited_change(verdict, prompt) if label == "benign_true_positive" else None,
        created_at=alert.get("created_at"),
    )
    if not real:
        return facts

    facts.target_affected = not (blocked and _nothing_got_in(ev))
    facts.customers_involved = customers and not blocked  # a customer account or session really involved
    secrets_read = any(w in str(v).casefold() for v in ev.get("env_vars_read") or [] for w in SECRET_WORDS)
    facts.credential_theft = not blocked and (rule in CREDENTIAL_RULES or _techniques(verdict, CREDENTIAL_TECHNIQUES)
                                              or str(ev.get("credentials_submitted")).casefold() in ("true", "sí", "yes")
                                              or (_number(ev.get("successes")) or 0) > 0 or secrets_read)
    facts.persistence = not blocked and (rule in PERSISTENCE_RULES or _techniques(verdict, PERSISTENCE_TECHNIQUES))
    facts.malicious_execution = not blocked and (rule in EXECUTION_RULES or "confirmed_execution" in adj
                                                 and _techniques(verdict, EXECUTION_TECHNIQUES))
    facts.personal_data_exfil = bool(signals) and (runbook in EXFIL_RUNBOOKS or _techniques(verdict, EXFIL_TECHNIQUES))
    payment_signal = any(("iban" in s.casefold() or "pago" in s.casefold() or "cuenta" in s.casefold()) for s in signals)
    facts.financial_fraud = rule in FRAUD_RULES or (runbook == "RB-05" and payment_signal and not blocked)
    facts.attack_chain = _other_rules_nearby(pack) and not blocked
    if runbook == "RB-01" and (ev.get("new_iban_country") or ev.get("amount_mentioned")):
        facts.runbook_severity = "critical"
        facts.runbook_reason = "RB-01: petición de cambio de IBAN o de pago no verificada"
    return facts
