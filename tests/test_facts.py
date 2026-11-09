"""C4 helper: facts_for(pack, verdict, prompt) -> TriageFacts for the policy engine."""
import copy
import json
import re
from pathlib import Path

import pytest

from triage import data, llm, policy
from triage.collectors import collect
from triage.facts import facts_for
from triage.prompts.builder import build_prompt
from triage.schemas import LLMVerdict

ROOT = Path(__file__).resolve().parent.parent
MALWARE = "ALR-20261013-700003"  # s01: the PaperKite loader runs on a Finance laptop (UC-EDR-001)
RECON = "ALR-20261013-700005"  # s01: domain recon from the implant (UC-EDR-008: no credential/persistence rule)
SCAN = "ALR-20261014-700264"  # s19: the weekly Nessus scan, inside CHG-2026-2102 (UC-NET-003)
CAMPAIGN = "ALR-20261012-700230"  # s15: public campaign bucket; B2 calls CHG-2026-2108 possible, RB-06.5 confirms it
FAILED_SPRAY = "ALR-20261017-700070"  # s07 twin: smart lockout stopped every attempt of the spray (successes 0)

# Built here: the dataset's own cases (s04 IBAN request, s12 and s17 personal data) are holdout alerts, which tests
# never name.
IBAN_REQUEST = {
    "alert_id": "ALR-TEST-IBAN", "created_at": "2026-10-14T09:20:00.000Z", "source_product": "EMAIL_GW",
    "rule_id": "UC-EML-004", "rule_name": "Petición de cambio de cuenta bancaria por correo", "severity": "high",
    "status": "new", "runbook": "RB-01", "entities": {"users": [{"upn": "carla.bartra@tarvia.example"}]},
    "evidence": {"keywords": ["IBAN", "cambio de cuenta"], "amount_mentioned": "9.800,00 €",
                 "new_iban_country": "PT"},
    "related_events": [],
}
PERSONAL_DATA_MAIL = {
    "alert_id": "ALR-TEST-DLP", "created_at": "2026-10-14T10:30:00.000Z", "source_product": "DLP",
    "rule_id": "UC-DLP-002", "rule_name": "Datos personales enviados a un correo externo", "severity": "high",
    "status": "new", "runbook": "RB-04", "entities": {"users": [{"upn": "teresa.quintana@tarvia.example"}]},
    "evidence": {"recipient": "agencia@marketing-externo.example", "matches": {"correos": 58, "telefonos": 41},
                 "dlp_action": "audit"},
    "related_events": [],
}


def verdict(label, adjustments=(), mitre=(), summary="resumen"):
    return LLMVerdict.model_validate({
        "evidence": [], "summary": summary, "open_questions": [], "injection_detected": [],
        "adjustments": [{"delta": -1 if a == "blocked_no_effect" else 1, "reason_type": a, "reason": "x"}
                        for a in adjustments],
        "mitre": list(mitre), "verdict": label, "confidence": 0.9, "title": "t", "recommended_actions": [],
        "escalation_suggestion": {"escalate": False, "to": "", "reason": ""}})


def facts(alert, label, adjustments=(), mitre=(), summary="resumen"):
    """`alert`: a dataset alert id, or an alert dict built in the test."""
    pack = collect(data.get_alert(alert) if isinstance(alert, str) else copy.deepcopy(alert))
    return facts_for(pack, verdict(label, adjustments, mitre, summary), build_prompt(pack))


# ---------------------------------------------------------------- agreement with the golden-set labels (dev only)

# The adjustments each labelled attack implies, by incident_key: the AI's part of the input, which the labels
# don't carry. A blocked attempt implies blocked_no_effect; benign and false-positive labels imply none.
IMPLIED_ADJUSTMENTS = {
    "paperkite-finanzas": ["confirmed_execution"],
    "phishing-buzon-marketing": [],
    "spray-atencion-cliente": ["confirmed_execution"],
    "spray-fallido-sabado": ["blocked_no_effect"],
    "logisoft-sabado-noche": ["confirmed_execution"],
    "adm-domain-admins-sabado": ["confirmed_execution"],
    "insider-compras": ["confirmed_execution", "personal_data_payments"],
    "noise-escaneos-internet": ["blocked_no_effect"],
    "ato-tienda-online": ["confirmed_execution", "personal_data_payments"],
    "stuffing-fallido-lunes": ["blocked_no_effect"],
    "bucket-exportaciones-publico": ["personal_data_payments"],
    "supply-chain-npm-aws": ["confirmed_execution"],
    "mfa-fatigue-atencion-cliente": ["confirmed_execution"],
    "tunel-dns-logistica": ["confirmed_execution"],
}


def test_dev_golden_severity_and_escalation_agree():
    """Golden verdict + the adjustments its scenario implies in -> the labelled severity and escalation out.
    A benign true positive cites the change its label's notes name."""
    rows = [json.loads(line) for line in open(ROOT / "eval" / "golden_set.jsonl", encoding="utf-8")]
    misses = []
    for r in rows:
        # A new attack scenario must say here which adjustments it implies (KeyError otherwise).
        adj = IMPLIED_ADJUSTMENTS[r["incident_key"]] if r["expected_verdict"] == "true_positive" else []
        summary = " ".join(re.findall(r"CHG-\d{4}-\d{4}", r["notes"])) or "resumen"
        d = policy.evaluate(facts(r["alert_id"], r["expected_verdict"], adj, summary=summary))
        if (d.severity, d.escalation["escalate"]) != (r["expected_severity"], r["expected_escalate"]):
            misses.append((r["alert_id"], d.severity, d.escalation["escalate"]))
    assert rows and not misses, misses


# ---------------------------------------------------------------- the rules

def test_benign_verdicts_never_carry_escalation_facts():
    for label in ("false_positive", "benign_true_positive"):
        f = facts(MALWARE, label, ["confirmed_execution"], ["T1059.001", "T1547.001"])
        assert not any([f.malicious_execution, f.credential_theft, f.persistence, f.personal_data_exfil,
                        f.financial_fraud, f.attack_chain])


def test_btp_takes_the_change_it_cites():
    f = facts(SCAN, "benign_true_positive", summary="Escaneo autorizado por CHG-2026-2102.")
    assert f.approved_change == "CHG-2026-2102"
    assert policy.evaluate(f).severity == "low"
    # The campaign bucket: B2 can only call CHG-2026-2108 possible, but RB-06.5 confirms the deploy came from the
    # known pipeline, so a BTP that cites nothing still takes that code authorization (a CloudTrail event id).
    cited = facts(CAMPAIGN, "benign_true_positive", summary="Web de campaña publicada según CHG-2026-2108.")
    assert cited.approved_change == "CHG-2026-2108"
    assert str(facts(CAMPAIGN, "benign_true_positive").approved_change).startswith("CT-")
    # Without that finding, a change B2 could not confirm (applies: null) is taken only when the verdict cites it.
    pack = collect(data.get_alert(CAMPAIGN))
    pack["findings"] = [f for f in pack["findings"] if not f["check"].startswith("RB-06.5")]
    prompt = build_prompt(pack)
    assert prompt.authorized_changes == () and prompt.possible_changes == ("CHG-2026-2108",)
    assert facts_for(pack, verdict("benign_true_positive"), prompt).approved_change is None
    assert facts_for(pack, verdict("benign_true_positive", summary="Según CHG-2026-2108."),
                     prompt).approved_change == "CHG-2026-2108"


def test_iban_change_request_sets_the_runbook_minimum():
    f = facts(IBAN_REQUEST, "true_positive", ["personal_data_payments"])
    assert f.runbook_severity == "critical" and f.financial_fraud
    assert policy.evaluate(f).severity == "critical"
    # Without the +1 the matrix stops at high (high rule x regular user); the runbook minimum makes it critical.
    d = policy.evaluate(facts(IBAN_REQUEST, "true_positive"))
    assert d.severity == "critical" and d.severity_calc["runbook_floor"]["applied"]


def test_blocked_attempt_without_success_does_not_affect_the_target():
    f = facts(FAILED_SPRAY, "true_positive", ["blocked_no_effect"])
    assert f.target_affected is False and not f.credential_theft
    d = policy.evaluate(f)
    assert d.severity_calc["criticality"] == "Baja"  # D-3: the target counts as Baja
    assert d.severity == "informational"  # medium rule x Baja = low, -1 blocked_no_effect


def test_personal_data_signals_reach_the_policy():
    f = facts(PERSONAL_DATA_MAIL, "true_positive", ["personal_data_payments"])
    assert f.personal_data_signals and f.personal_data_exfil
    assert policy.evaluate(f).severity_calc["adjustments_applied"]


def test_mitre_from_the_ai_adds_facts_for_a_true_positive():
    before = facts(RECON, "true_positive")
    assert not (before.persistence or before.credential_theft)  # the rule alone states neither
    f = facts(RECON, "true_positive", mitre=["T1547.001", "T1003.001"])
    assert f.persistence and f.credential_theft


def test_failed_ai_call_still_gives_policy_facts():
    pack = collect(data.get_alert(MALWARE))
    meta = llm.CallMeta(tag="", model="ornith", served_model=None, effort="low", prompt_version="c2-v2",
                        cache_key="k", disk_cache_hit=False, status="error", error_kind="timeout")
    nmi = llm.needs_more_info_verdict(llm.LLMResult("error", None, None, meta))
    d = policy.evaluate(facts_for(pack, nmi, build_prompt(pack)))
    assert d.severity_calc["verdict"] == "needs_more_info"
    assert d.escalation["escalate"]  # serious alert without an automatic verdict -> a human, now


@pytest.mark.parametrize("prompt", [None])
def test_works_without_a_prompt(prompt):
    pack = collect(data.get_alert(SCAN))
    f = facts_for(pack, verdict("benign_true_positive"), prompt)
    assert f.approved_change is None and f.verdict == "benign_true_positive"
