"""Tests for the B1 policy engine (politica_soc.md + decisions D-1..D-4)."""
import pytest

from triage import policy as p
from triage.policy import TriageFacts, evaluate

# Minimal inventory rows, shaped like data.get_asset() / data.get_user().
WEB = {"hostname": "WEB-ECOM01", "type": "Frontal web", "criticality": "Crítica", "zone": "DMZ",
       "business_service": "Tienda online y app"}
LAPTOP = {"hostname": "WS-BCN-2012", "type": "Portátil", "criticality": "Media", "zone": "HQ-USERS",
          "business_service": "Puesto de trabajo"}
SERVER_LOW = {"hostname": "PRINT01", "type": "Servidor de impresión", "criticality": "Baja", "zone": "DC-SERVERS",
              "business_service": "Impresión"}
DC = {"hostname": "DC01", "type": "Controlador de dominio", "criticality": "Crítica", "zone": "DC-SERVERS",
      "business_service": "Identidad y directorio activo"}
POS = {"hostname": "POS-T07-01", "type": "TPV", "criticality": "Alta", "zone": "STORES",
       "business_service": "Cobro en tienda (PCI DSS)"}
PLC = {"hostname": "PLC-SORT01", "type": "PLC", "criticality": "Alta", "zone": "LOGISTICS-OT",
       "business_service": "Clasificación automática de pedidos"}

USER = {"username": "teresa.quintana", "account_type": "user", "privileged": "False", "vip": "False"}
VIP = {"username": "pau.vilaseca", "account_type": "user", "privileged": "False", "vip": "True"}
ADMIN = {"username": "adm.bclotet", "account_type": "admin", "privileged": "True", "vip": "False"}


# ---------------------------------------------------------------- matrix

@pytest.mark.parametrize("rule,row", list(p.MATRIX.items()))
def test_matrix_matches_policy(rule, row):
    for crit, expected in zip(p.CRITICALITIES, row):
        asset = {"hostname": "X", "criticality": crit}
        assert evaluate(TriageFacts(rule, "true_positive", assets=[asset])).severity == expected


def test_most_critical_entity_sets_the_column():
    d = evaluate(TriageFacts("medium", "true_positive", assets=[LAPTOP, DC]))
    assert d.severity_calc["criticality"] == "Crítica"
    assert d.severity == "high"


def test_service_raises_asset_criticality():
    asset = {"hostname": "SRV", "criticality": "Baja", "business_service": "CRM y datos de clientes (RGPD"}
    assert p.asset_criticality(asset).level == "Crítica"


def test_no_inventory_defaults_to_media():
    assert evaluate(TriageFacts("high", "true_positive")).severity_calc["criticality"] == "Media"


# ---------------------------------------------------------------- D-1 identities

@pytest.mark.parametrize("user,expected", [
    (ADMIN, "Crítica"),
    ({"username": "svc_sql", "account_type": "service"}, "Crítica"),
    ({"username": "svc_backup", "account_type": "service"}, "Alta"),
    ({"username": "svc_jenkins", "account_type": "service"}, "Alta"),  # Integración continua is Alta
    ({"username": "ext.logisoft", "account_type": "external"}, "Crítica"),  # the WMS it supports is Crítica
    ({"username": "svc_print_upd", "account_type": "service"}, "Alta"),  # unknown service: prudent
    (USER, "Media"),
    (VIP, "Media"),  # VIP is handled by the +1 adjustment, not the column
])
def test_identity_criticality(user, expected):
    assert p.identity_criticality(user).level == expected


def test_service_account_takes_its_service_level_even_below_the_prudent_default(monkeypatch):
    # No service account in this dataset serves a Media or Baja service, so map one for the test.
    monkeypatch.setitem(p.SERVICE_ACCOUNT_SERVICE, "svc_print_upd", "Impresión")
    assert p.identity_criticality({"username": "svc_print_upd", "account_type": "service"}).level == "Baja"


def test_customers_are_critical():
    assert evaluate(TriageFacts("low", "true_positive", customers_involved=True)).severity == "medium"


# ---------------------------------------------------------------- D-2 VIP / privileged

def test_vip_regular_user_gets_plus_one():
    d = evaluate(TriageFacts("medium", "true_positive", assets=[LAPTOP], identities=[VIP]))
    assert d.severity_calc["matrix_result"] == "medium"
    assert [a["reason_type"] for a in d.severity_calc["adjustments_applied"]] == ["vip_privileged"]
    assert d.severity == "high"


def test_admin_privilege_not_counted_twice():
    d = evaluate(TriageFacts("medium", "true_positive", assets=[LAPTOP], identities=[ADMIN]))
    assert d.severity_calc["criticality"] == "Crítica"  # set by the admin's privilege
    assert d.severity_calc["adjustments_applied"] == []
    assert d.severity == "high"


def test_admin_on_critical_asset_gets_plus_one():
    # The column comes from the DC, not from the privilege, so the +1 applies (D-2).
    d = evaluate(TriageFacts("low", "true_positive", assets=[DC], identities=[ADMIN]))
    assert d.severity == "high"  # low x Crítica = medium, +1


def test_llm_cannot_add_vip_adjustment_itself():
    d = evaluate(TriageFacts("medium", "true_positive", assets=[LAPTOP], identities=[USER],
                             adjustments=[{"reason_type": "vip_privileged", "reason": "llm says so"}]))
    assert d.severity == "medium"


# ---------------------------------------------------------------- D-3 + organizers' example

def test_ticket_ejemplo_waf_scan_blocked_on_missing_path():
    d = evaluate(TriageFacts("low", "true_positive", assets=[WEB], target_affected=False,
                             adjustments=[{"reason_type": "blocked_no_effect", "reason": "403 del WAF"}]))
    assert d.severity_calc["criticality"] == "Baja"
    assert d.severity == "informational"
    assert d.escalation["escalate"] is False


def test_same_scan_on_existing_path_is_low():
    d = evaluate(TriageFacts("low", "true_positive", assets=[WEB],
                             adjustments=[{"reason_type": "blocked_no_effect", "reason": "403 del WAF"}]))
    assert d.severity == "low"  # Crítica -> medium, -1


# ---------------------------------------------------------------- adjustments cap

def test_adjustments_capped_at_plus_one():
    d = evaluate(TriageFacts("medium", "true_positive", assets=[LAPTOP], adjustments=[
        {"reason_type": "confirmed_execution", "reason": "proceso hijo ejecutado"},
        {"reason_type": "personal_data_payments", "reason": "datos de clientes"},
    ], personal_data_signals=["DLP: 120 coincidencias"]))
    assert d.severity_calc["net_adjustment"] == 1
    assert d.severity == "high"
    assert "limitado a +1" in d.severity_rationale


def test_plus_and_minus_cancel():
    d = evaluate(TriageFacts("high", "true_positive", assets=[LAPTOP], adjustments=[
        {"reason_type": "confirmed_execution", "reason": "x"},
        {"reason_type": "blocked_no_effect", "reason": "y"},
    ]))
    assert d.severity == "high"


def test_unknown_adjustment_ignored():
    d = evaluate(TriageFacts("medium", "true_positive", assets=[LAPTOP],
                             adjustments=[{"reason_type": "because_i_said_so", "reason": "x"}]))
    assert d.severity == "medium"
    assert d.severity_calc["adjustments_ignored"][0]["why"] == "tipo de ajuste desconocido"


def test_severity_never_out_of_range():
    d = evaluate(TriageFacts("critical", "true_positive", assets=[DC],
                             adjustments=[{"reason_type": "confirmed_execution", "reason": "x"}]))
    assert d.severity == "critical"


# ---------------------------------------------------------------- verdict rules

def test_btp_on_critical_server_is_low():
    d = evaluate(TriageFacts("critical", "benign_true_positive", assets=[DC], approved_change="CHG-2026-2107"))
    assert d.severity == "low"
    assert d.escalation["escalate"] is False


def test_btp_on_minor_alert_is_informational():
    assert evaluate(TriageFacts("low", "benign_true_positive", assets=[LAPTOP])).severity == "informational"


def test_false_positive_is_informational():
    assert evaluate(TriageFacts("high", "false_positive", assets=[DC])).severity == "informational"


def test_change_match_does_not_override_true_positive():
    d = evaluate(TriageFacts("critical", "true_positive", assets=[DC], approved_change="CHG-2026-2107"))
    assert d.severity == "critical"
    assert d.warnings and "CHG-2026-2107" in d.warnings[0]


def test_unknown_verdict_treated_as_needs_more_info():
    d = evaluate(TriageFacts("medium", "maybe", assets=[LAPTOP]))
    assert d.severity_calc["verdict"] == "needs_more_info" and d.warnings


def test_bad_rule_severity_raises():
    with pytest.raises(ValueError):
        evaluate(TriageFacts("urgent"))


# ---------------------------------------------------------------- SLA

def test_sla_critical_15_minutes():
    s = p.sla_for("critical", "2026-10-10T00:23:00Z")
    assert s["due"] == "2026-10-10T00:38:00Z"
    assert "CISO" in s["notify"]


def test_sla_local_time_handles_dst():
    # Before 25 Oct Spain is UTC+2, after it UTC+1.
    assert p.to_local("2026-10-09T16:10:00Z").hour == 18
    assert p.to_local("2026-10-28T02:08:00Z").hour == 3


def test_sla_informational_daily():
    assert p.sla_for("informational")["triage_within_minutes"] == 1440


# ---------------------------------------------------------------- escalation (§5)

def test_true_positive_high_escalates_to_n2():
    d = evaluate(TriageFacts("high", "true_positive", assets=[LAPTOP]))
    assert d.escalation["escalate"] and d.escalation["to"] == "N2"


def test_critical_escalates_by_phone():
    d = evaluate(TriageFacts("critical", "true_positive", assets=[DC], credential_theft=True))
    assert d.escalation["to"] == "N2 de guardia (teléfono)"
    assert "robo de credenciales" in d.escalation["reasons"]


def test_personal_data_notifies_dpo():
    d = evaluate(TriageFacts("medium", "true_positive", assets=[LAPTOP], personal_data_exfil=True))
    assert d.escalation["escalate"] and "DPO" in d.escalation["notify"]


def test_low_alerts_chain_escalates():
    d = evaluate(TriageFacts("low", "true_positive", assets=[LAPTOP], attack_chain=True))
    assert d.severity == "low" and d.escalation["escalate"]


def test_ot_escalates_to_operations():
    d = evaluate(TriageFacts("high", "needs_more_info", assets=[PLC]))
    assert "Responsable de Operaciones" in d.escalation["to"]


def test_ticket_fields_match_schema_shape():
    f = evaluate(TriageFacts("high", "true_positive", assets=[LAPTOP])).ticket_fields()
    assert set(f) == {"severity", "severity_rationale", "escalation"}
    assert set(f["escalation"]) == {"escalate", "to", "reason"}


# ---------------------------------------------------------------- containment (§4, D-4)

def test_purge_email_n1_but_human_clicks():
    a = p.action_policy("purge_email", "<msg@x>")
    assert a["n1_may_execute"] and not a["requires_approval"] and a["human_confirmation_required"]


def test_block_dual_use_needs_n2():
    a = p.action_policy("block_ioc", "mega.nz")
    assert a["requires_approval"] and a["approvers"] == ["N2"]


def test_block_malicious_domain_n1():
    assert not p.action_policy("block_ioc", "cdn-sync-update.example")["requires_approval"]


def test_isolate_workstation_n2():
    assert p.action_policy("isolate_host", "WS-BCN-2012", LAPTOP)["approvers"] == ["N2"]


def test_isolate_server_needs_service_owner():
    a = p.action_policy("isolate_host", "DC01", DC)
    assert a["approvers"] == ["N2", "Responsable de Sistemas"]  # owner of «Identidad y directorio activo»


def test_isolate_pos_needs_business():
    a = p.action_policy("isolate_host", "POS-T07-01", POS)
    assert a["approvers"] == ["N2", "Negocio (Director de Tiendas)"]  # owner of «Cobro en tienda (PCI DSS)»


def test_ot_action_forbidden():
    a = p.action_policy("isolate_host", "PLC-SORT01", PLC)
    assert a["allowed"] is False
    assert p.recommended_action("isolate_host", "PLC-SORT01", "x", PLC) is None


def test_disable_service_account_warns():
    a = p.action_policy("disable_user", "svc_backup", user={"username": "svc_backup", "account_type": "service"})
    assert a["approvers"] == ["N2"] and any("proceso de negocio" in n for n in a["notes"])


def test_unknown_action_rejected():
    assert p.action_policy("format_disk", "X")["allowed"] is False


def test_recommended_action_schema_shape():
    r = p.recommended_action("revoke_sessions", "yago.prieto", "sesión del atacante tras la fatiga de MFA")
    assert {"action", "target", "requires_approval", "justification"} <= set(r)
    assert r["requires_approval"] is True


# ---------------------------------------------------------------- D-5 runbook minimum

IBAN = {"reason_type": "personal_data_payments", "reason": "pago a un IBAN nuevo de LT"}


def test_runbook_minimum_raises_iban_case_to_critical():
    # Matrix: medium rule x regular user (Media) = medium, +1 payment = high; RB-01 says critical.
    d = evaluate(TriageFacts("medium", "true_positive", identities=[USER], adjustments=[IBAN],
                             personal_data_signals=["petición de pago o de cambio de IBAN"],
                             financial_fraud=True, runbook_severity="critical",
                             runbook_reason="RB-01: petición de cambio de IBAN no verificada"))
    assert d.severity_calc["after_adjustments"] == "high"
    assert d.severity == "critical"
    assert d.severity_calc["runbook_floor"]["applied"] is True
    assert "RB-01" in d.severity_rationale
    assert d.escalation["to"] == "N2 de guardia (teléfono)"
    assert d.sla["triage_within_minutes"] == 15


def test_runbook_minimum_never_lowers():
    d = evaluate(TriageFacts("critical", "true_positive", assets=[DC], runbook_severity="low",
                             runbook_reason="RB-02: bloqueado antes de ejecutar"))
    assert d.severity == "critical"
    assert d.severity_calc["runbook_floor"]["applied"] is False


def test_runbook_minimum_ignored_for_benign_and_false_positive():
    for verdict, expected in (("benign_true_positive", "low"), ("false_positive", "informational")):
        d = evaluate(TriageFacts("high", verdict, assets=[LAPTOP], runbook_severity="critical"))
        assert d.severity == expected


def test_no_runbook_minimum_keeps_matrix_result():
    d = evaluate(TriageFacts("medium", "true_positive", identities=[USER], adjustments=[IBAN],
                             personal_data_signals=["petición de pago o de cambio de IBAN"]))
    assert d.severity == "high"
    assert d.severity_calc["runbook_floor"] is None


def test_bad_runbook_severity_raises():
    with pytest.raises(ValueError):
        evaluate(TriageFacts("medium", "true_positive", runbook_severity="urgent"))


# ---------------------------------------------------------------- personal_data_payments gate

PDP = {"reason_type": "personal_data_payments", "reason": "posibles datos de clientes"}


def test_personal_data_proposal_without_signals_is_ignored():
    d = evaluate(TriageFacts("medium", "true_positive", assets=[LAPTOP], adjustments=[PDP]))
    assert d.severity_calc["net_adjustment"] == 0 and d.severity == "medium"
    ignored = d.severity_calc["adjustments_ignored"]
    assert ignored and ignored[0]["reason_type"] == "personal_data_payments" and "ningún hecho" in ignored[0]["why"]


def test_personal_data_proposal_with_signals_applies_and_cites_them():
    d = evaluate(TriageFacts("medium", "true_positive", assets=[LAPTOP], adjustments=[PDP],
                             personal_data_signals=["DLP: 58 coincidencias de datos personales"]))
    assert d.severity == "high"
    assert "DLP: 58" in d.severity_calc["adjustments_applied"][0]["reason"]


def test_signals_alone_do_not_add_the_adjustment():
    """The gate only confirms what the LLM proposes; it never adds +1 by itself."""
    d = evaluate(TriageFacts("medium", "true_positive", assets=[LAPTOP], personal_data_signals=["activo PCI"]))
    assert d.severity == "medium"


# ---------------------------------------------------------------- dual use by domain, SLA in UTC

@pytest.mark.parametrize("target,dual", [
    ("mega.nz", True), ("www.mega.nz", True), ("https://mega.co.nz/file/abc", True), ("MEGA.IO", True),
    ("AnyDesk", True), ("anydesk.com", True), ("C:/Users/x/AnyDesk.exe", True),
    ("notmega.nz", False), ("mega.nz.evil.example", False), ("omega.io", False),
    ("cdn-sync-update.example", False),
])
def test_dual_use_matches_domains_and_product_names_not_substrings(target, dual):
    assert p.is_dual_use(target) is dual
    assert p.action_policy("block_ioc", target)["requires_approval"] is dual


@pytest.mark.parametrize("created,minutes", [("2026-10-25T00:30:00Z", 15), ("2026-10-24T23:50:00Z", 15),
                                             ("2026-10-25T00:30:00Z", 30), ("2026-10-10T08:00:00Z", 240)])
def test_sla_is_exact_minutes_in_utc_even_across_the_dst_change(created, minutes):
    from datetime import datetime, timedelta
    severity = {15: "critical", 30: "high", 240: "medium"}[minutes]
    if p.SLA_TABLE[severity]["minutes"] != minutes:
        pytest.skip("SLA table changed")
    sla = p.sla_for(severity, created)
    start = datetime.fromisoformat(created.replace("Z", "+00:00"))
    due = datetime.fromisoformat(sla["due"].replace("Z", "+00:00"))
    assert due - start == timedelta(minutes=minutes)
    assert datetime.fromisoformat(sla["due_local"]) == due  # same instant, shown in Madrid time
