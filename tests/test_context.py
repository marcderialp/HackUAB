"""Tests for B2 context checks (triage/context.py) on the scenarios planted in the mock dataset
(tools/make_mock_data.py). Alerts are found through their expected answers in eval/, not by id."""
import json
from pathlib import Path

import pytest

from triage import data
from triage.context import Check, _decide, context_for, event_time

ROOT = Path(__file__).resolve().parent.parent


def labels():
    rows = []
    for name in ("golden_set.jsonl", "holdout.jsonl"):
        rows += [json.loads(line) for line in (ROOT / "eval" / name).read_text(encoding="utf-8").splitlines()]
    return rows


def planted(rule, incident):
    """Id of the alert a mock scenario planted for this rule and incident (the first by id if it labels several)."""
    ids = sorted(r["alert_id"] for r in labels() if r["rule_id"] == rule and r["incident_key"] == incident)
    assert ids, f"no labelled {rule} alert in incident {incident}"
    return ids[0]


def flags(alert_id):
    return {f["flag"]: f for f in context_for(data.get_alert(alert_id))["flags"]}


def approved(alert_id):
    return flags(alert_id)["approved_change"]["applies"]


# ---------------------------------------------------------------- pure logic (no database)

def test_decide_true_only_when_everything_checkable_passes():
    ok, no, unk = Check("x", True, ""), Check("x", False, ""), Check("x", None, "")
    assert _decide([ok], []) is True
    assert _decide([ok], [ok]) is True
    assert _decide([unk], [ok]) is True  # missing host alone doesn't block (VPN alerts)
    assert _decide([ok], [unk]) is None  # a specific condition couldn't be checked
    assert _decide([ok], [ok, no]) is False
    assert _decide([no], [unk]) is False


# ---------------------------------------------------------------- twin pairs: benign half covered, attack half not

TWINS = [  # (rule, incident of the half an approved change covers); the labels pair it with its attack twin
    ("UC-VPN-001", "benign-chg-2106"),  # vendor VPN: approved overtime vs Saturday night from a VPS
    ("UC-NET-003", "benign-chg-2102"),  # port scan: Nessus in its window vs the infected laptop
    ("UC-DLP-002", "benign-chg-2109"),  # personal data by mail: payroll to the advisor vs a personal address
    ("UC-IDP-008", "benign-chg-2107"),  # privileged group: Backup Operators from JUMP01 vs Domain Admins at night
    ("UC-WEB-001", "benign-chg-2101"),  # WAF: pentest vs internet scan
    ("UC-OT-001", "benign-chg-2104"),  # OT: firmware maintenance from ENG-WS01 vs a warehouse laptop
    ("UC-EDR-002", "noise-sccm-inventario"),  # encoded PowerShell: SCCM inventory vs the invoice loader
]


@pytest.mark.db
@pytest.mark.parametrize("rule,incident", TWINS)
def test_twin_pairs(rule, incident):
    pairs = [(r["alert_id"], r["twin_of"]) for r in labels()
             if r["rule_id"] == rule and r["incident_key"] == incident and r["twin_of"]]
    assert pairs, f"no labelled twin for {rule} in {incident}"
    benign, attack = pairs[0]
    assert approved(benign) is True
    assert approved(attack) is False


@pytest.mark.db
def test_sccm_inventory_covered_inside_its_daily_window():
    c = context_for(data.get_alert(planted("UC-EDR-002", "noise-sccm-inventario")))
    sccm = next(ch for ch in c["changes"] if ch["change_id"] == "CHG-2026-2103")
    assert sccm["applies"] is True
    assert any(k["condition"].startswith("franja diaria") and k["ok"] for k in sccm["checks"])


@pytest.mark.db
def test_free_text_scope_changes_do_not_cover_everything():
    # find_changes() returns the changes scoped in free text ("Todos los puestos", "Servidores Windows", "Correo") for
    # any host; for the PsExec move from the infected laptop to FS01 none of them applies (nor the pentest's).
    c = context_for(data.get_alert(planted("UC-NET-004", "paperkite-finanzas")))
    assert {ch["change_id"]: ch["applies"] for ch in c["changes"]} == {
        "CHG-2026-2101": False, "CHG-2026-2103": False, "CHG-2026-2105": False, "CHG-2026-2109": False}


@pytest.mark.db
def test_payroll_flow_never_whitelists_phishing():
    # Regression: an email alert without a recipient used to match the approved payroll flow (CHG-2026-2109).
    assert approved(planted("UC-EML-003", "phishing-buzon-marketing")) is False  # phishing click
    assert approved(planted("UC-EML-004", "bec-suministros")) is not True  # IBAN fraud: no recipient in the alert


@pytest.mark.db
def test_no_golden_attack_is_marked_as_covered():
    path = ROOT / "eval" / "golden_set.jsonl"
    if not path.exists():
        pytest.skip("golden set not on this branch")
    for line in path.read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        if r["expected_verdict"] == "true_positive":
            assert approved(r["alert_id"]) is not True, r["alert_id"]


# ---------------------------------------------------------------- internal rules

@pytest.mark.db
def test_adm_accounts_outside_jump01():
    assert flags(planted("UC-IDP-008", "adm-domain-admins-sabado"))["adm_outside_jump01"]["applies"] is True  # laptop
    assert flags(planted("UC-IDP-008", "benign-chg-2107"))["adm_outside_jump01"]["applies"] is False  # from JUMP01


@pytest.mark.db
def test_vendor_window_and_source():
    attack = flags(planted("UC-VPN-001", "logisoft-sabado-noche"))
    assert attack["vendor_outside_window"]["applies"] is True  # Saturday 23:40
    assert attack["vendor_unusual_source"]["applies"] is True  # a VPS abroad
    benign = flags(planted("UC-VPN-001", "benign-chg-2106"))
    assert benign["vendor_unusual_source"]["applies"] is False  # usual IP
    assert benign["vendor_outside_window"]["applies"] is True  # Tuesday 18:20...
    assert benign["approved_change"]["applies"] is True  # ...but inside CHG-2026-2106


@pytest.mark.db
def test_ot_sources():
    maint = flags(planted("UC-OT-001", "benign-chg-2104"))
    assert maint["ot_unauthorized_source"]["applies"] is False  # ENG-WS01 is authorized
    assert maint["approved_change"]["applies"] is True  # and inside CHG-2026-2104
    laptop = flags(planted("UC-OT-001", "ot-modbus-desde-portatil"))
    assert laptop["ot_unauthorized_source"]["applies"] is True  # a warehouse laptop is not
    assert laptop["approved_change"]["applies"] is False


@pytest.mark.db
def test_hr_events():
    assert flags(planted("UC-IDP-001", "benign-viaje-cfo"))["hr_travel"]["applies"] is True  # CFO in Mexico 13-16/10
    assert flags(planted("UC-DLP-001", "insider-compras"))["hr_leaving"]["applies"] is True  # last day 23/10


@pytest.mark.db
def test_remote_tool_and_mfa_exempt():
    assert flags(planted("UC-EDR-005", "anydesk-tienda-t05"))["unapproved_remote_tool"]["applies"] is True  # AnyDesk
    assert flags(planted("UC-IDP-008", "benign-chg-2107"))["mfa_exempt_account"]["applies"] is True  # svc_backup


# ---------------------------------------------------------------- timing and robustness

@pytest.mark.db
def test_event_time_uses_activity_not_alert_creation():
    alert = data.get_alert(planted("UC-EML-003", "phishing-buzon-marketing"))  # created 09:31 local, phish at 08:47
    assert event_time(alert) < alert["created_at"]


@pytest.mark.db
def test_runs_on_the_whole_dev_sample():
    path = ROOT / "03_alertas" / "alertas_muestra_desarrollo.jsonl"
    for line in path.read_text(encoding="utf-8").splitlines():
        c = context_for(json.loads(line))
        assert c["flags"][0]["flag"] == "approved_change"


# ---------------------------------------------------------------- approved_change must match the change's purpose

def moved(alert_id, created_at, **evidence):
    """A mock alert moved into another moment (and optionally with changed evidence): the review's repro."""
    import copy
    alert = copy.deepcopy(data.get_alert(alert_id))
    alert["created_at"] = created_at
    alert["related_events"] = []  # so the event time is the new created_at
    alert["evidence"].update(evidence)
    return alert


def change_check(alert, change_id, condition):
    change = next(c for c in context_for(alert)["changes"] if c["change_id"] == change_id)
    return next(k for k in change["checks"] if k["condition"].startswith(condition))


@pytest.mark.db
def test_attack_inside_a_change_window_is_not_covered():
    # The loader's encoded PowerShell moved into the daily window of the SCCM inventory change (CHG-2026-2103): same
    # rule and scope (a laptop), but it runs as the user, not svc_sccm, and its chain loads an unsigned DLL.
    unsigned = data.get_alert(planted("UC-EDR-001", "paperkite-finanzas"))["evidence"]["signer"]
    alert = moved(planted("UC-EDR-002", "paperkite-finanzas"), "2026-10-13T08:30:00Z", signer=unsigned)
    assert context_for(alert)["flags"][0]["applies"] is False
    assert change_check(alert, "CHG-2026-2103", "franja diaria")["ok"] is True
    assert change_check(alert, "CHG-2026-2103", "cuenta svc_sccm")["ok"] is False
    assert change_check(alert, "CHG-2026-2103", "sin procesos sin firmar")["ok"] is False
    # PsExec from that laptop to FS01 falls inside the PsExec change (CHG-2026-2105), but the alert says there is none.
    lateral = data.get_alert(planted("UC-NET-004", "paperkite-finanzas"))
    assert context_for(lateral)["flags"][0]["applies"] is False
    assert change_check(lateral, "CHG-2026-2105", "la alerta indica que no hay cambio")["ok"] is False


@pytest.mark.db
def test_change_for_one_group_does_not_cover_another():
    # Domain Admins addition moved into CHG-2026-2107, which is about Backup Operators.
    alert = moved(planted("UC-IDP-008", "adm-domain-admins-sabado"), "2026-10-15T08:30:00Z")
    assert context_for(alert)["flags"][0]["applies"] is False
    assert change_check(alert, "CHG-2026-2107", "grupo")["ok"] is False


@pytest.mark.db
def test_change_purpose_must_match_the_rule():
    # CHG-2026-2105 is about PsExec from JUMP01 with adm.* accounts on Windows servers. The Backup Operators addition,
    # moved to the day after its own change, fits that window, scope, source and account, but it is not PsExec.
    alert = moved(planted("UC-IDP-008", "benign-chg-2107"), "2026-10-16T08:30:00Z")
    assert change_check(alert, "CHG-2026-2105", "propósito del cambio")["ok"] is False
    assert all(change_check(alert, "CHG-2026-2105", c)["ok"] for c in ("alcance", "desde JUMP01", "cuenta adm"))
    assert context_for(alert)["flags"][0]["applies"] is False


@pytest.mark.db
def test_approved_destination_counts_only_as_recipient():
    # The payroll flow's approved recipient (CHG-2026-2109) as the SENDER does not make an alert that flow.
    advisor = data.get_alert(planted("UC-DLP-002", "benign-chg-2109"))["evidence"]["recipient"]
    fraud = planted("UC-EML-004", "bec-suministros")  # the IBAN fraud, sent from the advisor's address
    alert = moved(fraud, data.get_alert(fraud)["created_at"], sender=advisor)
    assert context_for(alert)["flags"][0]["applies"] is False
    leak = planted("UC-DLP-002", "insider-compras")  # personal data mailed to a personal address
    alert = moved(leak, data.get_alert(leak)["created_at"], sender=advisor)
    assert change_check(alert, "CHG-2026-2109", "propósito del cambio")["ok"] is True
    assert change_check(alert, "CHG-2026-2109", "destinatario")["ok"] is False
    assert context_for(alert)["flags"][0]["applies"] is False


@pytest.mark.db
def test_alert_citing_another_change_is_not_covered():
    maint = planted("UC-OT-001", "benign-chg-2104")
    alert = moved(maint, data.get_alert(maint)["created_at"], maintenance_window="CHG-2026-9999")
    assert change_check(alert, "CHG-2026-2104", "la alerta cita")["ok"] is False
    assert context_for(alert)["flags"][0]["applies"] is False


def test_unknown_change_purpose_is_only_possible():
    from triage.context import _purpose_checks
    change = {"id": "CHG-X", "titulo": "Reorganización de oficinas", "detalle": "", "alcance": "Barcelona HQ"}
    check = _purpose_checks(change, {"rule_id": "UC-EDR-011", "evidence": {}})[0]
    assert check.condition == "propósito del cambio" and check.ok is None


@pytest.mark.db
def test_routine_change_is_marked_and_risky_ones_are_not():
    """D-6: the management-PowerShell (inventory) change documents routine work; a pentest change doesn't."""
    def changes(alert_id):
        return {c["change_id"]: c for c in context_for(data.get_alert(alert_id))["changes"]}

    sccm = changes(planted("UC-EDR-002", "noise-sccm-inventario"))
    assert sccm["CHG-2026-2103"]["applies"] is True and sccm["CHG-2026-2103"]["routine"] is True
    pentest = changes(planted("UC-WEB-001", "benign-chg-2101"))
    assert pentest["CHG-2026-2101"]["applies"] is True and pentest["CHG-2026-2101"]["routine"] is False
