"""Check the fast SOC API on its own.

Its read endpoints keep the organizers' mock API contract: the same paths, status codes and response
shapes, serving the dataset as the files hold it. So the expected answers here are read straight from the
dataset files. Then come our extra endpoints and the containment gate.
"""
import csv
import json
import os

import pytest
from fastapi.testclient import TestClient

from triage.loader import LOG_SOURCES, ROOT

pytestmark = pytest.mark.db

FIELDS_WE_ADD = {
    "/assets": {"services"},
    "/changes": {"inicio_utc", "fin_utc", "scope_hosts", "scope_text", "scope_match"},
}
# Where the API logs containment unless SOC_CONTAINMENT_LOG says otherwise. Tests must never write there.
DEFAULT_LOG = ROOT / "out" / "containment_log.jsonl"
DEFAULT_LOG_BEFORE = DEFAULT_LOG.read_bytes() if DEFAULT_LOG.exists() else None


def read_jsonl(relative):
    with open(ROOT / relative, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def read_csv(relative):
    """Rows with every cell as text and empty cells as '', which is how the API returns them."""
    with open(ROOT / relative, encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def log_rows(source):
    path = f"04_logs/{source}.jsonl"
    return read_jsonl(path) if (ROOT / path).exists() else read_csv(f"04_logs/{source}.csv")


ALERTS = read_jsonl("03_alertas/alertas.jsonl")
ASSETS = read_csv("02_inventario/activos.csv")
VULNERABILITIES = read_csv("02_inventario/vulnerabilidades.csv")
USERS = read_csv("02_inventario/usuarios.csv")
HR_EVENTS = read_csv("02_inventario/eventos_rrhh.csv")
CHANGES = read_csv("02_inventario/calendario_cambios.csv")
TIP = {row["value"]: row for row in read_jsonl("05_inteligencia/ti_feed.jsonl")}
GEOIP = {row["ip"]: row for row in read_csv("05_inteligencia/geoip_asn.csv")}
SANDBOX = read_jsonl("05_inteligencia/sandbox_informes.jsonl")


@pytest.fixture(scope="module")
def log_path(tmp_path_factory):
    path = tmp_path_factory.mktemp("containment") / "log.jsonl"
    os.environ["SOC_CONTAINMENT_LOG"] = str(path)
    return path


@pytest.fixture(scope="module")
def fast(log_path):
    from api import soc_api

    soc_api.LOGFILE = log_path
    return TestClient(soc_api.app)


# The read contract
def expected_queue(status="new", desde="", hasta="", rule_id="", limit=50, offset=0):
    """The alert queue: file order, with `desde` and `hasta` compared with created_at as text."""
    rows = [a for a in ALERTS if a["status"] == status and (not rule_id or a["rule_id"] == rule_id)
            and (not desde or a["created_at"] >= desde) and (not hasta or a["created_at"] <= hasta)]
    return {"total": len(rows), "items": rows[offset:offset + limit]}


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 5}, {"limit": 5, "offset": 100}, {"rule_id": "UC-NET-003", "limit": 20},
        {"desde": "2026-10-13", "hasta": "2026-10-14", "limit": 20}, {"status": "closed"},
    ],
)
def test_alert_queue_is_the_alert_file_in_order(fast, params):
    expected = expected_queue(**params)
    assert expected["items"] or params == {"status": "closed"}
    response = fast.get("/alerts", params=params)
    assert response.status_code == 200 and response.json() == expected


def test_alert_by_id(fast):
    for alert in (ALERTS[0], ALERTS[-1]):
        assert fast.get(f"/alerts/{alert['alert_id']}").json() == alert
    missing = fast.get("/alerts/NOPE")
    assert missing.status_code == 404 and missing.json() == {"detail": "Not Found"}


@pytest.mark.parametrize(
    "key, username, hr_events",
    [
        ("oriol.masdeu", "oriol.masdeu", 0),
        ("oriol.masdeu@tarvia.example", "oriol.masdeu", 0),
        ("TARVIA%5Coriol.masdeu", "oriol.masdeu", 0),  # accepted by our API only
        ("didac.ubach", "didac.ubach", 1),
    ],
)
def test_user_is_the_directory_row_with_its_hr_events(fast, key, username, hr_events):
    row = next(u for u in USERS if u["username"] == username)
    expected = {**row, "hr_events": [e for e in HR_EVENTS if e["usuario"] == row["upn"]]}
    assert len(expected["hr_events"]) == hr_events
    response = fast.get(f"/users/{key}")
    assert response.status_code == 200 and response.json() == expected


def test_unknown_user_is_a_404(fast):
    response = fast.get("/users/nadie")
    assert response.status_code == 404 and response.json() == {"detail": "Not Found"}


@pytest.mark.parametrize(
    "indicator, in_tip, in_geoip",
    [
        ("203.0.113.45", True, True),  # the C2 server
        ("198.19.10.1", False, True),  # the Barcelona office's Internet address
        ("cdn-sync-update.example", True, False),
        ("unknown.example", False, False),
    ],
)
def test_intel_combines_the_tip_and_geoip(fast, indicator, in_tip, in_geoip):
    assert (indicator in TIP, indicator in GEOIP) == (in_tip, in_geoip)
    response = fast.get(f"/intel/{indicator}")
    assert response.status_code == 200
    assert response.json() == {"indicator": indicator, "tip": TIP.get(indicator), "geo": GEOIP.get(indicator)}


def test_every_sandbox_report_is_served_as_is(fast):
    assert SANDBOX
    for report in SANDBOX:
        assert fast.get(f"/sandbox/{report['sha256']}").json() == report
    missing = fast.get("/sandbox/" + "0" * 64)
    assert missing.status_code == 404 and "sandbox" in missing.json()["detail"]


def expected_asset(hostname):
    row = next(a for a in ASSETS if a["hostname"] == hostname)
    return {**row, "vulnerabilities": [v for v in VULNERABILITIES if v["hostname"] == hostname]}


def without_our_fields(body, endpoint):
    return {k: v for k, v in body.items() if k not in FIELDS_WE_ADD[endpoint]}


@pytest.mark.parametrize(
    "key, hostname, vulnerabilities",
    [("JUMP01", "JUMP01", 0), ("jump01", "JUMP01", 0), ("WEB-ECOM02", "WEB-ECOM02", 1), ("POS-T07-01", "POS-T07-01", 0)],
)
def test_asset_is_the_cmdb_row_with_its_vulnerabilities(fast, key, hostname, vulnerabilities):
    expected = expected_asset(hostname)
    assert len(expected["vulnerabilities"]) == vulnerabilities
    response = fast.get(f"/assets/{key}")
    assert response.status_code == 200
    assert without_our_fields(response.json(), "/assets") == expected
    assert FIELDS_WE_ADD["/assets"] <= set(response.json())


def test_asset_by_ip(fast):
    expected = expected_asset("JUMP01")
    assert without_our_fields(fast.get(f"/assets/{expected['ip']}").json(), "/assets") == expected


def test_unknown_asset_is_a_404(fast):
    response = fast.get("/assets/none")
    assert response.status_code == 404 and "CMDB" in response.json()["detail"]


@pytest.mark.parametrize(
    "q, ids",
    [("", None), ("pentest", ["CHG-2026-2101"]), ("JUMP01", ["CHG-2026-2105", "CHG-2026-2107"]), ("nothing-here", [])],
)
def test_changes_are_the_calendar_rows_in_any_order(fast, q, ids):
    response = fast.get("/changes", params={"q": q} if q else None)
    assert response.status_code == 200
    by_id = lambda row: row["id"]
    ours = sorted((without_our_fields(c, "/changes") for c in response.json()), key=by_id)
    assert ours == [c for c in sorted(CHANGES, key=by_id) if ids is None or c["id"] in ids]
    assert all(FIELDS_WE_ADD["/changes"] <= set(c) for c in response.json())


@pytest.mark.parametrize("source", sorted(LOG_SOURCES))
def test_logs_are_the_source_file_in_order(fast, source):
    rows = log_rows(source)
    assert len(rows) == LOG_SOURCES[source]
    start, end = "2026-10-13T00:00:00.000Z", "2026-10-14T00:00:00.000Z"
    queries = [
        ({}, lambda row: True),
        ({"q": "Tarvia"}, lambda row: "tarvia" in json.dumps(row, ensure_ascii=False).lower()),
        ({"desde": start, "hasta": end}, lambda row: start <= row["timestamp"] <= end),
    ]
    for params, keep in queries:
        expected = [row for row in rows if keep(row)][:25]
        response = fast.get(f"/logs/{source}", params={**params, "limit": 25})
        assert response.status_code == 200, params
        assert response.json() == {"count": len(expected), "truncated": len(expected) == 25, "items": expected}, params


def test_logs_errors(fast):
    unknown = fast.get("/logs/not_a_source")
    assert unknown.status_code == 404 and unknown.json() == {"detail": "fuente desconocida: not_a_source"}
    assert fast.get("/logs/dns?limit=5000").status_code == 422


def test_bad_timestamp_is_a_400_not_a_crash(fast):
    assert fast.get("/logs/dns?desde=yesterday").status_code == 400


# Our extra endpoints
def test_timeline_refuses_an_entity_it_cant_type(fast):
    assert fast.get("/entities/no-existe/timeline").status_code == 400
    assert fast.get("/entities/no-existe/timeline?entity_type=user").json()["total"] == 0
    assert fast.get("/entities/dnsbl-ejemplo.example/timeline?limit=1").json()["total"] > 0


def test_new_endpoints(fast):
    timeline = fast.get("/entities/TARVIA%5Coriol.masdeu/timeline?entity_type=user&sources=edr_events&limit=3").json()
    assert timeline["count"] == 3 and timeline["truncated"]
    assert fast.get("/entities/x/timeline?entity_type=user&sources=nope").status_code == 400
    assert fast.get("/events/WAF-7000123").json()["source"] == "waf"
    assert fast.get("/events/NOPE").status_code == 404
    assert fast.get("/mentions?text=cdn-sync-update.example&limit=1").json()["total"] > 1
    assert fast.get("/resolve/ip/10.40.16.5").json()["zone"]["zona"] == "LOGISTICS-OT"
    assert "ws-bcn-2005" in [h["value"] for h in fast.get("/users/oriol.masdeu/hosts").json()]
    assert "oriol.masdeu" in [u["value"] for u in fast.get("/assets/WS-BCN-2005/users").json()]


# Containment
BODY = {"target": "WS-BCN-2005", "justification": "prueba", "ticket_id": "TKT-1"}


def approve(client, action, target, ticket_id="TKT-1"):
    response = client.post("/approvals", json={"action": action, "target": target, "approver": "Analista", "ticket_id": ticket_id})
    assert response.status_code == 200
    return response.json()["approval_token"]


def test_containment_needs_a_token_for_this_action_and_target(fast):
    assert fast.post("/containment/isolate_host", json=BODY).status_code == 403
    wrong_action = approve(fast, "disable_user", "WS-BCN-2005")
    assert fast.post("/containment/isolate_host", json={**BODY, "approval_token": wrong_action}).status_code == 403
    wrong_target = approve(fast, "isolate_host", "WS-BCN-0001")
    assert fast.post("/containment/isolate_host", json={**BODY, "approval_token": wrong_target}).status_code == 403


def test_containment_with_valid_token_is_logged(fast, log_path):
    token = approve(fast, "isolate_host", "WS-BCN-2005")
    response = fast.post("/containment/isolate_host", json={**BODY, "approval_token": token})
    assert response.status_code == 200 and response.json()["result"] == "ok (simulado)"
    logged = fast.get("/containment/log").json()
    assert logged[-1]["action"] == "isolate_host" and logged[-1]["target"] == "WS-BCN-2005"
    assert "approval_token" not in response.json()
    assert token not in log_path.read_text(encoding="utf-8")


@pytest.mark.parametrize("action", ["block_ioc", "purge_email"])
def test_n1_actions_also_need_a_token(fast, action):
    body = {**BODY, "target": "bad.example"}
    assert fast.post(f"/containment/{action}", json=body).status_code == 403
    token = approve(fast, action, "bad.example")
    assert fast.post(f"/containment/{action}", json={**body, "approval_token": token}).status_code == 200


def test_dual_use_service_cannot_be_blocked_without_a_token(fast):
    assert fast.post("/containment/block_ioc", json={**BODY, "target": "mega.nz"}).status_code == 403


def test_unknown_and_workflow_actions_are_refused(fast):
    for action in ("format_disk", "close"):
        assert fast.post(f"/containment/{action}", json=BODY).status_code == 400


def test_token_works_only_once(fast):
    token = approve(fast, "isolate_host", "WS-BCN-2005")
    body = {**BODY, "approval_token": token}
    assert fast.post("/containment/isolate_host", json=body).status_code == 200
    assert fast.post("/containment/isolate_host", json=body).status_code == 403


def test_token_works_only_for_its_ticket(fast):
    token = approve(fast, "isolate_host", "WS-BCN-2005", ticket_id="TKT-OTHER")
    body = {**BODY, "approval_token": token}
    assert fast.post("/containment/isolate_host", json=body).status_code == 403
    assert fast.post("/containment/isolate_host", json={**body, "ticket_id": ""}).status_code == 403


def test_refused_attempt_does_not_spend_the_token(fast):
    token = approve(fast, "isolate_host", "WS-BCN-2005")
    body = {**BODY, "approval_token": token}
    assert fast.post("/containment/isolate_host", json={**body, "ticket_id": "TKT-OTHER"}).status_code == 403
    assert fast.post("/containment/isolate_host", json=body).status_code == 200


def test_expired_token_is_refused(fast, monkeypatch):
    from api import soc_api

    monkeypatch.setattr(soc_api, "TOKEN_TTL_SECONDS", -1)
    token = approve(fast, "isolate_host", "WS-BCN-2005")
    assert fast.post("/containment/isolate_host", json={**BODY, "approval_token": token}).status_code == 403


def test_approval_must_name_a_ticket(fast):
    base = {"action": "isolate_host", "target": "WS-BCN-2005", "approver": "Analista"}
    assert fast.post("/approvals", json=base).status_code == 422
    assert fast.post("/approvals", json={**base, "ticket_id": ""}).status_code == 422


def test_failed_safety_lookup_blocks_the_action(fast, monkeypatch):
    from api import soc_api

    def broken(_):
        raise RuntimeError("lookup failed")

    monkeypatch.setattr(soc_api.data, "get_asset", broken)
    assert fast.post("/containment/isolate_host", json=BODY).status_code == 503


@pytest.mark.parametrize("target", ["PLC-SORT01", "plc-sort01"])
def test_ot_hosts_cannot_be_isolated_even_with_approval(fast, target):
    token = approve(fast, "isolate_host", target)
    response = fast.post("/containment/isolate_host", json={**BODY, "target": target, "approval_token": token})
    assert response.status_code == 403 and "OT" in response.json()["detail"]


# PLC-SORT01..03 are 10.40.17.11-13; the whole LOGISTICS-OT zone is 10.40.16.0/20.
OT_TARGETS = [
    "PLC-SORT01..03", "PLC-SORT01..PLC-SORT03", "plc-sort02..03", "PLC-SORT01-03", "PLC-*", "HMI-SORT01",
    "10.40.17.11", "10.40.17.11-13", "10.40.17.0/24", "10.40.16.5", "10.40.0.0/16", "http://10.40.17.11/admin",
    "WS-BCN-2005, PLC-SORT02", "PLC-SORT00..99999",
]


@pytest.mark.parametrize("action", ["isolate_host", "block_ioc", "disable_user"])
@pytest.mark.parametrize("target", OT_TARGETS)
def test_no_form_of_an_ot_target_gets_through_for_any_action(fast, action, target):
    token = approve(fast, action, target)
    response = fast.post(f"/containment/{action}", json={**BODY, "target": target, "approval_token": token})
    assert response.status_code == 403 and "OT" in response.json()["detail"], target


@pytest.mark.parametrize("target", ["WS-BCN-2005", "POS-T07-01", "198.51.100.7", "bad.example", "10.40.2.10", "<id-99999@mail.example>"])
def test_targets_outside_ot_still_run(fast, target):
    token = approve(fast, "block_ioc", target)
    assert fast.post("/containment/block_ioc", json={**BODY, "target": target, "approval_token": token}).status_code == 200


def test_ot_guard_also_catches_the_ip_form(fast):
    ip = fast.get("/assets/PLC-SORT01").json()["ip"]
    token = approve(fast, "isolate_host", ip)
    assert fast.post("/containment/isolate_host", json={**BODY, "target": ip, "approval_token": token}).status_code == 403


def test_tests_never_touch_the_real_containment_log(fast, log_path):
    from api import soc_api

    assert soc_api.LOGFILE == log_path != DEFAULT_LOG
    assert (DEFAULT_LOG.read_bytes() if DEFAULT_LOG.exists() else None) == DEFAULT_LOG_BEFORE
