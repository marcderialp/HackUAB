import json
import re
import time
from datetime import timedelta

import duckdb
import pytest

from triage import data, loader

pytestmark = pytest.mark.db


@pytest.fixture
def tiny_db(monkeypatch):
    """An in-memory database that data.* reads instead, for cases the mock dataset doesn't contain."""
    con = duckdb.connect()
    monkeypatch.setattr(data, "_cursor", lambda: con)
    yield con
    con.close()


def test_get_event_returns_original_event():
    item = data.get_event("WAF-7000123")
    assert item["source"] == "waf"
    assert item["event"]["event_id"] == "WAF-7000123"
    assert data.get_event("NOPE-1") is None


def test_timeline_finds_a_user_across_sources_and_all_name_forms():
    forms = [data.timeline(name, "user", limit=1)["total"]
             for name in ("oriol.masdeu", "TARVIA\\oriol.masdeu", "oriol.masdeu@tarvia.example")]
    assert forms[0] > 0 and len(set(forms)) == 1
    result = data.timeline("oriol.masdeu", "user", limit=2000)
    sources = {item["source"] for item in result["items"]}
    assert {"edr_events", "proxy", "idp_signins"} <= sources
    stamps = [item["timestamp"] for item in result["items"]]
    assert stamps == sorted(stamps)


def test_timeline_keeps_similar_names_apart():
    # Two people are called Candela Ruiz: candela.ruiz (Madrid office) and candela.ruiz2 (a store).
    one = data.timeline("candela.ruiz", "user", limit=2000)["items"]
    two = data.timeline("candela.ruiz2", "user", limit=2000)["items"]
    assert one and two
    # A message can go to both, but every event found must name the person searched for.
    assert all(re.search(r"candela\.ruiz(?!\d)", str(item["event"])) for item in one)
    assert all("candela.ruiz2" in str(item["event"]) for item in two)
    for name, items in (("candela.ruiz", one), ("candela.ruiz2", two)):
        assert {item["event"]["user_upn"] for item in items if item["source"] == "idp_signins"} == {f"{name}@tarvia.example"}


def test_timeline_window_and_sources_filter():
    result = data.timeline("WS-BCN-2005", "host", start="2026-10-13", end="2026-10-14", sources=["edr_events"], limit=2000)
    assert result["total"] > 0
    assert result["total"] < data.timeline("WS-BCN-2005", "host", sources=["edr_events"], limit=1)["total"]
    assert {item["source"] for item in result["items"]} == {"edr_events"}
    assert all("2026-10-13" <= item["timestamp"] <= "2026-10-14" for item in result["items"])


def test_timeline_reports_truncation():
    result = data.timeline("oriol.masdeu", "user", limit=5)
    assert result["count"] == 5 and result["truncated"] and result["total"] > 5


def test_timeline_domain_matches_subdomains_only():
    # `query` values are domains in DNS; a suffix match must respect the dot boundary.
    parent = data.timeline("cdn-metricas.example", "domain", limit=2000)
    assert parent["total"] > 0
    assert all(".cdn-metricas.example" in str(item["event"]) for item in parent["items"])
    assert data.timeline("metricas.example", "domain")["total"] == 0


def test_timeline_finds_host_in_signin_device_field():
    # Sign-ins name the laptop only in `device_id`, a field that can also hold opaque device codes.
    items = data.timeline("WS-BCN-2005", "host", sources=["idp_signins"], limit=2000)["items"]
    assert items and all(item["matched_fields"] == ["device_id"] for item in items)
    assert {item["event"]["device_id"] for item in items} == {"WS-BCN-2005"}


def test_opaque_device_code_is_a_device_but_not_a_host(tiny_db):
    # Every device_id in the mock data is a CMDB hostname, so build one sign-in with an opaque code.
    tiny_db.execute("CREATE TABLE assets AS SELECT 'WS-BCN-2005' AS hostname")
    tiny_db.execute("CREATE TABLE events (event_id VARCHAR, source VARCHAR, ts TIMESTAMP, raw VARCHAR)")
    for event_id, device in (("SIGN-1", "WS-BCN-2005"), ("SIGN-2", "dev-ficticio1")):
        raw = json.dumps({"event_id": event_id, "user_upn": "oriol.masdeu@tarvia.example", "device_id": device})
        tiny_db.execute("INSERT INTO events VALUES (?, 'idp_signins', TIMESTAMP '2026-10-13 08:00:00', ?)", [event_id, raw])
    loader._build_event_index(tiny_db)
    assert [item["event_id"] for item in data.timeline("WS-BCN-2005", "host")["items"]] == ["SIGN-1"]
    assert data.timeline("dev-ficticio1", "device", limit=1)["total"] > 0
    assert data.timeline("dev-ficticio1", "host", limit=1)["total"] == 0


def test_timeline_finds_domain_in_command_line_url():
    # certutil on WS-BCN-2005 downloads tools from the C2; the domain appears only in its command line.
    downloads = data.search_logs("edr_events", q="certutil")["items"]
    found = {item["event_id"]: item for item in data.timeline("cdn-sync-update.example", "domain", sources=["edr_events"], limit=2000)["items"]}
    assert downloads and all(found[event["event_id"]]["matched_fields"] == ["command_line"] for event in downloads)


def test_mentions_finds_free_text_across_sources():
    # A file name in a command line and in a URL path: no entity field holds it.
    result = data.mentions("tools.cab", limit=50)
    assert result["total"] == 2 and {item["source"] for item in result["items"]} == {"edr_events", "proxy"}
    with pytest.raises(ValueError):
        data.mentions("  ")


def test_detect_entity_type():
    assert data.detect_entity_type("10.10.4.15") == "ip"
    assert data.detect_entity_type("TARVIA\\oriol.masdeu") == "user"
    assert data.detect_entity_type("oriol.masdeu") == "user"
    assert data.detect_entity_type("JUMP01") == "host"
    assert data.detect_entity_type("nube-personal.example") == "domain"
    assert data.detect_entity_type("a" * 64) == "hash"
    assert data.detect_entity_type("no-existe") == "unknown"


def test_search_logs_filters():
    result = data.search_logs("edr_events", q="NLTEST", limit=50)
    assert result["count"] > 0
    assert all("nltest" in str(item).lower() for item in result["items"])
    with pytest.raises(ValueError):
        data.search_logs("not_a_source")


def test_asset_lookup_by_name_and_ip():
    by_name = data.get_asset("jump01")
    assert by_name["hostname"] == "JUMP01"
    assert data.get_asset(by_name["ip"])["hostname"] == "JUMP01"
    assert data.get_asset("no-such-host") is None


def test_asset_includes_expanded_services():
    services = [s["servicio"] for s in data.get_asset("WEB-ECOM03")["services"]]
    assert "Tienda online y app" in services


def test_user_lookup_includes_hr_events():
    user = data.get_user("TARVIA\\didac.ubach")
    assert user["upn"] == "didac.ubach@tarvia.example"
    assert any(event["tipo"] == "baja_voluntaria_comunicada" for event in user["hr_events"])
    assert data.get_user("didac.uba") is None


def test_unknown_indicator_has_no_tip():
    assert data.get_intel("203.0.113.254")["tip"] is None


def test_sandbox_missing_returns_none():
    assert data.get_sandbox("0" * 64) is None


def test_changes_by_host_and_time_use_local_windows():
    # CHG-2026-2104 runs 08:00-14:00 Madrid (UTC+2), so 06:30 UTC is inside and 05:30 UTC isn't.
    inside = data.find_changes(host="PLC-SORT03", at="2026-10-16T06:30:00Z")
    assert [c["id"] for c in inside if c["scope_match"] == "host"] == ["CHG-2026-2104"]
    outside = data.find_changes(host="PLC-SORT03", at="2026-10-16T05:30:00Z")
    assert "CHG-2026-2104" not in [c["id"] for c in outside]


def test_changes_with_free_text_scope_are_flagged_not_hidden():
    # CHG-2026-2103 covers "Todos los puestos", which only a person can match to a laptop.
    found = {c["id"]: c["scope_match"] for c in data.find_changes(host="WS-BCN-2005", at="2026-10-13T09:00:00Z")}
    assert found.get("CHG-2026-2103") == "text"


def test_zone_lookup():
    assert data.zone_for_ip("10.40.16.5")["zona"] == "LOGISTICS-OT"
    assert data.zone_for_ip("10.40.1.5")["zona"] == "LOGISTICS-IT"
    assert data.zone_for_ip("8.8.8.8") is None


def test_domain_seen_only_as_a_parent_is_a_domain():
    # The mail gateway queries <address>.zen.dnsbl-ejemplo.example, never the domain itself.
    assert not data._rows("SELECT 1 FROM event_index WHERE entity_type = 'domain' AND entity_value = 'dnsbl-ejemplo.example'")
    assert data.detect_entity_type("dnsbl-ejemplo.example") == "domain"
    assert data.timeline("dnsbl-ejemplo.example", limit=1)["total"] > 0


def test_another_users_disconnect_doesnt_end_a_vpn_session(tiny_db):
    # The mock gives every user their own VPN address, so build a reused one: oriol.masdeu connects,
    # then a late disconnect from the address's previous holder arrives before his own.
    tiny_db.execute("""
        CREATE TABLE log_vpn (event_id VARCHAR, ts TIMESTAMP, "user" VARCHAR, src_ip VARCHAR, assigned_ip VARCHAR,
                              action VARCHAR, country VARCHAR)
    """)
    tiny_db.executemany("INSERT INTO log_vpn VALUES (?, ?, ?, ?, ?, ?, 'ES')", [
        ("VPN-1", "2026-10-13 06:00:00", "carla.bartra", "198.19.30.20", "10.99.4.200", "connect"),
        ("VPN-2", "2026-10-13 08:00:00", "oriol.masdeu", "198.19.30.21", "10.99.4.200", "connect"),
        ("VPN-3", "2026-10-13 08:05:00", "carla.bartra", "198.19.30.20", "10.99.4.200", "disconnect"),
        ("VPN-4", "2026-10-13 15:00:00", "oriol.masdeu", "198.19.30.21", "10.99.4.200", "disconnect"),
    ])
    session = data.vpn_session("10.99.4.200", "2026-10-13T10:00:00Z")
    assert session["user"] == "oriol.masdeu" and session["connect_event_id"] == "VPN-2"
    assert session["disconnect_event_id"] == "VPN-4"
    assert data.vpn_session("10.99.4.200", "2026-10-13T16:00:00Z") is None


def test_vpn_session_is_time_specific():
    connect = data._rows(
        """SELECT "user" AS u, assigned_ip, ts FROM log_vpn WHERE action = 'connect' ORDER BY ts LIMIT 1"""
    )[0]
    session = data.vpn_session(connect["assigned_ip"], connect["ts"] + timedelta(seconds=1))
    assert session["user"] == connect["u"]
    assert data.vpn_session(connect["assigned_ip"], connect["ts"] - timedelta(days=1)) is None


def test_resolve_ip_for_a_managed_host():
    asset = data.get_asset("JUMP01")
    result = data.resolve_ip(asset["ip"], at="2026-10-13T09:00:00Z")
    assert result["asset"]["hostname"] == "JUMP01"
    assert result["zone"] is not None


def test_hosts_for_user_and_back():
    hosts = data.hosts_for_user("oriol.masdeu")
    assert "ws-bcn-2005" in [h["value"] for h in hosts]
    assert "oriol.masdeu" in [u["value"] for u in data.users_for_host("WS-BCN-2005")]


@pytest.mark.parametrize(
    "name, call",
    [
        ("timeline user", lambda: data.timeline("oriol.masdeu", "user", limit=200)),
        ("timeline busy ip", lambda: data.timeline("198.19.10.1", "ip", limit=200)),
        ("timeline domain", lambda: data.timeline("office365.com", "domain", limit=200)),
        ("get_asset", lambda: data.get_asset("JUMP01")),
        ("get_user", lambda: data.get_user("oriol.masdeu")),
        ("get_intel", lambda: data.get_intel("203.0.113.45")),
        ("find_changes", lambda: data.find_changes(host="JUMP01", at="2026-10-13T09:00:00Z")),
        ("resolve_ip", lambda: data.resolve_ip("10.10.4.15", at="2026-10-13T09:00:00Z")),
        ("hosts_for_user", lambda: data.hosts_for_user("oriol.masdeu")),
    ],
)
def test_indexed_queries_meet_the_200ms_target(name, call):
    assert_within(name, call, 200)


@pytest.mark.parametrize(
    "name, call",
    [
        ("search_logs", lambda: data.search_logs("proxy", q="nube-personal.example", limit=200)),
        ("mentions", lambda: data.mentions("cdn-sync-update.example", limit=200)),
    ],
)
def test_full_text_scans_stay_within_one_second(name, call):
    # These read every event's text, so they slow down as the logs grow and when memory is tight.
    # Indexed queries are what collectors should rely on.
    assert_within(name, call, 1000)


def assert_within(name, call, budget_ms):
    call()  # the first call warms the connection
    started = time.perf_counter()
    call()
    elapsed_ms = (time.perf_counter() - started) * 1000
    print(f"{name}: {elapsed_ms:.0f} ms")
    assert elapsed_ms < budget_ms, f"{name} took {elapsed_ms:.0f} ms"
