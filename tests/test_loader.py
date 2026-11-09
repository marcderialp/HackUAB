import json
from datetime import datetime

import duckdb
import pytest

from triage.loader import DB_PATH, LOG_SOURCES, ROOT
from triage.normalize import expand_members, madrid_to_utc, normalize_user, parse_ts


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("TARVIA\\Oriol.Masdeu", "oriol.masdeu"),
        ("oriol.masdeu@tarvia.example", "oriol.masdeu"),
        ("oriol.masdeu", "oriol.masdeu"),
        ("NT AUTHORITY\\SYSTEM", "system"),
        ("candela.ruiz2", "candela.ruiz2"),
        ("adm.bclotet", "adm.bclotet"),
        ("didac.ubach.personal@correo-personal.example", "didac.ubach.personal@correo-personal.example"),
        ("", ""),
        (None, ""),
    ],
)
def test_normalize_user(raw, expected):
    assert normalize_user(raw) == expected


def test_madrid_to_utc_handles_daylight_saving():
    assert madrid_to_utc("2026-10-08 08:00") == datetime(2026, 10, 8, 6, 0)  # UTC+2
    assert madrid_to_utc("2026-10-28 01:00") == datetime(2026, 10, 28, 0, 0)  # UTC+1 after 25 Oct


def test_parse_ts_accepts_all_forms():
    expected = datetime(2026, 10, 9, 10, 0)
    assert parse_ts("2026-10-09T10:00:00.000Z") == expected
    assert parse_ts("2026-10-09T12:00:00+02:00") == expected
    assert parse_ts("2026-10-09T10:00:00") == expected
    assert parse_ts(None) is None


def test_expand_members():
    hosts = ["WEB-ECOM01", "WEB-ECOM02", "POS-T07-01", "POS-T08-02", "DC01"]
    assert expand_members("WEB-ECOM01..02, DC01", hosts) == [
        ("WEB-ECOM01", "host"), ("WEB-ECOM02", "host"), ("DC01", "host"),
    ]
    assert expand_members("POS-T*", hosts) == [("POS-T07-01", "host"), ("POS-T08-02", "host")]
    # Text that isn't a host stays visible rather than disappearing.
    assert expand_members("IdP en la nube", hosts) == [("IdP en la nube", "other")]


@pytest.fixture(scope="module")
def con():
    connection = duckdb.connect(str(DB_PATH), read_only=True)
    yield connection
    connection.close()


@pytest.mark.db
def test_every_source_has_its_published_count(con):
    for source, expected in LOG_SOURCES.items():
        assert con.execute("SELECT count(*) FROM events WHERE source = ?", [source]).fetchone()[0] == expected
        assert con.execute(f"SELECT count(*) FROM log_{source}").fetchone()[0] == expected


@pytest.mark.db
def test_all_alert_related_events_resolve(con):
    missing = con.execute("""
        SELECT count(*) FROM (
            SELECT unnest(json_extract_string(raw, '$.related_events[*]')) AS event_id FROM alerts
        ) r ANTI JOIN events e USING (event_id)
    """).fetchone()[0]
    assert missing == 0


@pytest.mark.db
def test_similar_identities_stay_separate(con):
    # Near-identical names must never merge: candela.ruiz and candela.ruiz2 are two people.
    counts = dict(con.execute("""
        SELECT entity_value, count(*) FROM event_index
        WHERE entity_type = 'user' AND entity_value IN ('candela.ruiz', 'candela.ruiz2')
        GROUP BY 1
    """).fetchall())
    assert set(counts) == {"candela.ruiz", "candela.ruiz2"}


@pytest.mark.db
def test_user_values_are_fully_normalized(con):
    left = con.execute("""
        SELECT count(*) FROM event_index WHERE entity_type = 'user'
        AND (entity_value LIKE 'tarvia\\%' OR entity_value LIKE '%@tarvia.example')
    """).fetchone()[0]
    assert left == 0


@pytest.mark.db
def test_nested_fields_are_indexed(con):
    # The mock's EDR events never carry details.remote_host, so that path has no rows to check here.
    for entity_type, field in [("ip", "details.remote_ip"), ("ip", "details.logon_type"),
                               ("bucket", "requestParameters.bucketName"), ("hash", "attachments.sha256"),
                               ("hash", "attachments.contains.sha256"), ("hash", "details.new_packages.sha256"),
                               ("email", "recipients")]:
        found = con.execute(
            "SELECT count(*) FROM event_index WHERE entity_type = ? AND field = ?", [entity_type, field]
        ).fetchone()[0]
        assert found > 0, field


@pytest.mark.db
def test_empty_csv_cells_stay_empty_strings(con):
    # The SOC API contract returns '' for empty cells, so null would break it.
    nulls = con.execute("SELECT count(*) FROM users WHERE notes IS NULL").fetchone()[0]
    empties = con.execute("SELECT count(*) FROM users WHERE notes = ''").fetchone()[0]
    assert nulls == 0 and empties > 0


@pytest.mark.db
def test_change_windows_converted_to_utc(con):
    # CHG-2026-2103 runs from 1 September (UTC+2) to 31 December (UTC+1), across the clock change.
    start, end = con.execute("SELECT inicio_utc, fin_utc FROM changes WHERE id = 'CHG-2026-2103'").fetchone()
    assert start == datetime(2026, 8, 31, 22, 0) and end == datetime(2026, 12, 31, 22, 59)


@pytest.mark.db
def test_ranges_expand_against_the_cmdb(con):
    scope = [r[0] for r in con.execute(
        "SELECT member FROM change_scope WHERE change_id = 'CHG-2026-2104' AND kind = 'host' ORDER BY member"
    ).fetchall()]
    assert scope == [f"PLC-SORT0{n}" for n in range(1, 4)]
    pos = con.execute("""
        SELECT count(*) FROM service_members
        WHERE servicio = 'Cobro en tienda (PCI DSS)' AND kind = 'host'
    """).fetchone()[0]
    terminals = con.execute("SELECT count(*) FROM assets WHERE hostname LIKE 'POS-T%'").fetchone()[0]
    assert pos == terminals == 16  # two in each of the eight stores


@pytest.mark.db
def test_raw_event_is_the_original_json(con):
    raw = con.execute("SELECT raw FROM events WHERE event_id = 'WAF-7000123'").fetchone()[0]
    with open(ROOT / "04_logs" / "waf.jsonl", encoding="utf-8") as handle:
        original = next(json.loads(line) for line in handle if '"WAF-7000123"' in line)
    assert json.loads(raw) == original
