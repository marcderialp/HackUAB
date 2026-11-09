"""Build `.cache/tarvia.duckdb` from the dataset: `python -m triage.loader`.

Tables:
  events          one row per log event: event_id, source, ts (naive UTC), raw (original JSON)
  event_index     one row per entity seen in an event: entity_type, entity_value, ts, source, event_id, field
  log_<source>    each log source with typed columns, for direct SQL
  alerts          alert_id, ts, rule_id, severity... and raw
  alert_entities  one row per entity in an alert: alert_id, entity_type, entity_value, ts
  assets, users, services, service_members, network_zones, vulnerabilities, hr_events,
  changes, change_scope, stores, geoip, ti_feed, sandbox, build_info

Everything else opens the file read-only, so it builds to a temp file and is swapped in at the end.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import duckdb

from triage.entities import extract_entities, flatten
from triage.normalize import expand_members, madrid_to_utc

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = Path(os.environ.get("TARVIA_DB", ROOT / ".cache" / "tarvia.duckdb"))

# Row counts of the mock dataset written by tools/make_mock_data.py; a mismatch fails the build.
LOG_SOURCES = {
    "ad_events": 45, "ai_gateway": 408, "cicd_builds": 146, "cloudtrail": 262, "dlp": 24, "dns": 1686,
    "ecom_account": 385, "ecom_auth": 1483, "edr_events": 1262, "email": 177, "email_clicks": 16, "firewall": 1251,
    "idp_audit": 20, "idp_signins": 763, "proxy": 1485, "sql_audit": 158, "vpn": 50, "waf": 3866,
}
EXPECTED_ALERTS = 295

INVENTORY = {
    "assets": "02_inventario/activos.csv",
    "users": "02_inventario/usuarios.csv",
    "services": "02_inventario/servicios_negocio.csv",
    "network_zones": "02_inventario/zonas_red.csv",
    "vulnerabilities": "02_inventario/vulnerabilidades.csv",
    "hr_events": "02_inventario/eventos_rrhh.csv",
    "changes": "02_inventario/calendario_cambios.csv",
    "stores": "02_inventario/tiendas.csv",
    "geoip": "05_inteligencia/geoip_asn.csv",
}

# Keep in sync with normalize_user() in normalize.py.
USER_SQL = (
    "regexp_replace(regexp_replace(lower(trim({v})), '^(tarvia|nt authority)\\\\', ''), "
    "'@tarvia\\.example$', '')"
)

# source -> (entity_type, JSON path, kind). Kinds are defined in _value_sql().
ENTITY_FIELDS: dict[str, list[tuple[str, str, str]]] = {
    "ad_events": [
        ("user", "$.subject", "user"), ("user", "$.target", "user"),
        ("host", "$.dc", "lower"), ("host", "$.src_host", "lower"),
    ],
    "ai_gateway": [
        ("session", "$.session_id", "lower"), ("customer", "$.customer_id", "lower"), ("ip", "$.src_ip", "lower"),
    ],
    "cicd_builds": [("host", "$.runner", "lower"), ("hash", "$.details.new_packages[*].sha256", "lower")],
    "cloudtrail": [
        ("ip", "$.sourceIPAddress", "lower"), ("user", "$.userIdentity.userName", "user"),
        ("access_key", "$.userIdentity.accessKeyId", "lower"),
        ("bucket", "$.requestParameters.bucketName", "lower"), ("user", "$.requestParameters.userName", "user"),
    ],
    "dlp": [
        ("user", "$.user", "user"), ("host", "$.hostname", "lower"),
        ("email", "$.destination", "email"), ("user", "$.destination", "internal_email"),
        ("domain", "$.destination", "bare_domain"),
    ],
    "dns": [
        ("ip", "$.src_ip", "lower"), ("host", "$.hostname", "lower"), ("domain", "$.query", "lower"),
        ("ip", "$.response", "ip_only"),
    ],
    "ecom_account": [("customer", "$.customer_id", "lower"), ("ip", "$.src_ip", "lower")],
    "ecom_auth": [("customer", "$.customer_id", "lower"), ("email", "$.email", "email"), ("ip", "$.src_ip", "lower")],
    "edr_events": [
        ("host", "$.hostname", "lower"), ("user", "$.user", "user"), ("hash", "$.sha256", "lower"),
        ("host", "$.details.remote_host", "lower"), ("ip", "$.details.remote_ip", "lower"),
        ("domain", "$.command_line", "text_url_hosts"), ("ip", "$.command_line", "text_url_hosts"),
        ("ip", "$.details.logon_type", "text_ips"),
    ],
    "email": [
        ("message_id", "$.message_id", "lower"), ("ip", "$.sender_ip", "lower"),
        ("email", "$.sender", "email"), ("user", "$.sender", "internal_email"), ("domain", "$.sender", "email_domain"),
        ("email", "$.recipients[*]", "email"), ("user", "$.recipients[*]", "internal_email"),
        ("hash", "$.attachments[*].sha256", "lower"), ("hash", "$.attachments[*].contains[*].sha256", "lower"),
        ("domain", "$.urls[*]", "url_domain"),
    ],
    "email_clicks": [
        ("user", "$.user", "user"), ("message_id", "$.message_id", "lower"), ("ip", "$.src_ip", "lower"),
        ("domain", "$.url", "url_domain"),
    ],
    "firewall": [("ip", "$.src_ip", "lower"), ("ip", "$.dst_ip", "lower")],
    "idp_audit": [("user", "$.actor_upn", "user"), ("user", "$.target", "internal_email"), ("ip", "$.src_ip", "lower")],
    "idp_signins": [
        ("user", "$.user_upn", "user"), ("ip", "$.src_ip", "lower"), ("session", "$.session_id", "lower"),
        ("device", "$.device_id", "lower"), ("host", "$.device_id", "cmdb_host"),
    ],
    "proxy": [
        ("ip", "$.src_ip", "lower"), ("ip", "$.dst_ip", "lower"), ("host", "$.hostname", "lower"),
        ("user", "$.user", "user"), ("domain", "$.domain", "lower"),
    ],
    "sql_audit": [("user", "$.user", "user"), ("host", "$.client_host", "lower")],
    "vpn": [("user", "$.user", "user"), ("ip", "$.src_ip", "lower"), ("ip", "$.assigned_ip", "lower")],
    "waf": [("ip", "$.src_ip", "lower"), ("domain", "$.host", "lower")],
}


def _path(relative: str) -> str:
    return (ROOT / relative).as_posix()


def _read_csv_sql(path: str) -> str:
    # The custom nullstr keeps empty cells as '', matching what the mock API returns.
    return f"read_csv('{path}', header=true, all_varchar=true, sample_size=-1, nullstr='__no_null__')"


def _log_file(source: str) -> tuple[str, bool]:
    jsonl = ROOT / "04_logs" / f"{source}.jsonl"
    if jsonl.exists():
        return jsonl.as_posix(), True
    return (ROOT / "04_logs" / f"{source}.csv").as_posix(), False


def _load_logs(con: duckdb.DuckDBPyConnection) -> None:
    con.execute("CREATE TABLE events (event_id VARCHAR, source VARCHAR, ts TIMESTAMP, raw VARCHAR)")
    for source in LOG_SOURCES:
        path, is_json = _log_file(source)
        if is_json:
            typed = f"read_json('{path}', format='newline_delimited', sample_size=-1, timestampformat='%Y-%m-%dT%H:%M:%S.%gZ')"
            raw = f"SELECT json::VARCHAR AS raw FROM read_ndjson_objects('{path}')"
        else:
            typed = _read_csv_sql(path)
            raw = f"SELECT to_json(t)::VARCHAR AS raw FROM {_read_csv_sql(path)} t"
        con.execute(f"""
            INSERT INTO events
            SELECT raw->>'$.event_id', '{source}', CAST(replace(raw->>'$.timestamp', 'Z', '') AS TIMESTAMP), raw
            FROM ({raw})
        """)
        con.execute(f'CREATE TABLE log_{source} AS SELECT *, CAST("timestamp" AS TIMESTAMP) AS ts FROM {typed}')
    con.execute("CREATE UNIQUE INDEX idx_events_id ON events (event_id)")


def _value_sql(kind: str, v: str) -> tuple[str, str]:
    """Return the SQL for a value and an extra filter, given a value expression `v`."""
    low = f"lower(trim({v}))"
    if kind == "user":
        return USER_SQL.format(v=v), "TRUE"
    if kind == "internal_email":
        return USER_SQL.format(v=v), f"{low} LIKE '%@tarvia.example'"
    if kind == "email":
        return low, f"{low} LIKE '%@%'"
    if kind == "email_domain":
        return f"split_part({low}, '@', 2)", f"{low} LIKE '%@%'"
    if kind == "url_domain":
        return f"regexp_extract({low}, '^[a-z][a-z0-9+.-]*://([^/:?#]+)', 1)", "TRUE"
    if kind == "bare_domain":
        return low, f"{low} NOT LIKE '%@%' AND {low} NOT LIKE '% %'"
    if kind == "text_url_hosts":  # _build_event_index keeps IPs under `ip` and names under `domain`.
        pattern = """https?://([^/:?#\\s"']+)""".replace("'", "''")
        return f"unnest(regexp_extract_all({low}, '{pattern}', 1))", f"{low} LIKE '%://%'"
    if kind == "text_ips":
        return f"unnest(regexp_extract_all({low}, '\\b(?:[0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}\\b'))", "TRUE"
    if kind == "cmdb_host":
        return low, f"{low} IN (SELECT lower(hostname) FROM assets)"
    if kind == "ip_only":
        return low, f"regexp_full_match({low}, '[0-9]{{1,3}}(\\.[0-9]{{1,3}}){{3}}')"
    return low, "TRUE"


def _build_event_index(con: duckdb.DuckDBPyConnection) -> None:
    selects = []
    for source, fields in ENTITY_FIELDS.items():
        for entity_type, path, kind in fields:
            field = path.removeprefix("$.").replace("[*]", "")
            if "[*]" in path:
                inner = (
                    f"SELECT event_id, ts, unnest(json_extract_string(raw, '{path}')) AS v "
                    f"FROM events WHERE source = '{source}'"
                )
            else:
                inner = f"SELECT event_id, ts, raw->>'{path}' AS v FROM events WHERE source = '{source}'"
            value, condition = _value_sql(kind, "v")
            selects.append(
                f"SELECT '{entity_type}' AS entity_type, {value} AS entity_value, ts, '{source}' AS source, "
                f"event_id, '{field}' AS field FROM ({inner}) WHERE v IS NOT NULL AND trim(v) <> '' AND {condition}"
            )
    con.execute(f"""
        CREATE TABLE event_index AS
        SELECT * FROM ({' UNION ALL '.join(selects)})
        WHERE entity_value <> ''
          AND NOT (entity_type = 'domain' AND regexp_full_match(entity_value, '[0-9.]+'))
          AND NOT (field = 'command_line' AND entity_type = 'ip' AND NOT regexp_full_match(entity_value, '[0-9.]+'))
        ORDER BY entity_type, entity_value, ts
    """)


def _load_alerts_and_intel(con: duckdb.DuckDBPyConnection) -> None:
    alerts = _path("03_alertas/alertas.jsonl")
    con.execute(f"""
        CREATE TABLE alerts AS
        SELECT raw->>'$.alert_id' AS alert_id, raw->>'$.created_at' AS created_at,
               CAST(replace(raw->>'$.created_at', 'Z', '') AS TIMESTAMP) AS ts,
               raw->>'$.source_product' AS source_product, raw->>'$.rule_id' AS rule_id,
               raw->>'$.rule_name' AS rule_name, raw->>'$.severity' AS severity,
               raw->>'$.status' AS status, raw->>'$.runbook' AS runbook, raw
        FROM (SELECT json::VARCHAR AS raw FROM read_ndjson_objects('{alerts}'))
    """)
    con.execute("CREATE UNIQUE INDEX idx_alerts_id ON alerts (alert_id)")
    feed = _path("05_inteligencia/ti_feed.jsonl")
    con.execute(f"""
        CREATE TABLE ti_feed AS
        SELECT raw->>'$.value' AS value, raw->>'$.indicator_type' AS indicator_type, raw
        FROM (SELECT json::VARCHAR AS raw FROM read_ndjson_objects('{feed}'))
    """)
    sandbox = _path("05_inteligencia/sandbox_informes.jsonl")
    con.execute(f"""
        CREATE TABLE sandbox AS
        SELECT raw->>'$.sha256' AS sha256, raw
        FROM (SELECT json::VARCHAR AS raw FROM read_ndjson_objects('{sandbox}'))
    """)


def _build_alert_entities(con: duckdb.DuckDBPyConnection) -> None:
    alert_ids, types, values = [], [], []
    for alert_id, raw in con.execute("SELECT alert_id, raw FROM alerts").fetchall():
        for entity_type, value in flatten(extract_entities(json.loads(raw))):
            alert_ids.append(alert_id)
            types.append(entity_type)
            values.append(value)
    con.execute(
        """
        CREATE TABLE alert_entities AS
        SELECT e.alert_id, e.entity_type, e.entity_value, a.ts
        FROM (
            SELECT unnest(?::VARCHAR[]) AS alert_id, unnest(?::VARCHAR[]) AS entity_type,
                   unnest(?::VARCHAR[]) AS entity_value
        ) e JOIN alerts a USING (alert_id)
        ORDER BY e.entity_type, e.entity_value, a.ts
        """,
        [alert_ids, types, values],
    )


def _load_inventory(con: duckdb.DuckDBPyConnection) -> None:
    for table, relative in INVENTORY.items():
        con.execute(f"CREATE TABLE {table} AS SELECT * FROM {_read_csv_sql(_path(relative))}")
    con.execute("CREATE UNIQUE INDEX idx_geoip_ip ON geoip (ip)")
    hostnames = [row[0] for row in con.execute("SELECT hostname FROM assets").fetchall()]

    con.execute("CREATE TABLE service_members (servicio VARCHAR, criticidad VARCHAR, member VARCHAR, kind VARCHAR)")
    for servicio, criticidad, activos in con.execute("SELECT servicio, criticidad, activos FROM services").fetchall():
        rows = [(servicio, criticidad, member, kind) for member, kind in expand_members(activos, hostnames)]
        if rows:
            con.executemany("INSERT INTO service_members VALUES (?, ?, ?, ?)", rows)

    # Change windows are in local time; keep the originals and add UTC versions.
    con.execute("ALTER TABLE changes ADD COLUMN inicio_utc TIMESTAMP")
    con.execute("ALTER TABLE changes ADD COLUMN fin_utc TIMESTAMP")
    con.execute("CREATE TABLE change_scope (change_id VARCHAR, member VARCHAR, kind VARCHAR)")
    for change_id, inicio, fin, alcance in con.execute("SELECT id, inicio, fin, alcance FROM changes").fetchall():
        con.execute(
            "UPDATE changes SET inicio_utc = ?, fin_utc = ? WHERE id = ?",
            [madrid_to_utc(inicio), madrid_to_utc(fin), change_id],
        )
        rows = [(change_id, member, kind) for member, kind in expand_members(alcance, hostnames)]
        if rows:
            con.executemany("INSERT INTO change_scope VALUES (?, ?, ?)", rows)


def _validate(con: duckdb.DuckDBPyConnection) -> list[str]:
    problems = []
    for source, expected in LOG_SOURCES.items():
        actual = con.execute("SELECT count(*) FROM events WHERE source = ?", [source]).fetchone()[0]
        if actual != expected:
            problems.append(f"{source}: expected {expected}, got {actual}")
    alerts = con.execute("SELECT count(*) FROM alerts").fetchone()[0]
    if alerts != EXPECTED_ALERTS:
        problems.append(f"alerts: expected {EXPECTED_ALERTS}, got {alerts}")
    bad_ts = con.execute("SELECT count(*) FROM events WHERE ts IS NULL OR event_id IS NULL").fetchone()[0]
    if bad_ts:
        problems.append(f"events with no timestamp or id: {bad_ts}")
    return problems


def build(db_path: Path = DB_PATH) -> None:
    started = time.time()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = db_path.with_name(db_path.name + ".build")
    for leftover in (tmp, tmp.with_name(tmp.name + ".wal")):
        leftover.unlink(missing_ok=True)

    con = duckdb.connect(str(tmp))
    steps = [
        ("logs", _load_logs), ("alerts and intel", _load_alerts_and_intel),
        ("inventory", _load_inventory), ("event index", _build_event_index),
        ("alert entities", _build_alert_entities),
    ]
    for label, step in steps:
        step_started = time.time()
        step(con)
        print(f"  {label}: {time.time() - step_started:.1f} s")

    problems = _validate(con)
    if problems:
        con.close()
        tmp.unlink(missing_ok=True)
        sys.exit("Build failed validation:\n  " + "\n  ".join(problems))

    con.execute("CREATE TABLE build_info AS SELECT now()::VARCHAR AS built_at, (SELECT count(*) FROM events) AS events")
    events, index_rows = con.execute("SELECT (SELECT count(*) FROM events), (SELECT count(*) FROM event_index)").fetchone()
    con.close()

    try:
        os.replace(tmp, db_path)
    except PermissionError:
        sys.exit(f"Built {tmp}, but {db_path} is in use. Stop the API and UI, then run the loader again.")
    size_mb = db_path.stat().st_size / 1e6
    print(f"Built {db_path}: {events:,} events, {index_rows:,} index rows, {size_mb:.0f} MB, {time.time() - started:.0f} s")


if __name__ == "__main__":
    build()
