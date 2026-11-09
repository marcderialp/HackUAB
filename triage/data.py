"""Read-only query primitives over the DuckDB file. These return facts, never verdicts.

Build the database first with `python -m triage.loader`. Timestamps may be ISO strings (with `Z`
or an offset) or datetimes; anything without an offset is treated as UTC.

Safe to call from several threads and processes: each thread gets its own read-only cursor.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
import threading
from datetime import datetime, timedelta
from typing import Any, Iterable
from urllib.parse import urlsplit

import duckdb

from triage.loader import DB_PATH, LOG_SOURCES
from triage.normalize import is_ip, normalize_host, normalize_user, parse_ts
from triage.policy import OT_ASSET_TYPES, OT_ZONE

_lock = threading.Lock()
_root: duckdb.DuckDBPyConnection | None = None
_local = threading.local()

ENTITY_TYPES = ("user", "host", "ip", "domain", "email", "hash", "session", "message_id",
                "customer", "access_key", "bucket", "device")
DEFAULT_LIMIT = 200
MAX_LIMIT = 2000
# PLC-SORT01..06, PLC-SORT01..PLC-SORT06, 10.40.16.21-26
_TARGET_RANGE = re.compile(r"^(?P<stem>.*?)(?P<first>\d+)(?:\.\.|-)(?:(?P=stem))?(?P<last>\d+)$")
_MAX_TARGET_RANGE = 256  # past every IP octet and every numbered OT device, so a wider range still gets caught


def _cursor() -> duckdb.DuckDBPyConnection:
    global _root
    cursor = getattr(_local, "cursor", None)
    if cursor is None:
        with _lock:
            if _root is None:
                if not DB_PATH.exists():
                    raise FileNotFoundError(f"{DB_PATH} not found. Run: python -m triage.loader")
                _root = duckdb.connect(str(DB_PATH), read_only=True)
            cursor = _root.cursor()
        _local.cursor = cursor
    return cursor


def _rows(sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
    cursor = _cursor().execute(sql, list(params))
    names = [d[0] for d in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def _iso(value: datetime | None) -> str | None:
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z" if value else None


def _clamp(limit: int) -> int:
    return max(1, min(int(limit), MAX_LIMIT))


def window(at: str | datetime, hours: float = 24) -> tuple[datetime, datetime]:
    """Return the time window around a moment; the SOC policy correlates over ±24 h."""
    moment = parse_ts(at)
    return moment - timedelta(hours=hours), moment + timedelta(hours=hours)


def detect_entity_type(value: str) -> str:
    """Guess an entity's type from its shape. Pass the type explicitly when you know it."""
    text = value.strip()
    if is_ip(text):
        return "ip"
    if "\\" in text:
        return "user"
    if "@" in text:
        return "user" if text.lower().endswith("@tarvia.example") else "email"
    low = text.lower()
    if len(low) == 64 and all(c in "0123456789abcdef" for c in low):
        return "hash"
    for table, column, entity_type in (("assets", "hostname", "host"), ("users", "username", "user")):
        if _rows(f"SELECT 1 AS x FROM {table} WHERE lower({column}) = ? LIMIT 1", [low]):
            return entity_type
    if "." in low and _rows("SELECT 1 AS x FROM event_index WHERE entity_type = 'domain' AND entity_value = ? LIMIT 1", [low]):
        return "domain"
    found = _rows("SELECT entity_type FROM event_index WHERE entity_value = ? LIMIT 1", [normalize_user(low)])
    if found:
        return found[0]["entity_type"]
    # A domain may appear only through its subdomains, and timeline() matches those.
    return "domain" if "." in low and " " not in low else "unknown"


def _index_key(value: str, entity_type: str) -> str:
    if entity_type == "user":
        return normalize_user(value)
    if entity_type == "host":
        return normalize_host(value)
    return value.strip().lower()


def get_event(event_id: str) -> dict[str, Any] | None:
    """Fetch one log event by ID, such as the IDs in an alert's `related_events`."""
    found = get_events([event_id])
    return found[0] if found else None


def get_events(event_ids: Iterable[str]) -> list[dict[str, Any]]:
    ids = list(event_ids)
    if not ids:
        return []
    placeholders = ",".join("?" * len(ids))
    rows = _rows(f"SELECT event_id, source, ts, raw FROM events WHERE event_id IN ({placeholders}) ORDER BY ts, event_id", ids)
    return [_event_item(row) for row in rows]


def _event_item(row: dict[str, Any]) -> dict[str, Any]:
    item = {"event_id": row["event_id"], "source": row["source"], "timestamp": _iso(row["ts"]),
            "event": json.loads(row["raw"])}
    if "fields" in row:
        item["matched_fields"] = sorted(row["fields"])
    return item


def timeline(
    entity: str,
    entity_type: str | None = None,
    start: str | datetime | None = None,
    end: str | datetime | None = None,
    sources: Iterable[str] | None = None,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    """Return an entity's events in time order, across all log sources.

    Matching is exact, except that a domain also matches its subdomains. `truncated` is true when
    `limit` cut the results and `total` gives the full count, so callers can see what they missed.

    This covers structured fields, plus URLs in EDR command lines. For an indicator that may appear
    only in free text, also call `mentions()`.
    """
    kind = entity_type or detect_entity_type(entity)
    key = _index_key(entity, kind)
    where, params = ["entity_type = ?"], [kind]
    if kind == "domain":
        where.append(r"(entity_value = ? OR entity_value LIKE ? ESCAPE '\')")
        escaped = key.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        params += [key, "%." + escaped]
    else:
        where.append("entity_value = ?")
        params.append(key)
    if start:
        where.append("ts >= ?")
        params.append(parse_ts(start))
    if end:
        where.append("ts <= ?")
        params.append(parse_ts(end))
    source_list = list(sources or [])
    if source_list:
        unknown = set(source_list) - set(LOG_SOURCES)
        if unknown:
            raise ValueError(f"unknown log sources: {sorted(unknown)}")
        where.append(f"source IN ({','.join('?' * len(source_list))})")
        params += source_list
    condition = " AND ".join(where)
    capped = _clamp(limit)
    rows = _rows(
        f"""
        WITH hits AS (
            SELECT event_id, list(DISTINCT field) AS fields FROM event_index WHERE {condition} GROUP BY event_id
        ), total AS (SELECT count(*) AS n FROM hits)
        SELECT e.event_id, e.source, e.ts, e.raw, h.fields, (SELECT n FROM total) AS total
        FROM hits h JOIN events e USING (event_id)
        ORDER BY e.ts, e.event_id
        LIMIT ?
        """,
        params + [capped],
    )
    total = rows[0]["total"] if rows else 0
    return {"entity": key, "entity_type": kind, "count": len(rows), "total": total,
            "truncated": total > len(rows), "items": [_event_item(row) for row in rows]}


def search_logs(
    source: str,
    q: str = "",
    start: str | datetime | None = None,
    end: str | datetime | None = None,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    """Case-insensitive substring search over one source's events, in file order like the mock API."""
    if source not in LOG_SOURCES:
        raise ValueError(f"unknown log source: {source}")
    where, params = ["source = ?"], [source]
    if start:
        where.append("ts >= ?")
        params.append(parse_ts(start))
    if end:
        where.append("ts <= ?")
        params.append(parse_ts(end))
    if q:
        where.append("contains(lower(raw), lower(?))")
        params.append(q)
    capped = _clamp(limit)
    rows = _rows(f"SELECT raw FROM events WHERE {' AND '.join(where)} ORDER BY rowid LIMIT ?", params + [capped])
    return {"count": len(rows), "truncated": len(rows) >= capped, "items": [json.loads(row["raw"]) for row in rows]}


def mentions(
    text: str,
    start: str | datetime | None = None,
    end: str | datetime | None = None,
    sources: Iterable[str] | None = None,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    """Find events across all sources whose text contains `text`, case-insensitively, in time order.

    A plain substring search: `10.0.0.1` also matches `10.0.0.12`, so check each hit. Use it to catch
    what structured fields miss, such as an IP in a logon description or a domain in a command line.
    """
    if not text.strip():
        raise ValueError("mentions() needs some text to search for")
    where, params = ["contains(lower(raw), lower(?))"], [text.strip()]
    if start:
        where.append("ts >= ?")
        params.append(parse_ts(start))
    if end:
        where.append("ts <= ?")
        params.append(parse_ts(end))
    source_list = list(sources or [])
    if source_list:
        where.append(f"source IN ({','.join('?' * len(source_list))})")
        params += source_list
    capped = _clamp(limit)
    # Sort IDs only, then fetch the few events needed; sorting whole events is far slower.
    hits = _rows(
        f"SELECT event_id, ts FROM events WHERE {' AND '.join(where)} ORDER BY ts, event_id",
        params,
    )
    items = get_events(hit["event_id"] for hit in hits[:capped])
    return {"text": text.strip(), "count": len(items), "total": len(hits), "truncated": len(hits) > len(items),
            "items": items}


def get_asset(key: str) -> dict[str, Any] | None:
    """CMDB record by hostname or IP, with its vulnerabilities and business services."""
    text = key.strip()
    rows = _rows("SELECT * FROM assets WHERE lower(hostname) = ? OR ip = ? LIMIT 1", [text.lower(), text])
    if not rows:
        return None
    asset = rows[0]
    asset["vulnerabilities"] = _rows("SELECT * FROM vulnerabilities WHERE hostname = ?", [asset["hostname"]])
    asset["services"] = _rows(
        "SELECT servicio, criticidad FROM service_members WHERE kind = 'host' AND member = ?", [asset["hostname"]]
    )
    return asset


def get_user(key: str) -> dict[str, Any] | None:
    """Directory record by UPN, username or `TARVIA\\user`, with HR events. Matching is exact."""
    name = normalize_user(key)
    rows = _rows("SELECT * FROM users WHERE lower(username) = ? LIMIT 1", [name])
    if not rows:
        return None
    user = rows[0]
    user["hr_events"] = _rows("SELECT * FROM hr_events WHERE usuario = ?", [user["upn"]])
    return user


def get_intel(indicator: str) -> dict[str, Any]:
    """TIP and GeoIP lookup. `tip: None` means unknown, which is not the same as clean."""
    text = indicator.strip()
    tips = _rows("SELECT raw FROM ti_feed WHERE value = ? OR lower(value) = ? LIMIT 1", [text, text.lower()])
    geo = _rows("SELECT * FROM geoip WHERE ip = ? LIMIT 1", [text])
    return {"indicator": text, "tip": json.loads(tips[0]["raw"]) if tips else None, "geo": geo[0] if geo else None}


def get_sandbox(sha256: str) -> dict[str, Any] | None:
    """Sandbox report, or None when the file was never submitted."""
    rows = _rows("SELECT raw FROM sandbox WHERE sha256 = ? LIMIT 1", [sha256.strip().lower()])
    return json.loads(rows[0]["raw"]) if rows else None


def find_changes(
    q: str = "",
    host: str | None = None,
    at: str | datetime | None = None,
) -> list[dict[str, Any]]:
    """Find approved changes and flows by text, host and/or moment.

    Each result has `scope_match`: "host" when the change names that host, or "text" when its scope
    is free text such as "Todos los puestos" and a person or collector has to judge whether it
    applies. Windows are compared in UTC. Recurrence described only in `detalle` is not expanded.
    """
    rows = _rows("SELECT * FROM changes ORDER BY inicio_utc")
    scope = _rows("SELECT change_id, member, kind FROM change_scope")
    results = []
    needle = q.lower()
    moment = parse_ts(at)
    wanted_host = normalize_host(host) if host else None
    for change in rows:
        original = {k: v for k, v in change.items() if k not in ("inicio_utc", "fin_utc")}
        if needle and needle not in json.dumps(original, ensure_ascii=False).lower():
            continue
        if moment and not change["inicio_utc"] <= moment <= change["fin_utc"]:
            continue
        members = [s for s in scope if s["change_id"] == change["id"]]
        hosts = [m["member"] for m in members if m["kind"] == "host"]
        free_text = [m["member"] for m in members if m["kind"] == "other"]
        match = None
        if wanted_host:
            if wanted_host in (h.lower() for h in hosts):
                match = "host"
            elif free_text:
                match = "text"
            else:
                continue
        results.append({
            **change,
            "inicio_utc": _iso(change["inicio_utc"]),
            "fin_utc": _iso(change["fin_utc"]),
            "scope_hosts": hosts,
            "scope_text": free_text,
            "scope_match": match,
        })
    return results


def zone_for_ip(ip: str) -> dict[str, Any] | None:
    """Network zone containing an IP, choosing the most specific range."""
    try:
        address = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    best, best_prefix = None, -1
    for zone in _rows("SELECT * FROM network_zones"):
        network = ipaddress.ip_network(zone["cidr"], strict=False)
        if address.version == network.version and address in network and network.prefixlen > best_prefix:
            best, best_prefix = zone, network.prefixlen
    return best


def _target_forms(target: str) -> list[str]:
    """Split a containment target into single names, IPs, CIDRs and patterns.

    The target can come from the LLM, which may copy a range from the inventory.
    """
    forms: list[str] = []
    for token in re.split(r"[,;\s]+", target.strip()):
        if "://" in token:
            try:
                token = urlsplit(token).hostname or token
            except ValueError:
                pass
        if not token:
            continue
        forms.append(token)  # also as written: a name such as POS-T07-01 looks like a range
        found = _TARGET_RANGE.match(token)
        if found:
            first, last = int(found["first"]), int(found["last"])
            width = len(found["first"])
            forms += [f"{found['stem']}{number:0{width}d}" for number in range(first, min(last, first + _MAX_TARGET_RANGE) + 1)]
    return forms


def _ot_asset_for(form: str) -> dict[str, Any] | None:
    if any(mark in form for mark in "*?"):
        for row in _rows(f"SELECT hostname FROM assets WHERE zone = ? OR type IN {OT_ASSET_TYPES!r}", [OT_ZONE]):
            if fnmatch.fnmatch(row["hostname"].lower(), form.lower()):
                return get_asset(row["hostname"])
        return None
    if "/" in form:
        try:
            network = ipaddress.ip_network(form, strict=False)
        except ValueError:
            return None
        for zone in _rows("SELECT cidr FROM network_zones WHERE zona = ?", [OT_ZONE]):
            other = ipaddress.ip_network(zone["cidr"], strict=False)
            if network.version == other.version and network.overlaps(other):
                return {"hostname": form, "zone": OT_ZONE}
        return None
    asset = get_asset(form)
    if asset and (asset.get("zone") == OT_ZONE or asset.get("type") in OT_ASSET_TYPES):
        return asset
    zone = zone_for_ip(form)
    return {"hostname": form, "zone": OT_ZONE} if zone and zone.get("zona") == OT_ZONE else None


def action_target_asset(target: str) -> dict[str, Any] | None:
    """The asset behind a containment target, for policy.action_policy(), whatever the action.

    If any part of the target is in OT (a name, IP, numbered or last-octet range, CIDR, pattern or
    URL), that part is returned, so the policy refuses the action.
    """
    for form in _target_forms(target):
        asset = _ot_asset_for(form)
        if asset:
            return asset
    return get_asset(target.strip())


def vpn_session(ip: str, at: str | datetime) -> dict[str, Any] | None:
    """Who held a VPN-pool IP at a moment: the latest connect, if that user's disconnect didn't follow it.

    Pool IPs get reused, so only the time-specific answer is reliable.
    """
    moment = parse_ts(at)
    rows = _rows(
        """
        SELECT event_id, ts, "user" AS username, src_ip, country FROM log_vpn
        WHERE assigned_ip = ? AND action = 'connect' AND ts <= ?
        ORDER BY ts DESC LIMIT 1
        """,
        [ip, moment],
    )
    if not rows:
        return None
    session = rows[0]
    ended = _rows(
        """
        SELECT ts, event_id FROM log_vpn
        WHERE assigned_ip = ? AND action = 'disconnect' AND ts >= ? AND lower("user") = lower(?)
        ORDER BY ts LIMIT 1
        """,
        [ip, session["ts"], session["username"]],
    )
    if ended and ended[0]["ts"] < moment:
        return None
    return {
        "user": normalize_user(session["username"]),
        "connected_at": _iso(session["ts"]),
        "disconnected_at": _iso(ended[0]["ts"]) if ended else None,
        "src_ip": session["src_ip"],
        "country": session["country"],
        "connect_event_id": session["event_id"],
        "disconnect_event_id": ended[0]["event_id"] if ended else None,
    }


def resolve_ip(ip: str, at: str | datetime | None = None, hours: float = 1) -> dict[str, Any]:
    """Everything known about an IP: CMDB asset, zone, VPN holder, and hosts/users seen on it."""
    text = ip.strip()
    result: dict[str, Any] = {"ip": text, "asset": None, "zone": zone_for_ip(text), "vpn": None,
                              "observed": {"hosts": [], "users": []}, **get_intel(text)}
    result.pop("indicator")
    rows = _rows("SELECT hostname FROM assets WHERE ip = ? LIMIT 1", [text])
    if rows:
        result["asset"] = get_asset(rows[0]["hostname"])
    if at:
        result["vpn"] = vpn_session(text, at)
        start, end = window(at, hours)
        seen = _rows(
            """
            SELECT other.entity_type, other.entity_value, count(*) AS events
            FROM event_index i JOIN event_index other USING (event_id)
            WHERE i.entity_type = 'ip' AND i.entity_value = ? AND i.ts BETWEEN ? AND ?
              AND other.entity_type IN ('host', 'user')
            GROUP BY 1, 2 ORDER BY events DESC
            """,
            [text.lower(), start, end],
        )
        result["observed"] = {
            "hosts": [r["entity_value"] for r in seen if r["entity_type"] == "host"],
            "users": [r["entity_value"] for r in seen if r["entity_type"] == "user"],
        }
    return result


def _related_entities(
    source_type: str, target_type: str, key: str, start: str | datetime | None, end: str | datetime | None
) -> list[dict[str, Any]]:
    where, params = ["i.entity_type = ?", "i.entity_value = ?", "other.entity_type = ?"], [source_type, key, target_type]
    if start:
        where.append("i.ts >= ?")
        params.append(parse_ts(start))
    if end:
        where.append("i.ts <= ?")
        params.append(parse_ts(end))
    rows = _rows(
        f"""
        SELECT other.entity_value AS value, count(*) AS events, min(i.ts) AS first_seen, max(i.ts) AS last_seen
        FROM event_index i JOIN event_index other USING (event_id)
        WHERE {' AND '.join(where)}
        GROUP BY 1 ORDER BY events DESC
        """,
        params,
    )
    return [{**row, "first_seen": _iso(row["first_seen"]), "last_seen": _iso(row["last_seen"])} for row in rows]


def hosts_for_user(user: str, start: str | datetime | None = None, end: str | datetime | None = None) -> list[dict[str, Any]]:
    """Hosts that appear in the same log events as a user, with counts and first/last seen."""
    return _related_entities("user", "host", normalize_user(user), start, end)


def users_for_host(host: str, start: str | datetime | None = None, end: str | datetime | None = None) -> list[dict[str, Any]]:
    """Users that appear in the same log events as a host, with counts and first/last seen."""
    return _related_entities("host", "user", normalize_host(host), start, end)


def get_alert(alert_id: str) -> dict[str, Any] | None:
    rows = _rows("SELECT raw FROM alerts WHERE alert_id = ? LIMIT 1", [alert_id])
    return json.loads(rows[0]["raw"]) if rows else None


def alerts_for_entity(
    entity: str,
    entity_type: str | None = None,
    start: str | datetime | None = None,
    end: str | datetime | None = None,
    exclude_alert_id: str | None = None,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    """Other alerts naming an entity, in time order, for correlation. Matching follows `timeline()`.

    Alert times are `created_at`, which can be later than the events an alert describes.
    """
    kind = entity_type or detect_entity_type(entity)
    key = _index_key(entity, kind)
    where, params = ["e.entity_type = ?"], [kind]
    if kind == "domain":
        escaped = key.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        where.append(r"(e.entity_value = ? OR e.entity_value LIKE ? ESCAPE '\')")
        params += [key, "%." + escaped]
    else:
        where.append("e.entity_value = ?")
        params.append(key)
    if start:
        where.append("e.ts >= ?")
        params.append(parse_ts(start))
    if end:
        where.append("e.ts <= ?")
        params.append(parse_ts(end))
    if exclude_alert_id:
        where.append("e.alert_id <> ?")
        params.append(exclude_alert_id)
    rows = _rows(
        f"""
        SELECT DISTINCT a.alert_id, a.created_at, a.rule_id, a.rule_name, a.severity, a.ts
        FROM alert_entities e JOIN alerts a USING (alert_id)
        WHERE {' AND '.join(where)}
        ORDER BY a.ts, a.alert_id
        """,
        params,
    )
    capped = _clamp(limit)
    items = [{k: v for k, v in row.items() if k != "ts"} for row in rows[:capped]]
    return {"entity": key, "entity_type": kind, "count": len(items), "total": len(rows),
            "truncated": len(rows) > len(items), "items": items}


def get_alert_entities(alert_id: str) -> list[dict[str, str]]:
    """Normalized entities of a dataset alert, as stored by the loader."""
    return _rows("SELECT entity_type, entity_value FROM alert_entities WHERE alert_id = ? ORDER BY 1, 2", [alert_id])


def list_alerts(
    status: str = "new",
    start: str = "",
    end: str = "",
    rule_id: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Alert queue in file order. `start` and `end` compare against `created_at` as text, like the mock API."""
    where, params = ["status = ?"], [status]
    if rule_id:
        where.append("rule_id = ?")
        params.append(rule_id)
    if start:
        where.append("created_at >= ?")
        params.append(start)
    if end:
        where.append("created_at <= ?")
        params.append(end)
    condition = " AND ".join(where)
    total = _rows(f"SELECT count(*) AS n FROM alerts WHERE {condition}", params)[0]["n"]
    rows = _rows(f"SELECT raw FROM alerts WHERE {condition} ORDER BY rowid LIMIT ? OFFSET ?", params + [max(limit, 0), max(offset, 0)])
    return {"total": total, "items": [json.loads(row["raw"]) for row in rows]}
