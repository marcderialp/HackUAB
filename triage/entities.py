"""Extract and normalize the entities in an alert. Deterministic, with no database or LLM.

Only structured fields are read. Free text (subjects, bodies, command lines, prompts) is
attacker-controlled and never parsed here. Values are validated by shape, and any that fail land in
`unparsed` rather than vanishing, so a person can still see them.

The function tolerates missing fields and alternate shapes, because live alerts may differ from the
dataset's.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from triage.normalize import INTERNAL_EMAIL_DOMAIN, is_ip, is_own_domain, normalize_user

_ACCOUNT = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_HOST = re.compile(r"^[a-z0-9][a-z0-9-]*$", re.IGNORECASE)
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_AGGREGATE = re.compile(r"^\((\d+) cuentas\)$")
_NOTE_SUFFIX = re.compile(r"\s+\(.*\)$")
_IP_RANGE = re.compile(r"^(?P<stem>(?:\d{1,3}\.){3})(?P<first>\d{1,3})-(?P<last>\d{1,3})$")

LIST_KEYS = ("users", "hosts", "ips", "domains", "emails", "hashes", "customers", "sessions", "message_ids",
             "access_keys", "buckets")
# entity_type names as used by event_index and data.timeline().
FLATTEN_TYPES = {
    "users": "user", "hosts": "host", "ips": "ip", "domains": "domain", "emails": "email", "hashes": "hash",
    "customers": "customer", "sessions": "session", "message_ids": "message_id",
    "access_keys": "access_key", "buckets": "bucket",
}

# Evidence fields holding one kind of entity. Others are facts about the alert, not entities.
_EVIDENCE_USERS = ("user", "reported_by", "account", "by", "member_added")
_EVIDENCE_HOSTS = ("from_host", "src", "dst")
_EVIDENCE_IPS = ("src_ip", "dst_ip", "created_from_ip", "submitted_from_ip")
_EVIDENCE_DOMAINS = ("domain", "parent_domain", "query", "new_email_domain")
_EVIDENCE_EMAILS = ("sender", "recipient")
_EVIDENCE_CUSTOMERS = ("requested_customer_id", "authenticated_customer_id")
_SYSTEM_ACCOUNTS = {"system"}


class _Collector:
    def __init__(self) -> None:
        self.values: dict[str, dict[str, None]] = {key: {} for key in LIST_KEYS}
        self.unparsed: list[dict[str, Any]] = []
        self.aggregate_accounts = 0
        self.system_account = False

    def add(self, key: str, value: str) -> None:
        self.values[key].setdefault(value)

    def reject(self, field: str, value: Any) -> None:
        self.unparsed.append({"field": field, "value": value})

    def user(self, field: str, value: Any) -> None:
        if not isinstance(value, str) or not value.strip():
            if value not in (None, ""):
                self.reject(field, value)
            return
        text = value.strip()
        aggregate = _AGGREGATE.match(text)
        if aggregate:  # A count of accounts, such as "(12 cuentas)", rather than an identity.
            self.aggregate_accounts += int(aggregate[1])
            return
        name = normalize_user(_NOTE_SUFFIX.sub("", text))
        if name in _SYSTEM_ACCOUNTS:
            self.system_account = True
        elif _ACCOUNT.match(name):
            self.add("users", name)
        elif _EMAIL.match(name):
            self.email(field, name)
        else:
            self.reject(field, value)

    def host(self, field: str, value: Any) -> None:
        text = value.strip() if isinstance(value, str) else ""
        if is_ip(text):
            self.add("ips", text)
        elif _HOST.match(text):
            self.add("hosts", text)
        elif value not in (None, ""):
            self.reject(field, value)

    def ip(self, field: str, value: Any) -> None:
        text = value.strip() if isinstance(value, str) else ""
        ip_range = _IP_RANGE.match(text)
        if is_ip(text):
            self.add("ips", text)
        elif ip_range and int(ip_range["first"]) <= int(ip_range["last"]) <= 255:
            # A last-octet range such as 10.40.16.21-26, so each machine can be looked up.
            for octet in range(int(ip_range["first"]), int(ip_range["last"]) + 1):
                self.add("ips", f"{ip_range['stem']}{octet}")
        elif value not in (None, ""):
            self.reject(field, value)

    def domain(self, field: str, value: Any) -> None:
        text = value.strip().lower().rstrip(".") if isinstance(value, str) else ""
        if _DOMAIN.match(text):
            # Our own domain says nothing about an attacker, and would link every web and mail alert.
            if not is_own_domain(text):
                self.add("domains", text)
        elif value not in (None, ""):
            self.reject(field, value)

    def email(self, field: str, value: Any) -> None:
        text = value.strip().lower() if isinstance(value, str) else ""
        if _EMAIL.match(text):
            self.add("emails", text)
            if not is_own_domain(text.rsplit("@", 1)[1]):
                self.add("domains", text.rsplit("@", 1)[1])
        elif value not in (None, ""):
            self.reject(field, value)

    def url(self, field: str, value: Any) -> None:
        try:
            host = urlsplit(value.strip()).hostname if isinstance(value, str) else None
        except ValueError:
            host = None
        if not host:
            if value not in (None, ""):
                self.reject(field, value)
        elif is_ip(host):
            self.add("ips", host)
        else:
            self.domain(field, host)

    def hash(self, field: str, value: Any) -> None:
        text = value.strip().lower() if isinstance(value, str) else ""
        if _SHA256.match(text):
            self.add("hashes", text)
        elif value not in (None, ""):
            self.reject(field, value)

    def token(self, key: str, value: Any) -> None:
        """Add an opaque identifier such as a session or customer ID."""
        if isinstance(value, (str, int)) and str(value).strip():
            self.add(key, str(value).strip())


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _dict_field(item: Any, key: str) -> Any:
    """Read `key` from a dict entry; a plain string entry is taken as the value itself."""
    return item.get(key) if isinstance(item, dict) else item


def extract_entities(alert: dict[str, Any]) -> dict[str, Any]:
    """Return an alert's entities as lists of strings, plus the details listed below.

    Users are normalized (`oriol.masdeu`), hosts keep their original case (`WS-BCN-2005`), domains are
    lowercase. Also returns:
      processes, files      entries from the alert, unmodified; command lines in them are untrusted
      aggregate_accounts    total from placeholders like "(12 cuentas)": accounts the alert doesn't name
      system_account        true if the local SYSTEM account was involved
      unparsed              structured values that failed validation, for a person to look at
    """
    entities = alert.get("entities") if isinstance(alert.get("entities"), dict) else {}
    evidence = alert.get("evidence") if isinstance(alert.get("evidence"), dict) else {}
    found = _Collector()

    for item in _as_list(entities.get("users")):
        found.user("entities.users", _dict_field(item, "upn"))
    for item in _as_list(entities.get("hosts")):
        found.host("entities.hosts", _dict_field(item, "hostname"))
        if isinstance(item, dict):
            found.ip("entities.hosts.ip", item.get("ip"))
    for value in _as_list(entities.get("ips")):
        found.ip("entities.ips", value)
    for value in _as_list(entities.get("domains")):
        found.domain("entities.domains", value)
    for value in _as_list(entities.get("urls")):
        found.url("entities.urls", value)
    for item in _as_list(entities.get("customers")):
        found.token("customers", _dict_field(item, "customer_id"))
    for item in _as_list(entities.get("files")):
        if isinstance(item, dict):
            found.hash("entities.files.sha256", item.get("sha256"))
    found.token("sessions", entities.get("ai_session"))

    cloud = entities.get("cloud") if isinstance(entities.get("cloud"), dict) else {}
    found.user("entities.cloud.identity", cloud.get("identity"))
    found.user("entities.cloud.new_user", cloud.get("new_user"))
    found.token("access_keys", cloud.get("access_key"))
    found.token("buckets", cloud.get("bucket"))

    for field in _EVIDENCE_USERS:
        found.user(f"evidence.{field}", evidence.get(field))
    for field in _EVIDENCE_HOSTS:
        found.host(f"evidence.{field}", evidence.get(field))
    for field in _EVIDENCE_IPS:
        found.ip(f"evidence.{field}", evidence.get(field))
    for field in _EVIDENCE_DOMAINS:
        found.domain(f"evidence.{field}", evidence.get(field))
    for field in _EVIDENCE_EMAILS:
        found.email(f"evidence.{field}", evidence.get(field))
    for field in _EVIDENCE_CUSTOMERS:
        found.token("customers", evidence.get(field))
    for field in ("previous_login", "current_login"):
        login = evidence.get(field)
        if isinstance(login, dict):
            found.ip(f"evidence.{field}.ip", login.get("ip"))
    found.token("message_ids", evidence.get("message_id"))
    found.token("sessions", evidence.get("session_id"))

    # `destination` holds a domain, an address, or a device name such as a USB model.
    destination = evidence.get("destination")
    if isinstance(destination, str) and "@" in destination:
        found.email("evidence.destination", destination)
    elif isinstance(destination, str) and " " not in destination.strip():
        found.domain("evidence.destination", destination)

    # Internal addresses in `sender`/`recipient` also identify directory users.
    for email in list(found.values["emails"]):
        if email.endswith(INTERNAL_EMAIL_DOMAIN):
            found.add("users", normalize_user(email))

    result: dict[str, Any] = {key: list(values) for key, values in found.values.items()}
    result["processes"] = [p for p in _as_list(entities.get("processes")) if isinstance(p, dict)]
    result["files"] = [f for f in _as_list(entities.get("files")) if isinstance(f, dict)]
    result["aggregate_accounts"] = found.aggregate_accounts
    result["system_account"] = found.system_account
    result["unparsed"] = found.unparsed
    return result


def flatten(entities: dict[str, Any]) -> list[tuple[str, str]]:
    """Return (entity_type, value) pairs in the normalized form used by event_index."""
    pairs = []
    for key, entity_type in FLATTEN_TYPES.items():
        for value in entities.get(key, []):
            pairs.append((entity_type, normalize_user(value) if entity_type == "user" else value.lower()))
    return pairs
