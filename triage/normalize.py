"""Shared normalization helpers for identities, hosts, timestamps and asset patterns."""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

MADRID = ZoneInfo("Europe/Madrid")
INTERNAL_EMAIL_DOMAIN = "@tarvia.example"
OWN_DOMAIN = INTERNAL_EMAIL_DOMAIN[1:]

_USER_PREFIX = re.compile(r"^(tarvia|nt authority)\\")
_RANGE = re.compile(r"^(?P<stem>.*?)(?P<first>\d+)\.\.(?P<last>\d+)$")


def is_own_domain(domain: str) -> bool:
    """True for the company's domain and its subdomains. Lookalikes such as tarvia-sso.example don't count."""
    return domain == OWN_DOMAIN or domain.endswith("." + OWN_DOMAIN)


def normalize_user(value: str | None) -> str:
    r"""Reduce `TARVIA\x` and `x@tarvia.example` to `x`.

    Matching stays exact afterwards: `candela.ruiz` and `candela.ruiz2` are different people,
    and `adm.bclotet` is a different account from `bclotet`. External addresses stay whole.
    Keep in sync with `USER_SQL` in loader.py.
    """
    text = (value or "").strip().lower()
    text = _USER_PREFIX.sub("", text)
    if text.endswith(INTERNAL_EMAIL_DOMAIN):
        text = text[: -len(INTERNAL_EMAIL_DOMAIN)]
    return text


def normalize_host(value: str | None) -> str:
    return (value or "").strip().lower()


def is_ip(value: str | None) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def parse_ts(value: str | datetime | None) -> datetime | None:
    """Parse an ISO timestamp into a naive UTC datetime, the form stored in DuckDB.

    Values without an offset are taken as UTC, like all dataset timestamps.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def madrid_to_utc(local: str) -> datetime:
    """Convert a local `YYYY-MM-DD HH:MM` time (change windows) into naive UTC, handling DST."""
    parsed = datetime.strptime(local.strip(), "%Y-%m-%d %H:%M").replace(tzinfo=MADRID)
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def utc_to_madrid(value: str | datetime) -> datetime:
    """Convert a UTC time into timezone-aware Europe/Madrid local time."""
    return parse_ts(value).replace(tzinfo=timezone.utc).astimezone(MADRID)


def expand_members(text: str, hostnames: list[str]) -> list[tuple[str, str]]:
    """Split an inventory list such as `WEB-ECOM01..04, POS-T*, IdP en la nube`.

    Returns (member, kind) pairs. `kind` is "host" for CMDB hostnames and "other" for anything
    that doesn't resolve to one, which stays visible rather than being dropped.
    """
    by_lower = {h.lower(): h for h in hostnames}
    members: list[tuple[str, str]] = []
    for part in (p.strip() for p in (text or "").split(",")):
        if not part:
            continue
        expanded = _expand_one(part, by_lower)
        if expanded:
            members.extend((host, "host") for host in expanded)
        else:
            members.append((part, "other"))
    return members


def _expand_one(part: str, by_lower: dict[str, str]) -> list[str]:
    key = part.lower()
    if key in by_lower:
        return [by_lower[key]]
    match = _RANGE.match(part)
    if match:
        first, last = match["first"], match["last"]
        width = len(first)
        names = (f"{match['stem']}{n:0{width}d}".lower() for n in range(int(first), int(last) + 1))
        return [by_lower[n] for n in names if n in by_lower]
    if "*" in part:
        return [host for low, host in by_lower.items() if fnmatch.fnmatchcase(low, key)]
    return []
