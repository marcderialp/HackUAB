"""E4 logic: read the alerts a person supplies and triage them one at a time. No Streamlit here.

The triage itself comes from C7. The function named by TARVIA_LIVE_FN (default
`triage.live:triage_live`) takes a full alert as a dict, or an alert id as a string, and returns a
ticket. Until it exists, the page says so: this module never produces a verdict of its own.
"""
from __future__ import annotations

import importlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from triage.store import Store, ValidationFailed

DEFAULT_LIVE_FN = "triage.live:triage_live"
MAX_ALERTS = 50
SECONDS_PER_ALERT = (10, 25)  # `ornith` with thinking off: median 11.5 s, p90 21.5 s (dev run, Sun 8 Nov)
# Ids reach the page's text, and pasted alerts can come from an attacker: letters, digits and separators only.
_ALERT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class LiveNotReady(RuntimeError):
    """The triage function can't be loaded yet."""


@dataclass
class ParsedInput:
    items: list[dict[str, Any]] = field(default_factory=list)  # {"alert_id": str, "payload": dict | str}
    problems: list[str] = field(default_factory=list)


def parse_input(text: str) -> ParsedInput:
    """Read a JSON object or array, JSONL, or alert ids. A bad entry is reported and the rest still run."""
    parsed = ParsedInput()
    text = text.strip().lstrip("﻿")
    if not text:
        return parsed
    try:
        whole = json.loads(text)
    except ValueError:
        _parse_lines(text, parsed)
    else:
        entries = whole if isinstance(whole, list) else [whole]
        for number, entry in enumerate(entries, 1):
            _add(entry, f"elemento {number}", parsed)
    if len(parsed.items) > MAX_ALERTS:
        parsed.problems.append(f"Máximo {MAX_ALERTS} alertas por tanda: se han descartado {len(parsed.items) - MAX_ALERTS}.")
        del parsed.items[MAX_ALERTS:]
    return parsed


def _parse_lines(text: str, parsed: ParsedInput) -> None:
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        where = f"línea {number}"
        if line.startswith(("{", "[", '"')):
            try:
                entry = json.loads(line)
            except ValueError:
                parsed.problems.append(f"{where}: JSON no válido.")
                continue
            _add(entry, where, parsed)
        else:
            for token in re.split(r"[\s,;]+", line):
                if token:
                    _add(token, where, parsed)


def _add(entry: Any, where: str, parsed: ParsedInput) -> None:
    if isinstance(entry, dict):
        alert_id = entry.get("alert_id")
    elif isinstance(entry, str):
        alert_id = entry.strip()
        entry = alert_id
    else:
        parsed.problems.append(f"{where}: no es una alerta ni un identificador.")
        return
    if not isinstance(alert_id, str) or not _ALERT_ID.match(alert_id):
        parsed.problems.append(f"{where}: falta un alert_id válido.")
    elif any(item["alert_id"] == alert_id for item in parsed.items):
        parsed.problems.append(f"{where}: {alert_id} está repetida; se usa la primera.")
    else:
        parsed.items.append({"alert_id": alert_id, "payload": entry})


def time_estimate(count: int) -> str:
    low, high = (count * seconds for seconds in SECONDS_PER_ALERT)
    if high < 120:
        return f"unos {low}–{high} segundos"
    return f"unos {round(low / 60)}–{round(high / 60)} minutos"


def load_triage_fn() -> Callable[[dict[str, Any] | str], dict[str, Any]]:
    spec = os.environ.get("TARVIA_LIVE_FN", DEFAULT_LIVE_FN)
    module, _, name = spec.partition(":")
    try:
        return getattr(importlib.import_module(module), name)
    except Exception as error:  # a broken module must leave the rest of the console usable
        raise LiveNotReady(f"{spec}: {error.__class__.__name__}: {error}") from error


def triage_one(item: dict[str, Any], triage_fn: Callable, store: Store) -> dict[str, Any]:
    """Triage and save one alert. Any failure stays on its own row, so the next alert still runs."""
    alert_id = item["alert_id"]
    result: dict[str, Any] = {"alert_id": alert_id, "status": "error", "ticket_id": None, "verdict": None,
                              "severity": None, "escalate": None, "error": ""}
    started = time.monotonic()
    try:
        ticket = triage_fn(item["payload"])
        if not isinstance(ticket, dict) or alert_id not in ticket.get("alert_ids", []):
            raise ValueError("el ticket devuelto no corresponde a esta alerta")
        store.save_ticket(ticket)
    except ValidationFailed as error:
        result["error"] = "Ticket con formato no válido: " + "; ".join(error.problems)[:300]
    except Exception as error:  # one bad alert must not stop the run in front of the jury
        result["error"] = f"{error.__class__.__name__}: {error}"[:300]
    else:
        info = ticket.get("model_info")
        model_failed = isinstance(info, dict) and info.get("status", "ok") != "ok"
        escalation = ticket.get("escalation")
        result.update(
            status="no_ai" if model_failed else "ok", ticket_id=ticket["ticket_id"], verdict=ticket["verdict"],
            severity=ticket["severity"], escalate=escalation.get("escalate") if isinstance(escalation, dict) else None,
        )
        if model_failed:
            result["error"] = f"La IA no respondió ({info.get('status')}): revisa este ticket a mano."
    result["seconds"] = round(time.monotonic() - started, 1)
    return result


class LiveRun:
    """One batch, worked through by one background thread.

    Streamlit starts a new pass of the page on every click while the old one may still be running, so
    triaging inside a pass could run an alert twice or lose its result. Here the pages only read.
    """

    def __init__(self, items: list[dict[str, Any]], triage_fn: Callable, store: Store):
        self.items = items
        self.results: list[dict[str, Any]] = []
        self._triage_fn = triage_fn
        self._store = store
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._work, daemon=True, name="live-triage")

    def _work(self) -> None:
        for item in self.items:
            if self._stop.is_set():
                return
            self.results.append(triage_one(item, self._triage_fn, self._store))

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        """Stop after the alert in progress, which still finishes and is recorded."""
        self._stop.set()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout)

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    @property
    def current_alert(self) -> str | None:
        done = len(self.results)
        return self.items[done]["alert_id"] if self.running and done < len(self.items) else None


# One batch per console, kept outside the browser session so a page reload can't lose it or start a second one.
_current: LiveRun | None = None
_current_lock = threading.Lock()


def current_run() -> LiveRun | None:
    return _current


def start_run(items: list[dict[str, Any]], triage_fn: Callable, store: Store) -> LiveRun:
    """Start a batch, unless one is already running; then that one is returned."""
    global _current
    with _current_lock:
        if _current is None or not _current.running:
            _current = LiveRun(items, triage_fn, store)
            _current.start()
        return _current


def clear_run() -> None:
    """Forget a finished batch. A running one is kept, so its progress stays visible."""
    global _current
    with _current_lock:
        if _current is not None and not _current.running:
            _current = None


def summarize(results: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "ok": sum(r["status"] == "ok" for r in results),
        "no_ai": sum(r["status"] == "no_ai" for r in results),
        "error": sum(r["status"] == "error" for r in results),
    }
