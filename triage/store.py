"""Ticket and incident store shared by the pipeline, the UI and the evaluation.

Files live in `out/` (or `TARVIA_OUT`), one JSON object per line, append-only:
  tickets.jsonl    AI tickets; saving a ticket_id again replaces it when read
  incidents.jsonl  incidents; same rule, by incident_id
  reviews.jsonl    human reviews and action decisions, kept apart so a re-run can't erase them

Tickets from `load_tickets()` always carry `human_review` and `action_decisions` from reviews.jsonl.
Their `verdict` and `severity` stay what the AI concluded, which is what the evaluation scores; use
`effective()` for the values after any human override. Treat returned records as read-only.

Safe across threads and processes: writers take a lock file, and readers skip a half-written last line.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from jsonschema import Draft202012Validator

from triage.loader import ROOT

log = logging.getLogger(__name__)

TICKET_SCHEMA_PATH = ROOT / "01_contexto" / "ticket_salida.schema.json"
INCIDENT_SCHEMA_PATH = ROOT / "01_contexto" / "informe_incidente.schema.json"

VERDICTS = ("true_positive", "benign_true_positive", "false_positive", "needs_more_info")
SEVERITIES = ("informational", "low", "medium", "high", "critical")
REVIEW_STATUSES = ("accepted", "overridden")
ACTION_DECISIONS = ("approved", "rejected", "executed", "failed")
OVERRIDABLE = {"verdict": VERDICTS, "severity": SEVERITIES}

# Checks for the fields we add to the official ticket format (docs/design.md, data contracts). Only optional fields here.
_TICKET_EXTENSIONS = {
    "type": "object",
    "properties": {
        "alert_ids": {"minItems": 1},
        "rule_severity": {"type": "string"},
        "criticality": {"type": "object"},
        "severity_calc": {
            "type": "object",
            "properties": {"adjustments": {"type": "array", "items": {"type": "object"}}},
        },
        "sla_due": {"type": ["string", "null"]},
        "trace": {"type": "array", "items": {"type": "object"}},
        "injection_flags": {"type": "array"},
        "cluster_id": {"type": ["string", "null"]},
        "incident_id": {"type": ["string", "null"]},
        "routing": {"enum": ["cluster", "deep_dive", "live"]},
        "model_info": {"type": "object"},
        "human_review": {"type": "object"},
    },
}
# Grouped incidents (L2) only need these; the full report format applies once investigated (L3).
_GROUPED_INCIDENT = {
    "type": "object",
    "required": ["incident_id", "title", "alert_ids"],
    "properties": {
        "incident_id": {"type": "string"},
        "title": {"type": "string"},
        "alert_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1},
    },
}
INCIDENT_STAGES = ("grouped", "investigated")

_schema_lock = threading.Lock()
_validators: dict[str, list[Draft202012Validator]] = {}


class ValidationFailed(ValueError):
    """A record doesn't match its format. `problems` lists each issue."""

    def __init__(self, record_id: str, problems: list[str]):
        super().__init__(f"{record_id}: " + "; ".join(problems))
        self.record_id = record_id
        self.problems = problems


def _load_validators(key: str) -> list[Draft202012Validator]:
    # Loaded on first save, so reading results works even without the dataset folders.
    with _schema_lock:
        if key not in _validators:
            if key == "ticket":
                official = json.loads(TICKET_SCHEMA_PATH.read_text(encoding="utf-8"))
                _validators[key] = [Draft202012Validator(official), Draft202012Validator(_TICKET_EXTENSIONS)]
            elif key == "incident":
                official = json.loads(INCIDENT_SCHEMA_PATH.read_text(encoding="utf-8"))
                _validators[key] = [Draft202012Validator(official)]
            else:
                _validators[key] = [Draft202012Validator(_GROUPED_INCIDENT)]
        return _validators[key]


def _problems(record: Any, key: str) -> list[str]:
    problems = []
    for validator in _load_validators(key):
        for error in validator.iter_errors(record):
            where = ".".join(str(part) for part in error.absolute_path) or "(top level)"
            problems.append(f"{where}: {error.message[:200]}")
    return problems


def validate_ticket(ticket: Any) -> list[str]:
    """Return every format problem in a ticket; an empty list means it is valid."""
    return _problems(ticket, "ticket")


def validate_incident(incident: Any) -> list[str]:
    """Return every format problem in an incident, using the rules for its `stage`."""
    stage = incident.get("stage", "investigated") if isinstance(incident, dict) else "investigated"
    if stage not in INCIDENT_STAGES:
        return [f"stage: must be one of {INCIDENT_STAGES}, got {stage!r}"]
    return _problems(incident, "incident" if stage == "investigated" else "grouped_incident")


def _conclusion_fingerprint(ticket: dict[str, Any]) -> str:
    conclusion = f"{ticket.get('verdict')}|{ticket.get('severity')}"
    return hashlib.sha1(conclusion.encode("utf-8")).hexdigest()[:12]


@contextmanager
def _file_lock(path: Path, timeout: float = 15, stale_after: float = 30) -> Iterator[None]:
    """Hold a cross-process lock by creating a file; a lock left by a crashed writer expires."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            handle = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except (FileExistsError, PermissionError):
            # On Windows, a file being deleted by another writer raises PermissionError.
            try:
                if time.time() - path.stat().st_mtime > stale_after:
                    path.unlink(missing_ok=True)
                    continue
            except OSError:
                pass
            if time.monotonic() > deadline:
                raise TimeoutError(f"Timed out waiting for {path}") from None
            time.sleep(0.005)
    try:
        yield
    finally:
        os.close(handle)
        for _ in range(100):
            try:
                path.unlink(missing_ok=True)
                break
            except PermissionError:
                time.sleep(0.005)


class _JsonlLog:
    """Append-only JSONL file with an incremental read cache, so frequent reads stay cheap."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._offset = 0
        self._records: list[dict[str, Any]] = []
        self.skipped = 0
        # What the cached records were read from: file identity and its first bytes. A file rewritten
        # in place or swapped by `git pull` can be larger than the offset, so size alone can't tell.
        self._identity: tuple[int, int] | None = None
        self._head = b""

    _HEAD_BYTES = 256

    def _reset(self) -> None:
        self._offset, self._records, self.skipped = 0, [], 0
        self._identity, self._head = None, b""

    def append(self, records: Iterable[dict[str, Any]]) -> None:
        lines = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _file_lock(self.path.with_name(self.path.name + ".lock")):
            with open(self.path, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(lines)

    def read(self) -> list[dict[str, Any]]:
        with self._lock:
            try:
                stat = self.path.stat()
            except FileNotFoundError:
                self._reset()
                return self._records
            size, identity = stat.st_size, (stat.st_dev, stat.st_ino)
            if self._offset and (size < self._offset or identity != self._identity):
                self._reset()  # The file was replaced, so start again.
            if size > self._offset or self._offset:
                with open(self.path, "rb") as handle:
                    if self._offset and handle.read(len(self._head)) != self._head:
                        self._reset()  # Rewritten in place with different content.
                    handle.seek(self._offset)
                    chunk = handle.read()
                if not self._offset:
                    self._identity = identity
                    self._head = chunk[: self._HEAD_BYTES]
                # Stop at the last full line; a half-written line is picked up on a later read.
                complete = chunk[: chunk.rfind(b"\n") + 1]
                self._offset += len(complete)
                for line in complete.splitlines():
                    if not line.strip():
                        continue
                    try:
                        self._records.append(json.loads(line))
                    except ValueError:
                        self.skipped += 1
                        log.warning("Skipping a malformed line in %s: %r", self.path, line[:80])
            return self._records


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _require_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    return value.strip()


class Store:
    def __init__(self, root: str | Path | None = None):
        self.root = Path(root) if root else Path(os.environ.get("TARVIA_OUT", ROOT / "out"))
        self._tickets = _JsonlLog(self.root / "tickets.jsonl")
        self._incidents = _JsonlLog(self.root / "incidents.jsonl")
        self._reviews = _JsonlLog(self.root / "reviews.jsonl")

    # Tickets
    def save_ticket(self, ticket: dict[str, Any]) -> None:
        self.save_tickets([ticket])

    def save_tickets(self, tickets: Iterable[dict[str, Any]]) -> None:
        """Validate every ticket, then save them all; if any is invalid, nothing is saved."""
        batch = list(tickets)
        for ticket in batch:
            problems = validate_ticket(ticket)
            if problems:
                record_id = ticket.get("ticket_id", "(no ticket_id)") if isinstance(ticket, dict) else "(not an object)"
                raise ValidationFailed(str(record_id), problems)
        if batch:
            self._tickets.append(batch)

    def _raw_tickets(self) -> dict[str, dict[str, Any]]:
        return {ticket["ticket_id"]: ticket for ticket in self._tickets.read() if "ticket_id" in ticket}

    def load_tickets(self) -> list[dict[str, Any]]:
        """All tickets (latest version of each, first-saved order) with human decisions merged in."""
        reviews, actions = self._review_index()
        return [self._merge(ticket, reviews, actions) for ticket in self._raw_tickets().values()]

    def get_ticket(self, ticket_id: str) -> dict[str, Any] | None:
        ticket = self._raw_tickets().get(ticket_id)
        if ticket is None:
            return None
        reviews, actions = self._review_index()
        return self._merge(ticket, reviews, actions)

    def tickets_for_alert(self, alert_id: str) -> list[dict[str, Any]]:
        return [t for t in self.load_tickets() if alert_id in t.get("alert_ids", [])]

    def tickets_for_incident(self, incident_id: str) -> list[dict[str, Any]]:
        return [t for t in self.load_tickets() if t.get("incident_id") == incident_id]

    def coverage(self, alert_ids: Iterable[str]) -> dict[str, Any]:
        """Report which alerts have a ticket, to prove every alert was handled."""
        wanted = list(dict.fromkeys(alert_ids))
        covered = {alert for ticket in self._raw_tickets().values() for alert in ticket.get("alert_ids", [])}
        missing = [alert for alert in wanted if alert not in covered]
        return {"total": len(wanted), "covered": len(wanted) - len(missing), "missing": missing}

    # Incidents
    def save_incident(self, incident: dict[str, Any]) -> None:
        """Save an incident. Set `stage: "grouped"` while it only has alerts; default is the full report."""
        problems = validate_incident(incident)
        if problems:
            record_id = incident.get("incident_id", "(no incident_id)") if isinstance(incident, dict) else "(not an object)"
            raise ValidationFailed(str(record_id), problems)
        self._incidents.append([incident])

    def load_incidents(self) -> list[dict[str, Any]]:
        return list({i["incident_id"]: i for i in self._incidents.read() if "incident_id" in i}.values())

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        return next((i for i in self.load_incidents() if i["incident_id"] == incident_id), None)

    # Human decisions
    def record_review(
        self,
        ticket_id: str,
        status: str,
        reviewer: str,
        reason: str = "",
        override: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record a person accepting or overriding the AI's conclusion. Overrides need a reason."""
        ticket = self._raw_tickets().get(ticket_id)
        if ticket is None:
            raise KeyError(f"No ticket {ticket_id}")
        if status not in REVIEW_STATUSES:
            raise ValueError(f"status must be one of {REVIEW_STATUSES}")
        override = override or None
        if status == "accepted" and override:
            raise ValueError("An accepted review can't include an override")
        if status == "overridden":
            if not override:
                raise ValueError("An overridden review needs the new values")
            _require_text("reason", reason)
            for field, value in override.items():
                if field not in OVERRIDABLE:
                    raise ValueError(f"Can't override {field!r}; allowed: {sorted(OVERRIDABLE)}")
                if value not in OVERRIDABLE[field]:
                    raise ValueError(f"Invalid {field}: {value!r}")
        record = {
            "kind": "review", "ticket_id": ticket_id, "status": status,
            "reviewer": _require_text("reviewer", reviewer), "reason": reason, "override": override,
            "ai_conclusion": _conclusion_fingerprint(ticket), "timestamp": _utc_now(),
        }
        self._reviews.append([record])
        return record

    def record_action(
        self,
        ticket_id: str,
        action: str,
        target: str,
        decision: str,
        approver: str,
        reason: str = "",
        result: Any = None,
    ) -> dict[str, Any]:
        """Record a person's decision on a containment action, and its outcome. Never store tokens here."""
        if self._raw_tickets().get(ticket_id) is None:
            raise KeyError(f"No ticket {ticket_id}")
        if decision not in ACTION_DECISIONS:
            raise ValueError(f"decision must be one of {ACTION_DECISIONS}")
        if decision == "rejected":
            _require_text("reason", reason)
        record = {
            "kind": "action", "ticket_id": ticket_id, "action": _require_text("action", action),
            "target": _require_text("target", target), "decision": decision,
            "approver": _require_text("approver", approver), "reason": reason, "result": result,
            "timestamp": _utc_now(),
        }
        self._reviews.append([record])
        return record

    def review_history(self, ticket_id: str) -> list[dict[str, Any]]:
        """Every human decision on a ticket, oldest first, as an audit trail."""
        return [deepcopy(r) for r in self._reviews.read() if r.get("ticket_id") == ticket_id]

    def _review_index(self) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
        latest: dict[str, dict[str, Any]] = {}
        actions: dict[str, list[dict[str, Any]]] = {}
        for record in self._reviews.read():
            ticket_id = record.get("ticket_id")
            if record.get("kind") == "review":
                latest[ticket_id] = record
            elif record.get("kind") == "action":
                actions.setdefault(ticket_id, []).append(record)
        return latest, actions

    @staticmethod
    def _merge(ticket: dict[str, Any], reviews: dict[str, dict[str, Any]], actions: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
        merged = dict(ticket)
        review = reviews.get(ticket["ticket_id"])
        if review:
            merged["human_review"] = {
                "status": review["status"], "reviewer": review["reviewer"], "override": review["override"],
                "reason": review["reason"], "timestamp": review["timestamp"],
                # The AI's conclusion changed after this review, so a person should look again.
                "stale": review["ai_conclusion"] != _conclusion_fingerprint(ticket),
            }
        else:
            merged["human_review"] = {"status": "pending", "reviewer": None, "override": None, "reason": "",
                                      "timestamp": None, "stale": False}
        decisions = actions.get(ticket["ticket_id"], [])
        merged["action_decisions"] = decisions
        merged["executed_actions"] = list(ticket.get("executed_actions", [])) + [
            {"action": d["action"], "target": d["target"], "approver": d["approver"],
             "result": d["result"], "timestamp": d["timestamp"]}
            for d in decisions if d["decision"] == "executed"
        ]
        return merged

    def health(self) -> dict[str, Any]:
        """Counts, including malformed lines that were skipped, so problems stay visible."""
        tickets = self._raw_tickets()
        incidents = self.load_incidents()
        self._reviews.read()
        return {
            "root": str(self.root), "tickets": len(tickets), "incidents": len(incidents),
            "reviews": sum(1 for r in self._reviews.read() if r.get("kind") == "review"),
            "actions": sum(1 for r in self._reviews.read() if r.get("kind") == "action"),
            "skipped_lines": self._tickets.skipped + self._incidents.skipped + self._reviews.skipped,
        }


def effective(ticket: dict[str, Any]) -> dict[str, Any]:
    """Return a ticket's verdict and severity after any human override, plus who decided them."""
    review = ticket.get("human_review") or {}
    override = review.get("override") or {}
    return {
        "verdict": override.get("verdict", ticket.get("verdict")),
        "severity": override.get("severity", ticket.get("severity")),
        "decided_by": review.get("reviewer") if override else "ai",
    }


_default: Store | None = None
_default_lock = threading.Lock()


def default_store() -> Store:
    """The shared store for this process, using `out/` or `TARVIA_OUT`."""
    global _default
    with _default_lock:
        if _default is None:
            _default = Store()
        return _default
