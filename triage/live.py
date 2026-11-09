"""C7: live mode. Triage alerts the system has never seen (the defence's common alerts), one call each.

    ticket = triage_live({"alert_id": "ALR-…", "rule_id": "UC-…", …})   # a full alert (dict)
    ticket = triage_live("ALR-20261013-700001")                          # or an id from the dataset

The console's live page (ui/pages/live_triage.py, E4) calls `triage_live` for each alert a person pastes
or uploads and saves the ticket. From the command line (plan B for the defence, and to warm the cache):

    python -m triage.live alerts.jsonl                 # JSON object or array, JSONL, or ids; '-' = stdin
    python -m triage.live alerts.jsonl --workers 4     # several at once (each still one call)
    python -m triage.live ALR-20261013-700001 --no-save

A live alert goes through the same pipeline as the dataset (triage/pipeline.py). Live alerts can be
messier, so before that this module:
- fills what the policy needs and the alert lacks: severity from the rule catalog when missing or not
  a known level (Spanish names are understood), and drops a created_at nobody can read (the collectors
  then use the related events' time). Each change is written into the ticket's open_questions.
- fences free text in evidence fields the known list (triage/untrusted.py) doesn't name: an unseen
  alert may carry attacker text under a key we have never seen.
- keeps the alert as received in the ticket (`live_alert`), since it is not in the alert database.

The ticket is marked `routing: "live"`. Nothing is executed: containment stays in the console.
"""
from __future__ import annotations

import argparse
import copy
import csv
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from triage import policy
from triage.pipeline import triage_alert
from triage.untrusted import UNTRUSTED_EVIDENCE_KEYS

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "01_contexto" / "catalogo_casos_de_uso.csv"
NOTE = "Modo en directo: "
FREE_TEXT_MIN_CHARS = 40  # shorter strings without a line break are values (ids, IPs, actions), not prose
SEVERITY_ALIASES = {
    "info": "informational", "informativa": "informational", "informativo": "informational",
    "baja": "low", "media": "medium", "alta": "high", "crítica": "critical", "critica": "critical",
}
_ALERT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")  # same rule as the console's live page

with open(CATALOG, encoding="utf-8") as _f:
    RULES: dict[str, dict[str, str]] = {row["rule_id"]: row for row in csv.DictReader(_f)}


def _severity(value: Any) -> str | None:
    text = str(value).strip().casefold() if value is not None else ""
    text = SEVERITY_ALIASES.get(text, text)
    return text if text in policy.SEVERITIES else None


def _free_text_fields(evidence: Any) -> list[dict[str, str]]:
    """Top-level evidence strings that read like prose and aren't in the known untrusted list."""
    if not isinstance(evidence, dict):
        return []
    out = []
    for key, value in evidence.items():
        if key in UNTRUSTED_EVIDENCE_KEYS or not isinstance(value, str):
            continue
        text = value.strip()
        if "\n" in text or (len(text) >= FREE_TEXT_MIN_CHARS and " " in text):
            out.append({"field": f"evidence.{key}", "text": value})
    return out


def prepare(alert: dict[str, Any]) -> tuple[dict[str, Any], list[str], list[dict[str, str]]]:
    """(copy ready for the pipeline, notes for the analyst in Spanish, extra untrusted fields).
    The input is not modified."""
    if not isinstance(alert, dict):
        raise TypeError("una alerta en directo debe ser un objeto JSON")
    alert_id = alert.get("alert_id")
    if not isinstance(alert_id, str) or not _ALERT_ID.match(alert_id):
        raise ValueError("la alerta no trae un alert_id válido")
    ready = copy.deepcopy(alert)
    notes: list[str] = []
    rule_id = str(ready.get("rule_id") or "")
    rule = RULES.get(rule_id)
    if rule is None:
        notes.append(f"{NOTE}la regla {rule_id or '(sin rule_id)'} no está en el catálogo: se ha triado sin "
                     "especialista de runbook; revisa el veredicto con más cuidado.")

    severity = _severity(ready.get("severity"))
    if severity is None:
        base = _severity(rule.get("severidad_base")) if rule else None
        given = ready.get("severity")
        if base:
            notes.append(f"{NOTE}la alerta {'no traía severidad' if given in (None, '') else f'traía una severidad no reconocida ({given!r})'}: "
                         f"se ha usado la severidad base de la regla en el catálogo ({base}).")
        else:
            notes.append(f"{NOTE}sin severidad reconocible ni regla en el catálogo: la política ha usado «medium».")
        ready.pop("severity", None)
        severity = base
    if severity:
        ready["severity"] = severity

    created = ready.get("created_at")
    if created in (None, ""):
        ready.pop("created_at", None)
        notes.append(f"{NOTE}la alerta no traía hora (created_at): no hay plazo de SLA calculado.")
    elif policy.parse_utc(created) is None:
        ready.pop("created_at")
        notes.append(f"{NOTE}la hora de la alerta ({str(created)[:40]!r}) no se puede leer: no hay plazo de SLA calculado.")
    return ready, notes, _free_text_fields(ready.get("evidence"))


def triage_live(alert: dict[str, Any] | str) -> dict[str, Any]:
    """Triage one live alert (full alert or dataset id) and return its ticket. Does not save it."""
    if isinstance(alert, str):
        ticket = triage_alert(alert.strip())
        ticket["routing"] = "live"
        return ticket
    ready, notes, extra = prepare(alert)
    ticket = triage_alert(ready, extra_untrusted=extra)
    ticket["routing"] = "live"
    ticket["open_questions"] = list(ticket.get("open_questions") or []) + notes
    ticket["live_alert"] = copy.deepcopy(alert)
    return ticket


# ---------------------------------------------------------------- command line (plan B, cache warm-up)

def read_alerts(text: str) -> list[dict[str, Any] | str]:
    """A JSON object or array, JSONL, or alert ids separated by spaces, commas or lines."""
    text = text.strip().lstrip("﻿")
    if not text:
        return []
    try:
        whole = json.loads(text)
    except ValueError:
        items: list[Any] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            items.extend([json.loads(line)] if line.startswith("{") else [t for t in re.split(r"[\s,;]+", line) if t])
        return items
    return whole if isinstance(whole, list) else [whole]


def _label(item: dict[str, Any] | str) -> str:
    return item if isinstance(item, str) else str(item.get("alert_id", "(sin alert_id)"))


def run_cli(items: list[dict[str, Any] | str], workers: int = 1, save: bool = True, out: str | None = None,
            log=print) -> dict[str, int]:
    from triage.store import Store

    store = Store(out) if save else None
    counts = {"ok": 0, "no_ai": 0, "error": 0}

    def one(item):
        started = time.monotonic()
        try:
            ticket = triage_live(item)
            if store:
                store.save_ticket(ticket)
            status = "ok" if (ticket.get("model_info") or {}).get("status", "ok") == "ok" else "no_ai"
            line = (f"{status:5} {_label(item)}  {ticket['verdict']:20} {ticket['severity']:13} "
                    f"escalar={'sí' if ticket['escalation']['escalate'] else 'no'}")
        except Exception as error:  # one bad alert must not stop the batch
            status, line = "error", f"error {_label(item)}  {error.__class__.__name__}: {error}"[:300]
        return status, f"{line}  {time.monotonic() - started:.1f}s"

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for status, line in pool.map(one, items):
            counts[status] += 1
            log(line)
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="C7 live mode: triage alerts the system has never seen.")
    parser.add_argument("source", help="file with alerts (JSON, JSONL or ids), '-' for stdin, or alert ids", nargs="+")
    parser.add_argument("--workers", type=int, default=1, help="alerts triaged at once (default 1)")
    parser.add_argument("--no-save", action="store_true", help="print only; don't save tickets")
    parser.add_argument("--out", help="ticket folder (default TARVIA_OUT or out/)")
    args = parser.parse_args(argv)

    items: list[Any] = []
    for source in args.source:
        if source == "-":
            items += read_alerts(sys.stdin.read())
        elif Path(source).is_file():
            items += read_alerts(Path(source).read_text(encoding="utf-8-sig"))
        else:
            items += read_alerts(source)
    if not items:
        print("No alerts to triage.")
        return 1
    started = time.monotonic()
    counts = run_cli(items, args.workers, not args.no_save, args.out)
    print(f"\n{len(items)} alerts in {time.monotonic() - started:.0f}s: {counts['ok']} triaged, "
          f"{counts['no_ai']} without an AI answer (review by hand), {counts['error']} failed")
    return 0 if counts["error"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
