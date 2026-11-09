"""B3 runbook collectors: `collect(alert)` builds the EvidencePack for one alert.

Every alert gets the common checks (B2 context, inventory, intel, related alerts); then the collector for
its runbook answers that runbook's "Comprobaciones" (the organizers' runbooks, not included in this repository):

    full:  RB-01 email · RB-02 endpoint · RB-03 identity · RB-05 online store · RB-09 network
    light: RB-04 DLP · RB-06 cloud · RB-07 AI assistant · RB-08 OT · RB-10 CI/CD

Light collectors gather the key facts; the deep-dive agent (C5) can query further.

`for_llm(pack)` is the compact view the prompt builder (C2) sends to the model: same facts and the same
citable event ids, without the trace, duplicated context fields, empty inventory fields or the full
checks of changes that don't apply.
"""
from __future__ import annotations

import csv
from pathlib import Path
import copy
from typing import Any, Callable

from triage.collectors import email, endpoint, identity, light, network, web
from triage.collectors.base import Pack, common

ROOT = Path(__file__).resolve().parent.parent.parent
CATALOG = ROOT / "01_contexto" / "catalogo_casos_de_uso.csv"

with open(CATALOG, encoding="utf-8") as _f:
    RULE_RUNBOOK: dict[str, str] = {row["rule_id"]: row["runbook"] for row in csv.DictReader(_f)}

COLLECTORS: dict[str, Callable[[Pack], None]] = {
    "RB-01": email.collect,
    "RB-02": endpoint.collect,
    "RB-03": identity.collect,
    "RB-04": light.rb04_dlp,
    "RB-05": web.collect,
    "RB-06": light.rb06_cloud,
    "RB-07": light.rb07_ai,
    "RB-08": network.collect,
    "RB-09": network.collect,
    "RB-10": light.rb10_cicd,
}


ENTITY_LISTS = ("ips", "users", "hosts", "domains", "urls", "processes", "customers", "files")


def _normal_shape(alert: Any) -> dict[str, Any]:
    """Copy of a (possibly live, hand-written) alert with the container types the collectors expect:
    dict evidence and entities, list entity groups. Values are kept; only shapes are fixed."""
    alert = dict(alert) if isinstance(alert, dict) else {}
    if alert.get("evidence") is not None and not isinstance(alert["evidence"], dict):
        alert["evidence"] = {"texto": str(alert["evidence"])}
    ents = alert.get("entities")
    if not isinstance(ents, dict):
        alert["entities"] = {}
    else:
        fixed = {}
        for key, value in ents.items():
            if key not in ENTITY_LISTS:  # e.g. cloud (dict), ai_session (str): keep as they come
                fixed[key] = value
                continue
            items = value if isinstance(value, list) else [value] if value is not None else []
            if key == "processes":
                items = [p if isinstance(p, dict) else {"command_line": str(p)} for p in items]
            else:
                items = [v for v in items if isinstance(v, (str, dict))]
            fixed[key] = items
        alert["entities"] = fixed
    return alert


def collect(alert: dict[str, Any]) -> dict[str, Any]:
    """Build the EvidencePack for one alert (dataset or live)."""
    alert = _normal_shape(alert)
    pack = Pack(alert)
    try:
        common(pack)
    except Exception as exc:  # context/inventory/intel failing must not lose the pack either
        pack.find("común", f"las comprobaciones comunes fallaron ({type(exc).__name__}: {exc}); revisar a mano",
                  "triage.collectors", notable=True)
    runbook = alert.get("runbook") or RULE_RUNBOOK.get(alert.get("rule_id", ""))
    collector = COLLECTORS.get(runbook or "")
    if collector:
        try:
            collector(pack)
        except Exception as exc:  # never lose the pack because one runbook step failed
            pack.find(runbook, f"el colector falló ({type(exc).__name__}: {exc}); revisar a mano", "triage.collectors",
                      notable=True)
    else:
        pack.find("runbook", f"sin colector para el runbook {runbook!r} de la regla {alert.get('rule_id')}",
                  "triage.collectors", notable=True)
    return pack.to_dict()


# ---------------------------------------------------------------- compact view for the LLM

MAX_RELATED_ALERTS = 15
MAX_UNAPPLIED_CHANGES = 5
_EMPTY = ("", None, [], {})


def _compact(row: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if not any(v == e and type(v) is type(e) for e in _EMPTY)}


def _change_line(change: dict[str, Any]) -> dict[str, Any]:
    """A change that does not apply: id, title and the conditions it fails, without the passing checks."""
    failed = [f"{c.get('condition')}: {c.get('detail')}" for c in change.get("checks") or [] if c.get("ok") is False]
    return {"change_id": change.get("change_id"), "title": change.get("title"), "applies": False,
            "no_aplica_por": "; ".join(failed)[:240]}


def for_llm(pack: dict[str, Any]) -> dict[str, Any]:
    """Compact copy of an EvidencePack for the model (the input is not modified).

    Keeps every finding, the alert, entities, intel, flags and the changes that apply or may apply in
    full, so every citable event_id is still there. Drops the trace (console only), context fields that
    repeat the pack's own (alert_id, event times), empty inventory fields, the passing checks of changes
    that do NOT apply (only their id, title and why), and caps related alerts."""
    view = copy.deepcopy(pack)
    view.pop("trace", None)
    context = view.get("context") or {}
    for key in ("alert_id", "event_time", "event_time_local"):
        context.pop(key, None)
    changes = context.get("changes") or []
    applying = [c for c in changes if c.get("applies") is not False]
    unapplied = [_change_line(c) for c in changes if c.get("applies") is False]
    if changes:
        context["changes"] = applying + unapplied[:MAX_UNAPPLIED_CHANGES]
        if len(unapplied) > MAX_UNAPPLIED_CHANGES:
            context["changes_not_shown"] = len(unapplied) - MAX_UNAPPLIED_CHANGES
    inventory = view.get("inventory") or {}
    for key in ("assets", "identities"):
        if isinstance(inventory.get(key), list):
            inventory[key] = [_compact(r) if isinstance(r, dict) else r for r in inventory[key]]
    related = view.get("related_alerts") or []
    if len(related) > MAX_RELATED_ALERTS:
        view["related_alerts"] = related[:MAX_RELATED_ALERTS]
        view["related_alerts_not_shown"] = len(related) - MAX_RELATED_ALERTS
    return view
