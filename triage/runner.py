"""D4: full-queue runner. Resumable, parallel, rate-limited, with a call budget.

The runner does not know how to triage an alert. It is given a function `triage_fn(alert_id) -> dict`
(`triage_alert()` from C4) and calls it for every alert that needs an LLM call according to
cluster.py: representatives, outliers and individual alerts. Members of a cluster are filled in later
by propagation (D5).

Work is ordered so that a quota or budget that runs out loses the least important alerts:
critical and high severity first, rare/outlier alerts before cluster representatives.

Every ticket is validated and saved through triage/store.py (out/tickets.jsonl, or TARVIA_OUT), which is
what the console and the evaluation read. A ticket the store rejects counts as an error and is retried.
A ticket whose `model_info.status` is not "ok" (the LLM refused, returned invalid output or failed; see
CallMeta.model_info in llm.py) is saved, so a human sees it, but also counts as an error: it is retried on
the next run and it feeds the circuit breaker. Only successful AI answers are propagated to cluster members.
out/run_results.jsonl is only the attempt log (one line per attempt, with the raw ticket); a rerun skips
alerts that already succeeded.

After the run, `--propagate` spreads each representative's ticket to its cluster members (D5), saves those
tickets the same way and lists the members that need their own call in out/retriage.jsonl.

Usage:
    python -m triage.runner --plan                      # calls left and the time they need
    python -m triage.runner --run --fn triage.pipeline:triage_alert --workers 8 --max-calls 250
    python -m triage.runner --propagate
    python -m triage.runner --run --fn triage.pipeline:triage_alert --include-retriage
"""
import argparse
import importlib
import inspect
import json
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

from triage.cluster import load_clustered
from triage.propagate import DEFAULT_RECHECKS, propagate

OUT_DIR = Path(__file__).resolve().parent.parent / "out"
RESULTS_PATH = OUT_DIR / "run_results.jsonl"
RETRIAGE_PATH = OUT_DIR / "retriage.jsonl"

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
ROLE_RANK = {"individual": 0, "outlier": 1, "representative": 2}
# Stop when the provider keeps failing in a row: the quota is gone, retrying burns time.
MAX_CONSECUTIVE_ERRORS = 5
# Measured on the gateway (docs/prompts.md): median ~14 s per call with 8 workers and thinking off.
DEFAULT_WORKERS = 8
DEFAULT_LATENCY_S = 15.0


def estimate_minutes(calls, latency_s=DEFAULT_LATENCY_S, workers=DEFAULT_WORKERS, rpm=0):
    """(sequential, parallel) minutes for `calls` calls: latency decides, an rpm limit can only slow it down."""
    sequential = calls * latency_s / 60
    parallel = math.ceil(calls / max(1, workers)) * latency_s / 60
    if rpm:
        parallel = max(parallel, calls / rpm)
    return sequential, parallel


def resolve_triage_fn(fn):
    """Accept a triage function that takes an alert id or the alert itself (C4 may be either)."""
    params = list(inspect.signature(fn).parameters)
    if params and params[0] in ("alert", "alert_dict", "alert_json"):
        from triage import data

        def by_id(alert_id):
            alert = data.get_alert(alert_id)
            if alert is None:
                raise LookupError(f"alert {alert_id} not found")
            return fn(alert)

        return by_id
    return fn


def plan(clustered):
    """Alerts that need an LLM call, most important first (list of dicts)."""
    work = clustered[clustered["role"].isin(ROLE_RANK)].copy()
    work["_sev"] = work["severity"].map(SEVERITY_RANK).fillna(len(SEVERITY_RANK))
    work["_role"] = work["role"].map(ROLE_RANK)
    work = work.sort_values(["_sev", "_role", "created_at", "alert_id"])
    return work[["alert_id", "rule_id", "severity", "role", "cluster_id"]].to_dict("records")


def done_alert_ids(path):
    """Alert ids that already have a successful result."""
    if not Path(path).exists():
        return set()
    done = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            if record.get("status") == "ok":
                done.add(record["alert_id"])
    return done


class _RateLimiter:
    """At most `rpm` calls per minute across all threads."""

    def __init__(self, rpm):
        self.interval = 60.0 / rpm if rpm else 0.0
        self.next_at = 0.0
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            now = time.monotonic()
            start = max(now, self.next_at)
            self.next_at = start + self.interval
        if start > now:
            time.sleep(start - now)


def prepare_ticket(ticket, item):
    """Add the cluster fields the console and D5 need, without overwriting what the triage set."""
    ticket = dict(ticket)
    ticket.setdefault("alert_ids", [item["alert_id"]])
    ticket.setdefault("cluster_id", item.get("cluster_id"))
    ticket.setdefault("routing", "cluster" if item["role"] == "representative" else "deep_dive")
    return ticket


def run(items, triage_fn, results_path=RESULTS_PATH, workers=DEFAULT_WORKERS, rpm=0, max_calls=None, log=print,
        save_ticket=None):
    """Triage `items` with `triage_fn`; returns a dict of counts.

    save_ticket(ticket) stores each ticket (the CLI passes the store's); if it raises, e.g. the ticket
    is invalid, the alert counts as an error and is retried on the next run.

    Skips alerts already done in `results_path`, stops after `max_calls` new calls, and stops early
    after MAX_CONSECUTIVE_ERRORS failures in a row.
    """
    results_path = Path(results_path)
    results_path.parent.mkdir(parents=True, exist_ok=True)
    done = done_alert_ids(results_path)
    todo = [item for item in items if item["alert_id"] not in done]
    skipped = len(items) - len(todo)
    if max_calls is not None:
        todo = todo[:max_calls]

    limiter = _RateLimiter(rpm)
    lock = threading.Lock()
    state = {"ok": 0, "error": 0, "streak": 0, "stop": False}
    started = time.monotonic()

    def work(item):
        if state["stop"]:
            return
        limiter.wait()
        if state["stop"]:
            return
        t0 = time.monotonic()
        try:
            ticket = prepare_ticket(triage_fn(item["alert_id"]), item)
            if save_ticket:
                save_ticket(ticket)
            ai_status = (ticket.get("model_info") or {}).get("status", "ok")
            if ai_status == "ok":
                record = {"alert_id": item["alert_id"], "status": "ok", "ticket": ticket}
            else:
                reason = (ticket.get("model_info") or {}).get("error_kind") or ""
                record = {"alert_id": item["alert_id"], "status": "error", "error": f"ai_{ai_status} {reason}".strip(),
                          "ticket": ticket}
        except Exception as exc:  # one bad alert must not stop the run
            problems = getattr(exc, "problems", None)  # ValidationFailed from the store lists each issue
            record = {"alert_id": item["alert_id"], "status": "error", "error": (repr(exc) + str(problems or ""))[:800]}
        record.update(role=item["role"], cluster_id=item["cluster_id"], seconds=round(time.monotonic() - t0, 2))
        with lock:
            with open(results_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            state[record["status"]] += 1
            state["streak"] = 0 if record["status"] == "ok" else state["streak"] + 1
            if state["streak"] >= MAX_CONSECUTIVE_ERRORS:
                state["stop"] = True
            finished = state["ok"] + state["error"]
            if finished % 10 == 0 or finished == len(todo):
                log(f"  {finished}/{len(todo)} done, {state['error']} errors, {time.monotonic() - started:.0f}s")

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        list(pool.map(work, todo))

    return {
        "planned": len(items),
        "already_done": skipped,
        "attempted": state["ok"] + state["error"],
        "ok": state["ok"],
        "errors": state["error"],
        "stopped_early": state["stop"],
    }


def propagate_clusters(clustered, results_path=RESULTS_PATH, save_tickets=None, severity_fn=None,
                       rechecks=DEFAULT_RECHECKS):
    """Spread each successful representative ticket to its cluster members (D5).

    Returns (tickets, retriage): the tickets to save and the members that must be triaged on their own.
    """
    reps = {}
    for record in _read_jsonl(results_path):
        if record.get("status") == "ok" and record.get("role") == "representative":
            reps[record["cluster_id"]] = record["ticket"]
    members = clustered[clustered["role"] == "member"]
    patterns = clustered[clustered["role"] == "representative"].set_index("cluster_id")["pattern"]
    tickets, retriage = [], []
    for cluster_id, rep_ticket in reps.items():
        group = members[members["cluster_id"] == cluster_id]
        rep = {**rep_ticket, "_pattern": patterns.get(cluster_id)}
        out, back = propagate(rep, group[["alert_id", "pattern"]].to_dict("records"),
                              rechecks=rechecks, severity_fn=severity_fn)
        tickets += out
        retriage += back
    if save_tickets and tickets:
        save_tickets(tickets)
    return tickets, retriage


def _read_jsonl(path):
    if not Path(path).exists():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def retriage_items(clustered, path=RETRIAGE_PATH):
    """Members pulled out of their cluster, as individual work items."""
    wanted = {r["alert_id"] for r in _read_jsonl(path)}
    rows = clustered[clustered["alert_id"].isin(wanted)].copy()
    rows["role"] = "individual"
    return plan(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--plan", action="store_true", help="show the plan and the time it needs")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--propagate", action="store_true", help="spread representative tickets to cluster members")
    parser.add_argument("--include-retriage", action="store_true", help="also triage members pulled out of clusters")
    parser.add_argument("--fn", help="triage function as module:function, e.g. triage.pipeline:triage_alert")
    parser.add_argument("--rpm", type=float, default=0, help="requests per minute limit (0 = none)")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--latency", type=float, default=DEFAULT_LATENCY_S, help="seconds per call, for the estimate")
    parser.add_argument("--max-calls", type=int, default=None)
    parser.add_argument("--results", default=str(RESULTS_PATH))
    args = parser.parse_args()

    clustered = load_clustered()
    items = plan(clustered)
    if args.include_retriage:
        items += retriage_items(clustered)
    done = done_alert_ids(args.results)
    remaining = [i for i in items if i["alert_id"] not in done]
    counts = pd.Series([i["role"] for i in remaining]).value_counts().to_dict()
    print(f"{len(items)} LLM calls planned, {len(done)} done, {len(remaining)} remaining {counts}")
    sequential, parallel = estimate_minutes(len(remaining), args.latency, args.workers, args.rpm)
    print(f"~{args.latency:g} s per call: {sequential / 60:.1f} h sequential, about {parallel:.0f} min with "
          f"{args.workers} workers" + (f" and {args.rpm:g} requests/minute" if args.rpm else ""))
    if args.run:
        if not args.fn:
            parser.error("--run needs --fn module:function")
        from triage.store import default_store

        module, name = args.fn.split(":")
        summary = run(items, resolve_triage_fn(getattr(importlib.import_module(module), name)),
                      args.results, args.workers, args.rpm, args.max_calls,
                      save_ticket=default_store().save_ticket)
        print(summary)
    if args.propagate:
        from triage.store import default_store

        from triage.member_policy import MemberChecks
        from triage.propagate import changed_pattern

        checks = MemberChecks()  # real context re-checks and the policy engine's decision per member
        tickets, retriage = propagate_clusters(
            clustered, args.results, default_store().save_tickets,
            severity_fn=checks.decide, rechecks=(changed_pattern, checks.recheck))
        RETRIAGE_PATH.parent.mkdir(exist_ok=True)
        with open(RETRIAGE_PATH, "w", encoding="utf-8") as f:
            for item in retriage:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        print(f"{len(tickets)} tickets saved, {len(retriage)} members need their own triage ({RETRIAGE_PATH.name})")


if __name__ == "__main__":
    main()
