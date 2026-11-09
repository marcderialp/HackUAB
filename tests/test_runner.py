import json

import pandas as pd

from triage.runner import MAX_CONSECUTIVE_ERRORS, done_alert_ids, plan, run


def clustered():
    rows = [
        ("A1", "UC-X", "low", "representative", "UC-X:1"),
        ("A2", "UC-X", "low", "member", "UC-X:1"),
        ("A3", "UC-Y", "high", "outlier", None),
        ("A4", "UC-Z", "critical", "individual", None),
        ("A5", "UC-W", "high", "representative", "UC-W:1"),
    ]
    df = pd.DataFrame(rows, columns=["alert_id", "rule_id", "severity", "role", "cluster_id"])
    df["created_at"] = pd.date_range("2026-10-05", periods=len(df), freq="h", tz="UTC")
    return df


def test_plan_skips_members_and_orders_by_importance():
    ids = [item["alert_id"] for item in plan(clustered())]
    assert ids == ["A4", "A3", "A5", "A1"]  # critical, then high (outlier before representative), then low


def test_run_writes_results_and_resumes(tmp_path):
    path = tmp_path / "results.jsonl"
    items = plan(clustered())
    calls = []

    def triage(alert_id):
        calls.append(alert_id)
        return {"alert_id": alert_id}

    first = run(items, triage, path, workers=1, max_calls=2, log=lambda *_: None)
    assert first["ok"] == 2 and done_alert_ids(path) == {"A4", "A3"}
    second = run(items, triage, path, workers=1, log=lambda *_: None)
    assert second["already_done"] == 2 and second["ok"] == 2
    assert sorted(calls) == ["A1", "A3", "A4", "A5"]  # nothing was called twice


def test_failed_alerts_are_recorded_and_retried_on_rerun(tmp_path):
    path = tmp_path / "results.jsonl"
    items = plan(clustered())

    def flaky(alert_id):
        if alert_id == "A3":
            raise RuntimeError("quota")
        return {}

    result = run(items, flaky, path, workers=1, log=lambda *_: None)
    assert result["errors"] == 1 and result["ok"] == 3
    assert "A3" not in done_alert_ids(path)
    records = [json.loads(line) for line in open(path)]
    assert next(r for r in records if r["alert_id"] == "A3")["status"] == "error"


def test_run_stops_after_consecutive_errors(tmp_path):
    items = [
        {"alert_id": f"A{i}", "rule_id": "R", "severity": "low", "role": "outlier", "cluster_id": None}
        for i in range(MAX_CONSECUTIVE_ERRORS + 10)
    ]

    def always_fails(alert_id):
        raise RuntimeError("429")

    result = run(items, always_fails, tmp_path / "r.jsonl", workers=1, log=lambda *_: None)
    assert result["stopped_early"] and result["attempted"] == MAX_CONSECUTIVE_ERRORS


# --- saving through the store (the console and the evaluation read out/tickets.jsonl) ---

import json as _json
from pathlib import Path as _Path

from triage.runner import propagate_clusters, retriage_items
from triage.store import Store

EXAMPLE_TICKET = _json.loads((_Path(__file__).resolve().parent.parent / "01_contexto" / "ticket_ejemplo.json").read_text())


def valid_ticket(alert_id, ticket_id=None):
    return {**EXAMPLE_TICKET, "ticket_id": ticket_id or f"TKT-{alert_id}", "alert_ids": [alert_id]}


def item(alert_id, role="representative", cluster_id="UC-X:1"):
    return {"alert_id": alert_id, "rule_id": "UC-X", "severity": "low", "role": role, "cluster_id": cluster_id}


def test_run_saves_tickets_with_cluster_fields(tmp_path):
    saved = []
    run([item("A1"), item("A2", role="outlier", cluster_id=None)], lambda a: valid_ticket(a),
        tmp_path / "r.jsonl", workers=1, log=lambda *_: None, save_ticket=saved.append)
    by_alert = {t["alert_ids"][0]: t for t in saved}
    assert by_alert["A1"]["cluster_id"] == "UC-X:1" and by_alert["A1"]["routing"] == "cluster"
    assert by_alert["A2"]["cluster_id"] is None and by_alert["A2"]["routing"] == "deep_dive"


def test_ticket_rejected_by_the_store_is_an_error_and_retried(tmp_path):
    class Rejected(ValueError):
        problems = ["verdict: not one of the allowed values"]

    def reject(ticket):
        raise Rejected(ticket["ticket_id"])

    path = tmp_path / "r.jsonl"
    result = run([item("A1")], lambda a: valid_ticket(a), path, workers=1, log=lambda *_: None, save_ticket=reject)
    assert result["errors"] == 1 and "A1" not in done_alert_ids(path)
    assert "verdict" in _json.loads(path.read_text())["error"]


def test_run_through_the_real_store_reaches_tickets_jsonl(tmp_path):
    store = Store(tmp_path / "out")
    run([item("A1")], lambda a: valid_ticket(a), tmp_path / "r.jsonl", workers=1,
        log=lambda *_: None, save_ticket=store.save_ticket)
    assert (tmp_path / "out" / "tickets.jsonl").exists()
    [ticket] = store.load_tickets()
    assert ticket["alert_ids"] == ["A1"] and ticket["cluster_id"] == "UC-X:1"


def clustered_with_members():
    rows = [
        ("A1", "representative", "UC-X:1", "p"),
        ("A2", "member", "UC-X:1", "p"),
        ("A3", "member", "UC-X:1", "p"),
        ("A4", "member", "UC-X:1", "different"),  # fails the pattern re-check
    ]
    return pd.DataFrame(rows, columns=["alert_id", "role", "cluster_id", "pattern"])


def test_propagate_clusters_covers_members_and_lists_the_rest(tmp_path):
    results = tmp_path / "r.jsonl"
    run([item("A1")], lambda a: valid_ticket(a), results, workers=1, log=lambda *_: None)
    saved = []
    tickets, retriage = propagate_clusters(clustered_with_members(), results, saved.extend)
    assert saved == tickets and len(tickets) == 1
    assert tickets[0]["alert_ids"] == ["A1", "A2", "A3"]
    assert [m["alert_id"] for m in retriage] == ["A4"]


def test_propagation_into_the_real_store_replaces_the_representative_ticket(tmp_path):
    store = Store(tmp_path / "out")
    results = tmp_path / "r.jsonl"
    run([item("A1")], lambda a: valid_ticket(a), results, workers=1, log=lambda *_: None, save_ticket=store.save_ticket)
    propagate_clusters(clustered_with_members(), results, store.save_tickets)
    [ticket] = store.load_tickets()  # same ticket_id: the later save replaces the earlier one
    assert ticket["alert_ids"] == ["A1", "A2", "A3"]


def test_retriage_items_become_individual_work(tmp_path):
    path = tmp_path / "retriage.jsonl"
    path.write_text(_json.dumps({"alert_id": "A4"}) + "\n")
    df = clustered_with_members().assign(
        rule_id="UC-X", severity="low", created_at=pd.Timestamp("2026-10-05", tz="UTC")
    )
    assert [i["alert_id"] for i in retriage_items(df, path)] == ["A4"]
    assert retriage_items(df, path)[0]["role"] == "individual"


# --- AI failures count as errors even when the pipeline returns a fallback ticket ---

def failed_ai_ticket(alert_id, status="error"):
    return {**valid_ticket(alert_id), "verdict": "needs_more_info", "model_info": {"status": status, "error_kind": "rate_limited"}}


def test_ticket_from_a_failed_ai_call_is_saved_but_counts_as_an_error(tmp_path):
    saved = []
    path = tmp_path / "r.jsonl"
    result = run([item("A1")], lambda a: failed_ai_ticket(a), path, workers=1, log=lambda *_: None, save_ticket=saved.append)
    assert len(saved) == 1  # the human still sees it
    assert result["errors"] == 1 and result["ok"] == 0
    assert "A1" not in done_alert_ids(path)  # retried on the next run
    assert "rate_limited" in _json.loads(path.read_text())["error"]


def test_successful_ai_status_and_missing_status_are_ok(tmp_path):
    ok_ticket = {**valid_ticket("A1"), "model_info": {"status": "ok"}}
    result = run([item("A1"), item("A2")], lambda a: ok_ticket if a == "A1" else valid_ticket(a),
                 tmp_path / "r.jsonl", workers=1, log=lambda *_: None)
    assert result["ok"] == 2


def test_repeated_ai_failures_trip_the_circuit_breaker(tmp_path):
    items = [item(f"A{i}", role="outlier", cluster_id=None) for i in range(MAX_CONSECUTIVE_ERRORS + 8)]
    result = run(items, lambda a: failed_ai_ticket(a, "refusal"), tmp_path / "r.jsonl", workers=1, log=lambda *_: None)
    assert result["stopped_early"] and result["attempted"] == MAX_CONSECUTIVE_ERRORS


def test_failed_representative_is_not_propagated(tmp_path):
    results = tmp_path / "r.jsonl"
    run([item("A1")], lambda a: failed_ai_ticket(a), results, workers=1, log=lambda *_: None)
    tickets, retriage = propagate_clusters(clustered_with_members(), results)
    assert tickets == [] and retriage == []


# --- ready for C4: latency-based estimate, 8 workers, alert-id or alert-dict triage functions ---

from triage.runner import DEFAULT_WORKERS, estimate_minutes, resolve_triage_fn


def test_estimate_uses_latency_and_workers_not_requests_per_minute():
    sequential, parallel = estimate_minutes(215, latency_s=15, workers=8)
    assert round(sequential / 60, 1) == 0.9  # ~54 min sequential
    assert 6 <= parallel <= 7  # 27 rounds of ~15 s: about 7 min, the PDF's "5-10 minutes"
    assert estimate_minutes(215, 15, 8, rpm=10)[1] == 21.5  # a request limit can only slow it down
    assert estimate_minutes(215, 15, 1)[1] == estimate_minutes(215, 15, 1)[0]  # one worker = sequential


def test_default_is_eight_workers():
    assert DEFAULT_WORKERS == 8


def test_resolve_passes_an_alert_id_through_when_the_function_takes_one():
    def triage_alert(alert_id):
        return alert_id

    assert resolve_triage_fn(triage_alert)("ALR-1") == "ALR-1"


def test_resolve_loads_the_alert_when_the_function_takes_an_alert(monkeypatch):
    from triage import data

    monkeypatch.setattr(data, "get_alert", lambda alert_id: {"alert_id": alert_id, "rule_id": "UC-X"})

    def triage_alert(alert):
        return alert["rule_id"]

    assert resolve_triage_fn(triage_alert)("ALR-1") == "UC-X"
    monkeypatch.setattr(data, "get_alert", lambda alert_id: None)
    try:
        resolve_triage_fn(triage_alert)("ALR-404")
        assert False, "a missing alert must raise so the runner records an error"
    except LookupError:
        pass
