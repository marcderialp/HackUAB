import json
import subprocess
import sys
import threading
import time

import pytest

from triage.loader import ROOT
from triage.store import ValidationFailed, Store, effective, validate_incident, validate_ticket


def make_ticket(ticket_id="TKT-1", **extra):
    ticket = {
        "ticket_id": ticket_id,
        "alert_ids": ["ALR-1"],
        "title": "Título",
        "verdict": "true_positive",
        "confidence": 0.9,
        "severity": "high",
        "summary": "Resumen con acentos: acción, señal.",
        "evidence": [],
        "recommended_actions": [],
        "escalation": {"escalate": False},
    }
    ticket.update(extra)
    return ticket


FULL_INCIDENT = {
    "incident_id": "INC-1", "title": "T", "alert_ids": ["ALR-1"], "patient_zero": "x", "initial_access": "y",
    "timeline": [], "scope": {}, "root_cause": "z", "containment_plan": [],
}


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path)


def test_official_example_ticket_is_valid_and_round_trips(store):
    example = json.loads((ROOT / "01_contexto" / "ticket_ejemplo.json").read_text(encoding="utf-8"))
    assert validate_ticket(example) == []
    store.save_ticket(example)
    loaded = store.get_ticket(example["ticket_id"])
    assert {k: loaded[k] for k in example if k != "executed_actions"} == {k: example[k] for k in example if k != "executed_actions"}


@pytest.mark.parametrize(
    "change",
    [
        {"verdict": "maybe"},
        {"severity": "urgent"},
        {"confidence": 1.5},
        {"alert_ids": []},
        {"routing": "guess"},
        {"recommended_actions": [{"action": "x"}]},
        {"escalation": {}},
    ],
)
def test_invalid_tickets_are_rejected_with_details(store, change):
    with pytest.raises(ValidationFailed) as error:
        store.save_ticket(make_ticket(**change))
    assert error.value.record_id == "TKT-1" and error.value.problems
    assert store.load_tickets() == []


def test_missing_required_field_is_rejected(store):
    ticket = make_ticket()
    del ticket["summary"]
    with pytest.raises(ValidationFailed):
        store.save_ticket(ticket)


def test_one_bad_ticket_saves_nothing_from_the_batch(store):
    with pytest.raises(ValidationFailed):
        store.save_tickets([make_ticket("TKT-1"), make_ticket("TKT-2", verdict="nope")])
    assert store.load_tickets() == []


def test_saving_again_replaces_and_keeps_position(store):
    store.save_tickets([make_ticket("TKT-1"), make_ticket("TKT-2")])
    store.save_ticket(make_ticket("TKT-1", title="Nuevo"))
    tickets = store.load_tickets()
    assert [t["ticket_id"] for t in tickets] == ["TKT-1", "TKT-2"]
    assert tickets[0]["title"] == "Nuevo"


def test_new_ticket_is_pending_review(store):
    store.save_ticket(make_ticket())
    review = store.get_ticket("TKT-1")["human_review"]
    assert review["status"] == "pending" and review["stale"] is False


def test_accent_text_survives(store):
    store.save_ticket(make_ticket())
    assert "acción" in Store(store.root).get_ticket("TKT-1")["summary"]


def test_empty_store_is_fine(store):
    assert store.load_tickets() == [] and store.load_incidents() == []
    assert store.get_ticket("x") is None and store.health()["tickets"] == 0


def test_lookups_by_alert_incident_and_coverage(store):
    store.save_tickets([
        make_ticket("TKT-1", alert_ids=["A", "B"], incident_id="INC-1"),
        make_ticket("TKT-2", alert_ids=["B"]),
    ])
    assert [t["ticket_id"] for t in store.tickets_for_alert("B")] == ["TKT-1", "TKT-2"]
    assert [t["ticket_id"] for t in store.tickets_for_incident("INC-1")] == ["TKT-1"]
    assert store.coverage(["A", "B", "C", "C"]) == {"total": 3, "covered": 2, "missing": ["C"]}


# Human decisions
def test_review_survives_a_rerun_of_the_pipeline(store):
    store.save_ticket(make_ticket())
    store.record_review("TKT-1", "accepted", "Ana")
    store.save_ticket(make_ticket())
    review = store.get_ticket("TKT-1")["human_review"]
    assert review["status"] == "accepted" and review["reviewer"] == "Ana" and review["stale"] is False


def test_review_goes_stale_when_the_ai_conclusion_changes(store):
    store.save_ticket(make_ticket())
    store.record_review("TKT-1", "accepted", "Ana")
    store.save_ticket(make_ticket(severity="critical"))
    assert store.get_ticket("TKT-1")["human_review"]["stale"] is True


def test_override_keeps_ai_values_for_evaluation(store):
    store.save_ticket(make_ticket())
    store.record_review("TKT-1", "overridden", "Ana", reason="Cambio aprobado", override={"verdict": "benign_true_positive", "severity": "low"})
    ticket = store.get_ticket("TKT-1")
    assert ticket["verdict"] == "true_positive" and ticket["severity"] == "high"
    assert effective(ticket) == {"verdict": "benign_true_positive", "severity": "low", "decided_by": "Ana"}


def test_effective_defaults_to_the_ai(store):
    store.save_ticket(make_ticket())
    assert effective(store.get_ticket("TKT-1")) == {"verdict": "true_positive", "severity": "high", "decided_by": "ai"}
    store.record_review("TKT-1", "accepted", "Ana")
    assert effective(store.get_ticket("TKT-1"))["decided_by"] == "ai"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status": "maybe", "reviewer": "Ana"},
        {"status": "accepted", "reviewer": "  "},
        {"status": "accepted", "reviewer": "Ana", "override": {"verdict": "false_positive"}},
        {"status": "overridden", "reviewer": "Ana", "reason": "x"},
        {"status": "overridden", "reviewer": "Ana", "override": {"verdict": "false_positive"}},
        {"status": "overridden", "reviewer": "Ana", "reason": "x", "override": {"verdict": "nope"}},
        {"status": "overridden", "reviewer": "Ana", "reason": "x", "override": {"title": "y"}},
    ],
)
def test_bad_reviews_are_rejected(store, kwargs):
    store.save_ticket(make_ticket())
    with pytest.raises(ValueError):
        store.record_review("TKT-1", **kwargs)
    assert store.review_history("TKT-1") == []


def test_cannot_review_a_missing_ticket(store):
    with pytest.raises(KeyError):
        store.record_review("NOPE", "accepted", "Ana")
    with pytest.raises(KeyError):
        store.record_action("NOPE", "isolate_host", "H", "approved", "Ana")


def test_action_decisions_and_executed_actions(store):
    store.save_ticket(make_ticket(executed_actions=[{"action": "earlier"}]))
    store.record_action("TKT-1", "isolate_host", "H1", "approved", "Ana")
    store.record_action("TKT-1", "isolate_host", "H1", "executed", "Ana", result={"result": "ok (simulado)"})
    store.record_action("TKT-1", "disable_user", "u1", "rejected", "Ana", reason="Falso positivo")
    ticket = store.get_ticket("TKT-1")
    assert [d["decision"] for d in ticket["action_decisions"]] == ["approved", "executed", "rejected"]
    assert [a["action"] for a in ticket["executed_actions"]] == ["earlier", "isolate_host"]
    assert ticket["executed_actions"][1]["approver"] == "Ana"
    assert validate_ticket(ticket) == []


def test_action_rules(store):
    store.save_ticket(make_ticket())
    with pytest.raises(ValueError):
        store.record_action("TKT-1", "isolate_host", "H", "rejected", "Ana")
    with pytest.raises(ValueError):
        store.record_action("TKT-1", "isolate_host", "H", "approved", " ")
    with pytest.raises(ValueError):
        store.record_action("TKT-1", "isolate_host", "H", "maybe", "Ana")


def test_review_history_is_an_audit_trail(store):
    store.save_ticket(make_ticket())
    store.record_review("TKT-1", "accepted", "Ana")
    store.record_review("TKT-1", "overridden", "Luis", reason="r", override={"severity": "low"})
    history = store.review_history("TKT-1")
    assert [h["reviewer"] for h in history] == ["Ana", "Luis"]
    assert store.get_ticket("TKT-1")["human_review"]["reviewer"] == "Luis"
    assert all(h["timestamp"].endswith("Z") for h in history)


def test_decisions_are_stored_apart_from_tickets(store):
    store.save_ticket(make_ticket())
    store.record_review("TKT-1", "accepted", "Ana")
    assert "Ana" not in (store.root / "tickets.jsonl").read_text(encoding="utf-8")


# Incidents
def test_full_incident_needs_every_report_field(store):
    assert validate_incident(FULL_INCIDENT) == []
    store.save_incident(FULL_INCIDENT)
    partial = {k: v for k, v in FULL_INCIDENT.items() if k != "root_cause"}
    with pytest.raises(ValidationFailed):
        store.save_incident(partial)


def test_grouped_incident_only_needs_its_alerts(store):
    grouped = {"incident_id": "INC-2", "stage": "grouped", "title": "T", "alert_ids": ["A"]}
    store.save_incident(grouped)
    assert store.get_incident("INC-2")["title"] == "T"
    with pytest.raises(ValidationFailed):
        store.save_incident({**grouped, "alert_ids": []})
    with pytest.raises(ValidationFailed):
        store.save_incident({**grouped, "stage": "draft"})


def test_grouped_incident_can_be_upgraded_to_a_report(store):
    store.save_incident({"incident_id": "INC-1", "stage": "grouped", "title": "T", "alert_ids": ["A"]})
    store.save_incident({**FULL_INCIDENT, "stage": "investigated"})
    assert len(store.load_incidents()) == 1 and store.get_incident("INC-1")["patient_zero"] == "x"


# Damaged files and concurrency
def test_half_written_last_line_is_ignored_then_picked_up(store):
    store.save_ticket(make_ticket("TKT-1"))
    line = json.dumps(make_ticket("TKT-2"), ensure_ascii=False)
    path = store.root / "tickets.jsonl"
    with open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(line[:40])
    assert [t["ticket_id"] for t in store.load_tickets()] == ["TKT-1"]
    assert store.health()["skipped_lines"] == 0
    with open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(line[40:] + "\n")
    assert [t["ticket_id"] for t in store.load_tickets()] == ["TKT-1", "TKT-2"]


def test_malformed_line_is_skipped_and_reported(store):
    store.save_ticket(make_ticket("TKT-1"))
    path = store.root / "tickets.jsonl"
    with open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write("{not json}\n")
    store.save_ticket(make_ticket("TKT-2"))
    assert len(store.load_tickets()) == 2
    assert store.health()["skipped_lines"] == 1


def test_reader_sees_writes_from_another_store_instance(store):
    reader = Store(store.root)
    assert reader.load_tickets() == []
    store.save_ticket(make_ticket("TKT-1"))
    assert len(reader.load_tickets()) == 1
    store.save_ticket(make_ticket("TKT-2"))
    assert len(reader.load_tickets()) == 2


def test_replaced_file_is_read_from_the_start(store):
    store.save_tickets([make_ticket("TKT-1"), make_ticket("TKT-2")])
    assert len(store.load_tickets()) == 2
    (store.root / "tickets.jsonl").unlink()
    assert store.load_tickets() == []
    store.save_ticket(make_ticket("TKT-3"))
    assert [t["ticket_id"] for t in store.load_tickets()] == ["TKT-3"]


def _jsonl(*tickets) -> str:
    import json

    return "".join(json.dumps(t, ensure_ascii=False) + "\n" for t in tickets)


def test_file_rewritten_in_place_with_more_tickets_is_read_from_the_start(store):
    store.save_tickets([make_ticket("TKT-1")])
    assert [t["ticket_id"] for t in store.load_tickets()] == ["TKT-1"]
    path = store.root / "tickets.jsonl"
    path.write_text(_jsonl(make_ticket("TKT-A"), make_ticket("TKT-B"), make_ticket("TKT-C")), encoding="utf-8")
    assert [t["ticket_id"] for t in store.load_tickets()] == ["TKT-A", "TKT-B", "TKT-C"]
    assert store.health()["skipped_lines"] == 0


def test_file_swapped_for_a_bigger_one_is_read_from_the_start(store):
    import os

    store.save_tickets([make_ticket("TKT-1")])
    assert len(store.load_tickets()) == 1
    path = store.root / "tickets.jsonl"
    new = store.root / "tickets.new"
    new.write_text(_jsonl(make_ticket("TKT-NEW-1"), make_ticket("TKT-2"), make_ticket("TKT-3")), encoding="utf-8")
    os.replace(new, path)  # how git pull and most tools replace a file
    assert [t["ticket_id"] for t in store.load_tickets()] == ["TKT-NEW-1", "TKT-2", "TKT-3"]
    assert store.health()["skipped_lines"] == 0


def test_appends_after_a_reload_are_still_read_once(store):
    store.save_tickets([make_ticket("TKT-1")])
    store.load_tickets()
    store.save_ticket(make_ticket("TKT-2"))
    store.save_ticket(make_ticket("TKT-3"))
    assert [t["ticket_id"] for t in store.load_tickets()] == ["TKT-1", "TKT-2", "TKT-3"]
    assert [t["ticket_id"] for t in store.load_tickets()] == ["TKT-1", "TKT-2", "TKT-3"]


def test_stale_lock_from_a_crashed_writer_expires(store):
    import os

    store.root.mkdir(exist_ok=True)
    lock = store.root / "tickets.jsonl.lock"
    lock.write_text("")
    old = time.time() - 120
    os.utime(lock, (old, old))
    store.save_ticket(make_ticket())
    assert store.get_ticket("TKT-1") is not None and not lock.exists()


def test_many_threads_writing_lose_nothing(store):
    def write(worker):
        for n in range(50):
            store.save_ticket(make_ticket(f"TKT-{worker}-{n}"))

    threads = [threading.Thread(target=write, args=(w,)) for w in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(store.load_tickets()) == 400
    assert store.health()["skipped_lines"] == 0


WRITER = """
import sys
sys.path.insert(0, sys.argv[1])
from triage.store import Store
from tests.test_store import make_ticket
store = Store(sys.argv[2])
for n in range(100):
    store.save_ticket(make_ticket(f"TKT-{sys.argv[3]}-{n}", title="x" * 3000))
"""


def test_many_processes_writing_while_reading_lose_nothing(store):
    store.root.mkdir(exist_ok=True)
    processes = [
        subprocess.Popen([sys.executable, "-c", WRITER, str(ROOT), str(store.root), str(w)])
        for w in range(4)
    ]
    reads = 0
    while any(p.poll() is None for p in processes):
        store.load_tickets()
        reads += 1
    assert all(p.returncode == 0 for p in processes)
    assert len(store.load_tickets()) == 400
    assert store.health()["skipped_lines"] == 0
    assert reads > 0


def test_loading_a_full_run_is_fast_and_incremental(store, monkeypatch):
    tickets = [make_ticket(f"TKT-{n}", summary="x" * 2000, alert_ids=[f"ALR-{n}"]) for n in range(11061)]
    store.save_tickets(tickets)

    parsed = []
    real_loads = json.loads
    monkeypatch.setattr("triage.store.json.loads", lambda text: (parsed.append(1), real_loads(text))[1])

    started = time.perf_counter()
    assert len(store.load_tickets()) == 11061
    first = time.perf_counter() - started
    assert first < 2
    assert len(parsed) == 11061

    # A reload must read only what's new, so the console stays fast during a long run.
    parsed.clear()
    store.save_ticket(make_ticket("TKT-new"))
    assert len(store.load_tickets()) == 11062
    assert len(parsed) == 1

    parsed.clear()
    assert len(store.load_tickets()) == 11062
    assert parsed == []


def test_returned_tickets_are_separate_per_load_at_top_level(store):
    store.save_ticket(make_ticket())
    copy = store.get_ticket("TKT-1")
    copy["title"] = "changed"
    assert store.get_ticket("TKT-1")["title"] == "Título"


# The fake data that the UI is built on
def test_fixtures_are_valid_and_clearly_fake():
    fixtures = Store(ROOT / "ui" / "fixtures")
    tickets, incidents = fixtures.load_tickets(), fixtures.load_incidents()
    assert len(tickets) >= 9 and len(incidents) >= 2
    assert fixtures.health()["skipped_lines"] == 0
    for ticket in tickets:
        assert validate_ticket(ticket) == [], ticket["ticket_id"]
        assert "FICTICIO" in ticket["ticket_id"] and ticket["title"].startswith("[FICTICIO]")
        assert all("FICTICIO" in alert for alert in ticket["alert_ids"])
    for incident in incidents:
        assert validate_incident(incident) == [], incident["incident_id"]
        assert "FICTICIO" in incident["incident_id"]
    assert {t["verdict"] for t in tickets} == {"true_positive", "benign_true_positive", "false_positive", "needs_more_info"}
    assert {t["severity"] for t in tickets} == {"informational", "low", "medium", "high", "critical"}
    assert {t.get("routing") for t in tickets} >= {"cluster", "deep_dive", "live"}
