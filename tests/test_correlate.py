import pandas as pd

from triage.correlate import group_alerts, is_local_entity, to_incidents


def ts(day, hour=0):
    return pd.Timestamp(f"2026-10-{day:02d} {hour:02d}:00", tz="UTC")


def alerts(*rows):
    return pd.DataFrame(rows, columns=["alert_id", "rule_id", "created_at"])


def entities(*rows):
    return pd.DataFrame(rows, columns=["alert_id", "entity_type", "entity_value", "ts"])


def test_local_entities():
    assert is_local_entity("host", "fs01")
    assert is_local_entity("ip", "10.10.4.15")
    assert not is_local_entity("ip", "198.51.100.5")  # documentation range, not RFC 1918
    assert not is_local_entity("user", "adm.bclotet")


def test_shared_user_links_alerts_days_apart():
    a = alerts(("A1", "UC-X", ts(10)), ("A2", "UC-Y", ts(18)))
    e = entities(("A1", "user", "adm.x", ts(10)), ("A2", "user", "adm.x", ts(18)))
    groups = group_alerts(a, e)
    assert len(groups) == 1
    assert groups[0]["alert_ids"] == ["A1", "A2"]


def test_shared_host_only_links_close_in_time():
    # The same server touched by an approved maintenance and an attack days apart is not one story.
    a = alerts(("A1", "UC-X", ts(10)), ("A2", "UC-Y", ts(13)), ("A3", "UC-Z", ts(13, 1)))
    e = entities(
        ("A1", "host", "fs01", ts(10)),
        ("A2", "host", "fs01", ts(13)),
        ("A3", "host", "fs01", ts(13, 1)),
    )
    groups = group_alerts(a, e)
    assert [g["alert_ids"] for g in groups] == [["A2", "A3"]]


def test_hub_entity_shared_by_too_many_alerts_is_ignored():
    rows = [(f"A{i}", "UC-X", ts(10)) for i in range(20)]
    e = entities(*[(f"A{i}", "domain", "www.tarvia.example", ts(10)) for i in range(20)])
    assert group_alerts(alerts(*rows), e) == []


def test_unrelated_alerts_stay_apart():
    a = alerts(("A1", "UC-X", ts(10)), ("A2", "UC-Y", ts(10)))
    e = entities(("A1", "user", "u1", ts(10)), ("A2", "user", "u2", ts(10)))
    assert group_alerts(a, e) == []


def test_incident_format_for_the_store():
    a = alerts(("ALR-20261010-1", "UC-X", ts(10)), ("ALR-20261010-2", "UC-Y", ts(10, 2)))
    e = entities(
        ("ALR-20261010-1", "user", "u", ts(10)), ("ALR-20261010-2", "user", "u", ts(10, 2))
    )
    [incident] = to_incidents(group_alerts(a, e))
    assert incident["incident_id"] == "INC-20261010-1"
    assert incident["stage"] == "grouped"
    assert incident["alert_ids"] == ["ALR-20261010-1", "ALR-20261010-2"]
    assert incident["title"]


def test_graph_nodes_skip_clusters_and_sensitive_only_outliers():
    from triage.cluster import SENSITIVE_REASON
    from triage.correlate import graph_nodes

    clustered = pd.DataFrame(
        [("A1", "member", "benign-pattern cluster"), ("A2", "representative", "benign-pattern cluster"),
         ("A3", "outlier", "rare pattern"), ("A4", "outlier", "young domain"),
         ("A5", "outlier", SENSITIVE_REASON), ("A6", "individual", "no signature or critical severity")],
        columns=["alert_id", "role", "reason"],
    )
    assert list(graph_nodes(clustered)["alert_id"]) == ["A3", "A4", "A6"]


def test_output_does_not_depend_on_input_order_or_set_ordering():
    a = alerts(*[(f"A{i}", "UC-X", ts(10)) for i in range(6)])  # same timestamp: ties everywhere
    e = entities(*[(f"A{i}", "user", f"u{i % 2}", ts(10)) for i in range(6)],
                 *[(f"A{i}", "domain", "d.example", ts(10)) for i in range(6)])
    first = group_alerts(a, e)
    shuffled = group_alerts(a.sample(frac=1, random_state=3), e.sample(frac=1, random_state=5))
    assert first == shuffled
    assert first[0]["shared_entities"] == sorted(first[0]["shared_entities"], key=lambda x: (x != "domain:d.example", x))


# --- the incident file is the store's log: never wipe an investigated report ---

import json as _json

from triage.correlate import write_incidents


def read_lines(path):
    return [_json.loads(line) for line in path.read_text().splitlines()]


def test_write_incidents_creates_the_file(tmp_path):
    path = tmp_path / "incidents.jsonl"
    kept, written = write_incidents([{"incident_id": "INC-1", "stage": "grouped", "alert_ids": ["A1", "A2"]}], path)
    assert (kept, written) == (0, 1) and read_lines(path)[0]["incident_id"] == "INC-1"


def test_write_incidents_keeps_investigated_reports_and_replaces_grouped_ones(tmp_path):
    path = tmp_path / "incidents.jsonl"
    path.write_text("\n".join(_json.dumps(r) for r in [
        {"incident_id": "INC-1", "stage": "investigated", "title": "Informe", "root_cause": "x"},
        {"incident_id": "INC-OLD", "stage": "grouped", "title": "old", "alert_ids": ["A9"]},
    ]) + "\n")
    new = [{"incident_id": "INC-1", "stage": "grouped", "title": "regrouped", "alert_ids": ["A1", "A2"]},
           {"incident_id": "INC-2", "stage": "grouped", "title": "new", "alert_ids": ["A3", "A4"]}]
    kept, written = write_incidents(new, path)
    by_id = {r["incident_id"]: r for r in read_lines(path)}
    assert (kept, written) == (1, 1)
    assert by_id["INC-1"]["stage"] == "investigated" and by_id["INC-1"]["root_cause"] == "x"  # not downgraded
    assert "INC-OLD" not in by_id  # a stale grouped incident is gone
    assert by_id["INC-2"]["title"] == "new"


def test_write_incidents_leaves_no_temp_file_and_the_last_record_per_id_wins(tmp_path):
    path = tmp_path / "incidents.jsonl"
    path.write_text("\n".join(_json.dumps(r) for r in [
        {"incident_id": "INC-1", "stage": "grouped", "title": "first"},
        {"incident_id": "INC-1", "stage": "investigated", "title": "later report"},
    ]) + "\n")
    write_incidents([], path)
    assert not (tmp_path / "incidents.jsonl.tmp").exists()
    assert [r["title"] for r in read_lines(path)] == ["later report"]
