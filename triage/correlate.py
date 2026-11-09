"""D6 v1: group related alerts into incidents (L2) with an entity graph.

Two alerts are linked when they share an entity (user, IP, domain, host, hash, ...) close enough in
time. The time window depends on what the entity identifies:
  * actors and attacker infrastructure (user, external IP, domain, hash, email, session, ...) are
    reused for days, so they link alerts up to FAR_DAYS apart;
  * hosts and internal IPs link alerts only within LOCAL_HOURS, because many unrelated activities
    (an approved patch run, an attack) touch the same server on different days.
An entity shared by more than MAX_DEGREE alerts is shared infrastructure, not evidence, and is ignored.
Only alerts that were not absorbed into a benign cluster (see cluster.py) enter the graph, and not those
pulled out of one solely for involving a VIP, privileged or OT asset.

v2 adds evidence the alerts do not carry (link_sources.py): IPs and e-mails the collectors' findings cite,
and user -> host pivots from the logs, so stages that share no entity (stolen key -> its later use, the
vendor's login -> the server that tunnels DNS) join. Alerts an approved change covers, and alerts whose
ticket says benign or false positive, are left out: authorized or routine activity is not an attack.

Output: out/incidents.jsonl, one `stage: "grouped"` incident per connected group of 2+ alerts. Incidents
that were already investigated (stage "investigated") are never overwritten.

Usage:
    python -m triage.correlate
"""
import ipaddress
import json
from collections import Counter
from pathlib import Path

import duckdb
import pandas as pd

from triage.cluster import SENSITIVE_REASON, load_clustered
from triage.link_sources import benign_ticket_alert_ids, enrich
from triage.loader import DB_PATH

OUT_PATH = Path(__file__).resolve().parent.parent / "out" / "incidents.jsonl"

MAX_DEGREE = 15
LOCAL_HOURS = 24
FAR_DAYS = 14
_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_local_entity(entity_type, value):
    """Hosts and RFC 1918 addresses identify a machine, not an actor."""
    if entity_type == "host":
        return True
    if entity_type == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(address in network for network in _RFC1918)
    return False


def group_alerts(alerts, entities):
    """Connected groups of alerts as a list of dicts, largest first.

    alerts: DataFrame with alert_id, rule_id, created_at (UTC).
    entities: DataFrame with alert_id, entity_type, entity_value, ts (UTC).
    Only groups with 2 or more alerts are returned.
    """
    ids = set(alerts["alert_id"])
    ent = entities[entities["alert_id"].isin(ids)].drop_duplicates(
        ["alert_id", "entity_type", "entity_value"]
    )
    degree = ent.groupby(["entity_type", "entity_value"])["alert_id"].transform("nunique")
    ent = ent[(degree >= 2) & (degree <= MAX_DEGREE)]

    parent = {alert_id: alert_id for alert_id in ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    shared = {alert_id: Counter() for alert_id in ids}
    for (entity_type, value), group in ent.groupby(["entity_type", "entity_value"]):
        group = group.sort_values("ts")
        window = (
            pd.Timedelta(hours=LOCAL_HOURS)
            if is_local_entity(entity_type, value)
            else pd.Timedelta(days=FAR_DAYS)
        )
        previous = None
        for alert_id, ts in zip(group["alert_id"], group["ts"]):
            if previous is not None and ts - previous[1] <= window:
                parent[find(previous[0])] = find(alert_id)
                for linked in (previous[0], alert_id):
                    shared[linked][f"{entity_type}:{value}"] += 1
            previous = (alert_id, ts)

    components = {}
    for alert_id in ids:
        components.setdefault(find(alert_id), []).append(alert_id)

    info = alerts.set_index("alert_id")
    groups = []
    for members in components.values():
        if len(members) < 2:
            continue
        rows = info.loc[sorted(members)].sort_values("created_at", kind="stable")  # ties: alert_id
        entity_counts = Counter()
        for alert_id in members:
            entity_counts.update(shared[alert_id])
        groups.append(
            {
                "alert_ids": list(rows.index),
                "rule_ids": list(dict.fromkeys(rows["rule_id"])),
                "first_seen": rows["created_at"].iloc[0].isoformat(),
                "last_seen": rows["created_at"].iloc[-1].isoformat(),
                "shared_entities": [e for e, _ in sorted(entity_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:3]],
            }
        )
    groups.sort(key=lambda g: (-len(g["alert_ids"]), g["first_seen"], g["alert_ids"][0]))
    return groups


def to_incidents(groups):
    """Wrap groups in the `grouped` incident format of the ticket store (titles in Spanish)."""
    incidents = []
    for group in groups:
        first = group["alert_ids"][0]
        n = len(group["alert_ids"])
        where = group["shared_entities"][0] if group["shared_entities"] else "entidades comunes"
        incidents.append(
            {
                "incident_id": "INC-" + first.removeprefix("ALR-"),
                "stage": "grouped",
                "title": f"{n} alertas relacionadas por {where} ({', '.join(group['rule_ids'][:3])})",
                **group,
            }
        )
    return incidents


def graph_nodes(clustered):
    """The alerts that enter the incident graph (see the module docstring)."""
    nodes = clustered[clustered["role"].isin(["outlier", "individual"])]
    # Alerts pulled out of a cluster only because of who they involve are triaged on their own but are
    # not graph nodes: nothing about them looks odd, and hub entities would chain them into a false incident.
    return nodes[nodes["reason"] != SENSITIVE_REASON]


def load_inputs(enrich_links=True, tickets=None):
    """(graph nodes, entity rows) for the incident graph.

    enrich_links: add the extra evidence of link_sources.py and drop approved-change alerts (needs the
    collectors, a few seconds). tickets: tickets from the store; benign ones are dropped as well.
    """
    clustered = load_clustered()
    nodes = graph_nodes(clustered)
    nodes = nodes[["alert_id", "rule_id", "created_at"]]
    con = duckdb.connect(str(DB_PATH), read_only=True)
    entities = con.sql(
        "SELECT alert_id, entity_type, entity_value, ts FROM alert_entities"
    ).df()
    entities["ts"] = pd.to_datetime(entities["ts"], utc=True)
    excluded = benign_ticket_alert_ids(tickets or [])
    if enrich_links:
        extra, approved = enrich(nodes)
        entities = pd.concat([entities, extra], ignore_index=True)
        excluded |= approved
    return nodes[~nodes["alert_id"].isin(excluded)], entities


def write_incidents(incidents, path=OUT_PATH):
    """Replace the grouped incidents in `path`, keeping every investigated one untouched.

    The file is the ticket store's incident log. A run of this module used to overwrite it, which would
    have wiped an investigated report. The rewrite is atomic.
    """
    kept = []
    if Path(path).exists():
        with open(path, encoding="utf-8") as f:
            latest = {}
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    latest[record.get("incident_id")] = record
        kept = [r for r in latest.values() if r.get("stage") == "investigated"]
    investigated = {r["incident_id"] for r in kept}
    fresh = [i for i in incidents if i["incident_id"] not in investigated]
    tmp = Path(str(path) + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        for record in kept + fresh:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    tmp.replace(path)
    return len(kept), len(fresh)


def main():
    from triage.store import default_store, effective

    tickets = [{**t, **effective(t)} for t in default_store().load_tickets()]
    nodes, entities = load_inputs(tickets=tickets)
    incidents = to_incidents(group_alerts(nodes, entities))
    OUT_PATH.parent.mkdir(exist_ok=True)
    kept, written = write_incidents(incidents)
    grouped = sum(len(i["alert_ids"]) for i in incidents)
    print(f"{len(nodes)} candidate alerts -> {len(incidents)} incidents covering {grouped} alerts"
          f" ({len(tickets)} tickets used to drop benign alerts, {kept} investigated incidents kept)")
    for i in incidents[:8]:
        print(f"  {i['incident_id']}  {i['title']}")
    print(f"wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
