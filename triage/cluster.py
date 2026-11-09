"""D2: cluster noisy alerts, keep needles out.

Every alert gets a role:
  representative  one per cluster; this is the alert that goes to the LLM
  member          the rest of a cluster; inherits the verdict, with per-alert re-checks (D5)
  outlier         a rare pattern inside a clustered rule; triaged on its own
  individual      never clustered (critical severity, or a rule with no signature)

Outliers also include any alert that touches a VIP or privileged identity or an OT asset: a cluster
verdict is never valid for them (the policy rates those by who and what is involved).

LLM calls needed = representatives + outliers + individuals.

Usage:
    python -m triage.cluster            # summary, and writes out/clusters.csv
"""
from pathlib import Path

import duckdb
import pandas as pd

from triage.loader import DB_PATH
# Same definitions as the policy engine, so "sensitive" means the same thing everywhere.
from triage.policy import _is_ot, _is_vip_or_privileged, identity_criticality
from triage.profile_alerts import SIGNATURE_FIELDS, load_alerts

OUT_PATH = Path(__file__).resolve().parent.parent / "out" / "clusters.csv"


# A pattern with at most this many alerts, or under this share of its rule, is never a cluster.
MAX_OUTLIER_COUNT = 10
MIN_CLUSTER_SHARE = 0.02
# A domain registered more recently than this is a standard analyst red flag.
YOUNG_DOMAIN_DAYS = 90
# Why an alert was pulled out only because of who or what it involves (not because it looks odd).
SENSITIVE_REASON = "vip, privileged or OT"


def is_outlier_pattern(pattern_count, rule_count):
    """True if a signature pattern is too rare to be treated as one benign cluster.

    pattern_count: alerts sharing this exact signature within the rule.
    rule_count: all alerts of the rule.
    """
    return pattern_count <= MAX_OUTLIER_COUNT or pattern_count / rule_count < MIN_CLUSTER_SHARE


def sensitive_alert_ids(users, assets, entities):
    """Ids of alerts that involve a VIP/privileged/admin identity or an OT host.

    users, assets: rows of the `users` and `assets` tables as dicts.
    entities: DataFrame with alert_id, entity_type, entity_value (the alert_entities table).
    Hosts are matched by name; an OT asset seen only by IP is not caught (see docs/limitations.md).
    """
    names = set()
    for user in users:
        if _is_vip_or_privileged(user) or identity_criticality(user).from_privilege:
            names |= {str(user[k]).casefold() for k in ("username", "upn") if user.get(k)}
    ot_hosts = {str(a["hostname"]).casefold() for a in assets if a.get("hostname") and _is_ot(a)}
    value = entities["entity_value"].astype(str).str.casefold()
    hit = ((entities["entity_type"] == "user") & value.isin(names)) | (
        (entities["entity_type"] == "host") & value.isin(ot_hosts)
    )
    return set(entities.loc[hit, "alert_id"])


def load_sensitive_alert_ids():
    con = duckdb.connect(str(DB_PATH), read_only=True)
    users = con.sql("SELECT * FROM users").df().to_dict("records")
    assets = con.sql("SELECT * FROM assets").df().to_dict("records")
    entities = con.sql("SELECT alert_id, entity_type, entity_value FROM alert_entities").df()
    return sensitive_alert_ids(users, assets, entities)


def alert_level_reasons(sub, sensitive):
    """Series: why an alert must leave its cluster whatever its pattern, or None.

    Counts cannot separate a small benign group from an attack (12 identical alerts look like
    a cluster), and a cluster verdict says nothing about who or what is involved, so we also check
    per-alert facts that benign noise does not have.
    """
    reason = pd.Series(None, index=sub.index, dtype=object)
    if "ev_domain_age_days" in sub:
        age = pd.to_numeric(sub["ev_domain_age_days"], errors="coerce")
        reason[age < YOUNG_DOMAIN_DAYS] = "young domain"
    reason[sub["alert_id"].isin(sensitive) & reason.isna()] = SENSITIVE_REASON
    return reason


def load_clustered():
    """All alerts with their roles; the entry point for everything that needs the clusters."""
    return assign_clusters(load_alerts(), load_sensitive_alert_ids())


def assign_clusters(df, sensitive=frozenset()):
    """Return df with `cluster_id`, `role`, `pattern` and `reason` columns added.

    sensitive: alert ids that must never sit in a cluster (see sensitive_alert_ids).
    """
    df = df.sort_values("created_at").reset_index(drop=True)
    df["cluster_id"] = None
    df["role"] = "individual"
    df["pattern"] = None
    df["reason"] = "no signature or critical severity"

    for rule_id, fields in SIGNATURE_FIELDS.items():
        rule_rows = df.index[(df["rule_id"] == rule_id) & (df["severity"] != "critical")]
        if rule_rows.empty:
            continue
        cols = [f"ev_{f}" for f in fields]
        sub = df.loc[rule_rows]
        parts = sub[cols].astype(object).where(sub[cols].notna(), "(empty)").astype(str)
        keys = parts.agg(" | ".join, axis=1)
        reasons = alert_level_reasons(sub, sensitive)
        for rank, (key, n) in enumerate(keys.value_counts().items(), start=1):
            idx = keys.index[keys == key]
            df.loc[idx, "pattern"] = key
            if is_outlier_pattern(n, len(sub)):
                df.loc[idx, "role"] = "outlier"
                df.loc[idx, "reason"] = "rare pattern"
                continue
            odd = idx[reasons.loc[idx].notna().to_numpy()]
            df.loc[odd, "role"] = "outlier"
            df.loc[odd, "reason"] = reasons.loc[odd].to_numpy()
            members = idx.difference(odd, sort=False)
            if len(members) == 0:
                continue
            df.loc[members, "cluster_id"] = f"{rule_id}:{rank}"
            df.loc[members, "role"] = "member"
            df.loc[members, "reason"] = "benign-pattern cluster"
            df.loc[members[0], "role"] = "representative"  # earliest alert of the cluster
    return df


def summarize(df):
    """LLM calls needed and the breakdown by role."""
    roles = df["role"].value_counts()
    calls = roles.get("representative", 0) + roles.get("outlier", 0) + roles.get("individual", 0)
    return roles, int(calls)


def main():
    df = load_clustered()
    roles, calls = summarize(df)
    print(f"{len(df)} alerts")
    print(roles.to_string())
    print(f"\nLLM calls needed: {calls}")
    OUT_PATH.parent.mkdir(exist_ok=True)
    df[["alert_id", "rule_id", "severity", "cluster_id", "role", "reason", "pattern"]].to_csv(
        OUT_PATH, index=False
    )
    print(f"wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
