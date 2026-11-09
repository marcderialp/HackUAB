import pandas as pd

from triage.cluster import assign_clusters, is_outlier_pattern, summarize


def make_alerts(rule_id, domains, ages=None, severity="medium"):
    n = len(domains)
    df = pd.DataFrame(
        {
            "alert_id": [f"A{i}" for i in range(n)],
            "created_at": pd.date_range("2026-10-05", periods=n, freq="h", tz="UTC"),
            "rule_id": rule_id,
            "severity": severity,
            "ev_domain": domains,
        }
    )
    if ages is not None:
        df["ev_domain_age_days"] = ages
    return df


def test_pattern_rule_flags_small_and_rare_patterns():
    assert is_outlier_pattern(10, 91)
    assert is_outlier_pattern(5, 1000)
    assert is_outlier_pattern(15, 1000)  # under 2% of the rule
    assert not is_outlier_pattern(150, 700)


def test_big_pattern_becomes_cluster_with_one_representative():
    out = assign_clusters(make_alerts("UC-NET-001", ["teams.microsoft.com"] * 40))
    assert out["cluster_id"].nunique() == 1
    assert (out["role"] == "representative").sum() == 1
    assert out.loc[out["role"] == "representative", "alert_id"].item() == "A0"  # earliest


def test_rare_pattern_is_outlier():
    out = assign_clusters(make_alerts("UC-NET-001", ["teams.microsoft.com"] * 40 + ["evil.example"]))
    assert out.loc[out["pattern"] == "evil.example", "role"].item() == "outlier"


def test_young_domain_leaves_a_big_cluster():
    # 12 identical alerts would pass as a cluster by count; the young domain must not.
    domains = ["a.example"] * 40 + ["tunnel.example"] * 12
    ages = [4000] * 40 + [20] * 12
    out = assign_clusters(make_alerts("UC-NET-001", domains, ages))
    tunnel = out[out["pattern"] == "tunnel.example"]
    assert (tunnel["role"] == "outlier").all()
    assert (tunnel["reason"] == "young domain").all()


def test_critical_and_unknown_rules_are_never_clustered():
    crit = assign_clusters(make_alerts("UC-NET-001", ["a.example"] * 30, severity="critical"))
    assert (crit["role"] == "individual").all()
    unknown = assign_clusters(make_alerts("UC-XXX-999", ["a.example"] * 30))
    assert (unknown["role"] == "individual").all()


def test_summarize_counts_llm_calls():
    out = assign_clusters(make_alerts("UC-NET-001", ["a.example"] * 40 + ["b.example"]))
    roles, calls = summarize(out)
    assert calls == 2  # one representative + one outlier
    assert roles["member"] == 39


# --- VIP / privileged / OT alerts never sit in a cluster ---

from triage.cluster import sensitive_alert_ids


def test_sensitive_alerts_leave_the_cluster_and_the_representative_is_not_one_of_them():
    df = make_alerts("UC-NET-001", ["a.example"] * 40)
    out = assign_clusters(df, sensitive={"A0", "A7"})  # A0 would have been the representative
    flagged = out[out["alert_id"].isin({"A0", "A7"})]
    assert (flagged["role"] == "outlier").all()
    assert (flagged["reason"] == "vip, privileged or OT").all()
    assert out.loc[out["role"] == "representative", "alert_id"].item() == "A1"
    assert (out["role"] == "member").sum() == 37  # 40 - 2 flagged - 1 representative


def test_sensitive_alert_ids_uses_the_policy_definitions():
    users = [
        {"username": "boss", "upn": "boss@tarvia.example", "vip": "True", "privileged": "False", "account_type": "user"},
        {"username": "adm.x", "upn": "adm.x@tarvia.example", "vip": "False", "privileged": "False", "account_type": "admin"},
        {"username": "plain", "upn": "plain@tarvia.example", "vip": "False", "privileged": "False", "account_type": "user"},
    ]
    assets = [
        {"hostname": "PLC-SORT01", "zone": "LOGISTICS-OT", "type": "PLC"},
        {"hostname": "WS-01", "zone": "CORP", "type": "Workstation"},
    ]
    entities = pd.DataFrame(
        [("A1", "user", "boss"), ("A2", "user", "ADM.X"), ("A3", "user", "plain"),
         ("A4", "host", "plc-sort01"), ("A5", "host", "ws-01"), ("A6", "user", "boss@tarvia.example")],
        columns=["alert_id", "entity_type", "entity_value"],
    )
    assert sensitive_alert_ids(users, assets, entities) == {"A1", "A2", "A4", "A6"}
