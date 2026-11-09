"""D1: alert profiling.

Two reports over 03_alertas/alertas.jsonl:
  * cardinality: per rule, how many distinct values each evidence field has
    (low cardinality = candidate for a cluster signature, high = unique per alert).
  * signature: per rule, the dominant pattern(s) and the long tail (needle candidates)
    for the evidence fields chosen in SIGNATURE_FIELDS.

Usage:
    python triage/profile_alerts.py                      # rule overview
    python triage/profile_alerts.py cardinality UC-NET-001
    python triage/profile_alerts.py signature              # all rules in SIGNATURE_FIELDS
    python triage/profile_alerts.py signature UC-EDR-002
"""
import json
import sys
from pathlib import Path

import pandas as pd

ALERTS_PATH = Path(__file__).resolve().parent.parent / "03_alertas" / "alertas.jsonl"

# Evidence fields that define "the same pattern" for a noisy rule. A field belongs
# here if it has few distinct values and a human would use it to say "these are all
# the same thing". Fields unique per alert (message_id, timestamps) never belong.
SIGNATURE_FIELDS = {
    "UC-EDR-002": ["parent", "user"],
    "UC-WEB-001": ["rule_msg", "action"],
    "UC-EML-001": ["sender"],
    # device and minutes_between separate the "known corporate phone" noise from real travel.
    "UC-IDP-001": ["device", "minutes_between"],
    # The beacon target defines the pattern; distinct_hosts_seen and user_agent vary in noise.
    "UC-NET-001": ["domain"],
    "UC-NET-005": ["parent_domain"],
    "UC-EDR-001": ["process_tree", "signer"],
    # prompt_excerpt is attacker-controlled; it is only a grouping key here, never read as instructions.
    "UC-AI-001": ["action", "prompt_excerpt"],
    "UC-EDR-003": ["detection_name", "action", "executed"],
    # Mid-volume rules (20-91 alerts each).
    "UC-NET-006": ["parent_domain", "qtype"],
    "UC-WEB-002": ["success_count", "distinct_src_ips"],
    "UC-IDP-002": ["protocol", "successes"],
    "UC-DLP-001": ["destination", "file"],
    "UC-CLD-003": ["change", "source"],
    "UC-NET-003": ["distinct_ports", "window_s"],
}


def _scalar(value):
    """Make any evidence value hashable/printable (dicts and lists become JSON)."""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return value


def load_alerts(path=ALERTS_PATH):
    """One row per alert; evidence fields flattened into `ev_<name>` columns."""
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            alert = json.loads(line)
            row = {
                "alert_id": alert["alert_id"],
                "created_at": alert["created_at"],
                "rule_id": alert["rule_id"],
                "severity": alert["severity"],
                "source_product": alert["source_product"],
                "runbook": alert.get("runbook"),
                "n_related_events": len(alert.get("related_events") or []),
            }
            for key, value in (alert.get("evidence") or {}).items():
                row[f"ev_{key}"] = _scalar(value)
            rows.append(row)
    df = pd.DataFrame(rows)
    df["created_at"] = pd.to_datetime(df["created_at"], utc=True)
    return df


def rule_overview(df):
    """Alerts per rule with share and cumulative share, biggest first."""
    out = (
        df.groupby("rule_id")
        .agg(alerts=("alert_id", "count"), severity=("severity", "first"))
        .sort_values("alerts", ascending=False)
    )
    out["share_%"] = (100 * out["alerts"] / len(df)).round(1)
    out["cum_%"] = out["share_%"].cumsum().round(1)
    return out


def cardinality_report(df, rule_id):
    """Distinct values per evidence field for one rule."""
    sub = df[df["rule_id"] == rule_id]
    cols = [c for c in sub.columns if c.startswith("ev_") and sub[c].notna().any()]
    rows = [
        {
            "field": c.removeprefix("ev_"),
            "distinct": sub[c].nunique(),
            "filled_%": round(100 * sub[c].notna().mean(), 1),
            "top_value": str(sub[c].value_counts().index[0])[:60],
            "top_share_%": round(100 * sub[c].value_counts(normalize=True).iloc[0], 1),
        }
        for c in cols
    ]
    return pd.DataFrame(rows).sort_values("distinct").reset_index(drop=True)


def signature_report(df, rule_id, fields):
    """Pattern counts for a rule using the chosen signature fields."""
    sub = df[df["rule_id"] == rule_id]
    cols = [f"ev_{f}" for f in fields]
    missing = [c for c in cols if c not in sub.columns]
    if missing:
        raise KeyError(f"{rule_id}: evidence fields not found: {missing}")
    counts = sub.groupby(cols, dropna=False).size().sort_values(ascending=False)
    out = counts.reset_index(name="alerts")
    out["share_%"] = (100 * out["alerts"] / len(sub)).round(1)
    return out


def main(argv):
    df = load_alerts()
    cmd = argv[1] if len(argv) > 1 else "overview"
    pd.set_option(
        "display.width", 200, "display.max_colwidth", 70, "display.max_rows", 200,
        "display.max_columns", None,
    )

    if cmd == "overview":
        print(f"{len(df)} alerts, {df['rule_id'].nunique()} rules\n")
        print(rule_overview(df))
    elif cmd == "cardinality":
        for rule_id in argv[2:] or [sys.exit("usage: cardinality <rule_id> ...")]:
            print(f"\n== {rule_id} ({(df['rule_id'] == rule_id).sum()} alerts)")
            print(cardinality_report(df, rule_id))
    elif cmd == "signature":
        rules = argv[2:] or list(SIGNATURE_FIELDS)
        for rule_id in rules:
            print(f"\n== {rule_id} signature={SIGNATURE_FIELDS[rule_id]}")
            print(signature_report(df, rule_id, SIGNATURE_FIELDS[rule_id]).head(15))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
