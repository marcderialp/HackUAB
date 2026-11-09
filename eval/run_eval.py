"""D3: evaluation harness. Scores tickets against the golden set, dev and holdout reported apart.

Golden set (B4, see eval/README.md): eval/golden_set.jsonl (dev) and eval/holdout.jsonl, one JSON
object per labeled alert with `expected_verdict`, `expected_severity`, `expected_escalate`,
`incident_key`, `twin_of`, `split` and `status`. The plain names `verdict` / `severity` / `incident`
are accepted too. Keys starting with `noise-` or `benign-` are not incidents.
Tickets (out/tickets.jsonl) use the ticket format; a ticket covers every alert in `alert_ids`.

Only the evaluation reads the holdout. Never copy its labels into prompts, code or tests.

Grouping is also scored on dev and holdout TOGETHER ("all_splits"), because one incident can have alerts in
both splits and scoring them apart flatters the result. There it also counts tickets that mix an incident
with alerts labeled `benign-*` / `noise-*` (a false merge a per-split view cannot see).

Metrics (per split):
  verdict accuracy, missed true positives (a real attack judged benign), deferred true positives
  (judged needs_more_info, handed to a human), false alarms (benign judged as an attack),
  missed escalations, twin pairs where both alerts get their opposite verdicts right,
  severity exact / within one level, grouping (tickets per incident, tickets mixing incidents),
  confidence (mean when right and when wrong, correct answers given with a confidence under
  LOW_CONFIDENCE, tickets with no confidence), and the cost and latency the tickets report.

Usage:
    python -m eval.run_eval [--golden PATH ...] [--tickets PATH] [--out PATH] [--only-verified]
    python -m eval.run_eval --incidents out/incidents.jsonl     # score only the L2 grouping
"""
import argparse
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEVERITIES = ["informational", "low", "medium", "high", "critical"]
ATTACK = "true_positive"
BENIGN = {"benign_true_positive", "false_positive"}
LOW_CONFIDENCE = 0.3  # a correct verdict below this is a suspicious number, e.g. a correct BTP with 0.0
NOT_INCIDENT_PREFIXES = ("noise-", "benign-")


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def normalize(row):
    """Golden row with the names this module uses; accepts the B4 names and the plain ones."""
    incident = row.get("incident_key", row.get("incident"))
    background = bool(incident) and incident.startswith(NOT_INCIDENT_PREFIXES)
    if background:
        incident = None
    split = str(row.get("split", "dev")).replace("hold-out", "holdout")
    return {
        "alert_id": row["alert_id"],
        "verdict": row.get("expected_verdict", row.get("verdict")),
        "severity": row.get("expected_severity", row.get("severity")),
        "escalate": row.get("expected_escalate"),
        "incident": incident,
        "background": background,
        "twin_of": row.get("twin_of"),
        "split": split,
        "status": row.get("status", "verified"),
    }


def index_tickets(tickets):
    """alert_id -> ticket. A later ticket for the same ticket_id replaces the earlier one."""
    latest = {t.get("ticket_id", i): t for i, t in enumerate(tickets)}
    by_alert = {}
    for ticket in latest.values():
        for alert_id in ticket.get("alert_ids", []):
            by_alert[alert_id] = ticket
    return by_alert


def _rate(count, total):
    return round(count / total, 3) if total else None


def severity_distance(expected, got):
    if expected not in SEVERITIES or got not in SEVERITIES:
        return None
    return abs(SEVERITIES.index(expected) - SEVERITIES.index(got))


def grouping(golden_rows, by_alert):
    """How well tickets keep each golden incident together without mixing incidents."""
    incident_tickets = defaultdict(set)
    ticket_incidents = defaultdict(set)
    ticket_background = defaultdict(int)
    ungrouped = defaultdict(int)
    for row in golden_rows:
        incident, ticket = row.get("incident"), by_alert.get(row["alert_id"])
        if row.get("background") and ticket:
            ticket_background[ticket.get("ticket_id") or id(ticket)] += 1
        if not incident:
            continue
        if not ticket:
            ungrouped[incident] += 1
            continue
        ticket_id = ticket.get("ticket_id") or id(ticket)
        incident_tickets[incident].add(ticket_id)
        ticket_incidents[ticket_id].add(incident)
    fragmented = {i: len(t) for i, t in incident_tickets.items() if len(t) > 1}
    mixed = sorted(t for t, i in ticket_incidents.items() if len(i) > 1)
    labeled = {r["incident"] for r in golden_rows if r.get("incident")}
    return {
        "incidents": len(labeled),
        "kept_whole": sum(
            1 for i in labeled if len(incident_tickets.get(i, ())) == 1 and not ungrouped.get(i)
        ),
        "split_across_tickets": fragmented,
        "alerts_without_ticket": dict(ungrouped),
        "tickets_mixing_incidents": len(mixed),
        "tickets_mixing_with_benign": sum(1 for t in ticket_incidents if ticket_background.get(t)),
    }


def confidence_report(covered):
    """Is the AI's confidence worth anything? Nothing else in the pipeline checks it."""
    right = [t.get("confidence") for r, t in covered if t.get("verdict") == r["verdict"]]
    wrong = [t.get("confidence") for r, t in covered if t.get("verdict") != r["verdict"]]
    numbers = lambda values: [v for v in values if isinstance(v, (int, float))]
    mean = lambda values: round(sum(values) / len(values), 3) if values else None
    return {
        "mean_when_right": mean(numbers(right)),
        "mean_when_wrong": mean(numbers(wrong)),
        "missing": sum(1 for _, t in covered if not isinstance(t.get("confidence"), (int, float))),
        "correct_but_low": [
            r["alert_id"] for r, t in covered
            if t.get("verdict") == r["verdict"] and isinstance(t.get("confidence"), (int, float))
            and t["confidence"] < LOW_CONFIDENCE
        ],
    }


def twin_pairs(covered):
    """Pairs of alerts with the same rule and opposite verdicts: both must be right."""
    by_id = {r["alert_id"]: (r, t) for r, t in covered}
    seen, pairs, both = set(), 0, 0
    for alert_id, (row, ticket) in by_id.items():
        twin = row.get("twin_of")
        if not twin or twin not in by_id or frozenset((alert_id, twin)) in seen:
            continue
        seen.add(frozenset((alert_id, twin)))
        pairs += 1
        twin_row, twin_ticket = by_id[twin]
        both += ticket.get("verdict") == row["verdict"] and twin_ticket.get("verdict") == twin_row["verdict"]
    return {"pairs": pairs, "both_correct": both}


def score_split(golden_rows, by_alert):
    covered = [(r, by_alert[r["alert_id"]]) for r in golden_rows if r["alert_id"] in by_alert]
    n = len(covered)
    correct = sum(t.get("verdict") == r["verdict"] for r, t in covered)
    attacks = [(r, t) for r, t in covered if r["verdict"] == ATTACK]
    benign = [(r, t) for r, t in covered if r["verdict"] in BENIGN]
    should_escalate = [(r, t) for r, t in covered if r.get("escalate")]
    distances = [d for r, t in covered if (d := severity_distance(r.get("severity"), t.get("severity"))) is not None]
    tickets = {id(t): t for _, t in covered}.values()
    costs = [t.get("model_info", {}).get("cost_usd") for t in tickets]
    seconds = [t.get("triage_seconds") or t.get("model_info", {}).get("latency_s") for t in tickets]
    seconds = [s for s in seconds if s is not None]
    return {
        "golden_alerts": len(golden_rows),
        "covered": n,
        "verdict_accuracy": _rate(correct, n),
        "true_positives": len(attacks),
        "missed_true_positives": sum(t.get("verdict") in BENIGN for _, t in attacks),
        "deferred_true_positives": sum(t.get("verdict") == "needs_more_info" for _, t in attacks),
        "benign_alerts": len(benign),
        "false_alarms": sum(t.get("verdict") == ATTACK for _, t in benign),
        "should_escalate": len(should_escalate),
        "missed_escalations": sum(not t.get("escalation", {}).get("escalate") for _, t in should_escalate),
        "twins": twin_pairs(covered),
        "confidence": confidence_report(covered),
        "severity_exact": _rate(sum(d == 0 for d in distances), len(distances)),
        "severity_within_one": _rate(sum(d <= 1 for d in distances), len(distances)),
        "grouping": grouping(golden_rows, by_alert),
        "cost_usd": round(sum(c for c in costs if c), 4),
        "mean_seconds": round(sum(seconds) / len(seconds), 2) if seconds else None,
        "missing": [r["alert_id"] for r in golden_rows if r["alert_id"] not in by_alert],
    }


def evaluate(golden, tickets, only_verified=False):
    """Metrics for each split present in the golden set."""
    by_alert = index_tickets(tickets)
    splits = defaultdict(list)
    for row in map(normalize, golden):
        if only_verified and row["status"] != "verified":
            continue
        splits[row["split"]].append(row)
    results = {name: score_split(rows, by_alert) for name, rows in sorted(splits.items())}
    every_row = [row for rows in splits.values() for row in rows]
    results["all_splits"] = {"grouping": grouping(every_row, by_alert), "golden_alerts": len(every_row)}
    return results


def incidents_as_tickets(incidents):
    """Grouped incidents (D6) viewed as tickets, to score the grouping alone."""
    return [{"ticket_id": i["incident_id"], "alert_ids": i["alert_ids"]} for i in incidents]


def to_markdown(results):
    lines = ["# Evaluation report", ""]
    for split, m in results.items():
        g = m["grouping"]
        if split == "all_splits":
            lines += [
                "## all splits together (grouping only)", "",
                f"- Incidents: {g['incidents']}, kept whole: {g['kept_whole']}, split across tickets: {g['split_across_tickets']},"
                f" alerts without a ticket: {g['alerts_without_ticket']}",
                f"- Tickets mixing incidents: {g['tickets_mixing_incidents']},"
                f" tickets mixing an incident with benign/noise alerts: {g['tickets_mixing_with_benign']}", "",
            ]
            continue
        lines += [
            f"## {split}", "",
            f"- Labeled alerts: {m['golden_alerts']}, with a ticket: {m['covered']}",
            f"- Verdict accuracy: {m['verdict_accuracy']}",
            f"- True positives: {m['true_positives']}, **missed** (judged benign): {m['missed_true_positives']},"
            f" deferred to a human: {m['deferred_true_positives']}",
            f"- Benign alerts: {m['benign_alerts']}, false alarms: {m['false_alarms']}",
            f"- Should escalate: {m['should_escalate']}, missed escalations: {m['missed_escalations']}",
            f"- Twin pairs: {m['twins']['pairs']}, both alerts right: {m['twins']['both_correct']}",
            f"- Confidence: mean {m['confidence']['mean_when_right']} when right, {m['confidence']['mean_when_wrong']} when wrong;"
            f" no confidence on {m['confidence']['missing']} tickets; correct but under {LOW_CONFIDENCE}:"
            f" {m['confidence']['correct_but_low'] or 'none'}",
            f"- Severity exact: {m['severity_exact']}, within one level: {m['severity_within_one']}",
            f"- Incidents: {g['incidents']}, kept whole: {g['kept_whole']}, split across tickets: {g['split_across_tickets']},"
            f" alerts without a ticket: {g['alerts_without_ticket']}, tickets mixing incidents: {g['tickets_mixing_incidents']},"
            f" mixing with benign: {g['tickets_mixing_with_benign']}",
            f"- Cost: ${m['cost_usd']}, mean seconds per ticket: {m['mean_seconds']}",
        ]
        if m["missing"]:
            lines.append(f"- No ticket for: {', '.join(m['missing'][:20])}")
        lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--golden", nargs="+", default=[
        str(ROOT / "eval" / "golden_set.jsonl"), str(ROOT / "eval" / "holdout.jsonl")])
    parser.add_argument("--tickets", default=str(ROOT / "out" / "tickets.jsonl"))
    parser.add_argument("--incidents", help="score the grouping of this incidents.jsonl instead of tickets")
    parser.add_argument("--only-verified", action="store_true", help="skip labels still marked to_verify")
    parser.add_argument("--out", default=str(ROOT / "eval" / "reports" / "latest.md"))
    args = parser.parse_args()

    golden = []
    for path in args.golden:
        if Path(path).exists():
            golden += read_jsonl(path)
        else:
            print(f"warning: {path} not found, skipped")
    if not golden:
        raise SystemExit("no golden set found")
    source = args.incidents or args.tickets
    if not Path(source).exists():
        raise SystemExit(f"not found: {source}")
    tickets = read_jsonl(source)
    if args.incidents:
        tickets = incidents_as_tickets(tickets)
    results = evaluate(golden, tickets, args.only_verified)
    report = to_markdown(results)
    print(report)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(report + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
