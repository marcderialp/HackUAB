# Evaluation set

The labeled alerts the triage system is measured against, scored by `eval/run_eval.py`. Reports are in [`reports/`](reports/): `latest.md` (verdicts, severity, escalation) and `grouping.md` (incidents).

## What is here

The labels for the organizers' dataset are private, like the dataset itself. The files here label the invented mock week that ships with this repository: `tools/make_mock_data.py` writes them together with the data, from what each planted scenario is.

| File | What | Who may open it |
|---|---|---|
| `golden_set.jsonl` | **dev** split (54 alerts) | anyone |
| `holdout.jsonl` | **holdout** split (13 alerts, one or two per runbook) | the evaluation script; never whoever tunes prompts or triage logic |

The holdout rule is the one we followed during the challenge: nobody who tunes prompts reads it, and the script reports dev and holdout separately. Nothing was tuned on the mock data, so both splits are new to the system; the split is kept to show how the harness works.

The reports in `reports/` score the committed mock run (`out/tickets.jsonl`). They show that the pipeline runs end to end on data it was not built on; they are not the project's results. The results on the organizers' dataset are in the [README](../README.md#results).

## Record format (one JSON object per line)

```json
{
  "alert_id": "ALR-...", "rule_id": "UC-...",
  "expected_verdict": "true_positive | benign_true_positive | false_positive | needs_more_info",
  "expected_severity": "informational | low | medium | high | critical",
  "expected_escalate": true,
  "incident_key": "paperkite-finanzas",
  "twin_of": "ALR-... or null",
  "split": "dev | holdout",
  "status": "verified",
  "notes": "why this label"
}
```

- `expected_severity` and `expected_escalate` come from the policy engine (`triage/policy.py`) applied to the label's verdict and to the ±1 adjustments the scenario implies (confirmed execution, blocked with no effect, personal data), never to the AI's answer. They follow the policy decisions D-1..D-6 ([design.md](../docs/design.md#policy-decisions-d-1d-6)).
- `incident_key` groups the alerts of one attack, to score grouping. Keys starting with `noise-` or `benign-` are not incidents.
- `twin_of` links two alerts of the same rule whose right answers differ, the most valuable test cases: the PowerShell launched by the phishing loader against the SCCM inventory, the vendor's Saturday-night VPN session against its approved overtime, a DNS tunnel against the mail gateway's spam-list lookups. Both alerts of a pair sit in the same split.
- **Never copy these labels or notes into prompts or triage code.** The system must reach them from the evidence.
