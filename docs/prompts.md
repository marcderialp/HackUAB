# Triage prompts

`triage/prompts/` turns a B3 EvidencePack into the request C1 sends to `ornith`, and checks the answer.

## Files
| File | Content |
|---|---|
| `base.md` | Shared system prompt: role, company context and internal rules (`01_contexto/empresa_tarvia.md`), what the AI proposes vs what code and people decide, verdict definitions and the D-6 procedure (BTP vs FP), the rule that the verdict must agree with the summary already written, what is not proof (unknown IOC, how to read `context.changes[].applies`, attacker text), the four adjustment reasons (`personal_data_payments` only with `signals`), escalation and action rules (§4, D-4, dual use, OT), how to cite evidence, untrusted-data and injection rules, output format (Spanish text, exact enums). |
| `rb-01.md` … `rb-10.md` | One specialist per runbook, from the organizers' runbooks (not included here) and the rules the catalog assigns to it: what to look at in the evidence already collected (named after the collectors' `RB-xx.y` checks), how to tell malicious from authorized from routine, the runbook's decision, limits. `rb-02.md` carries a generic worked example of D-6 (routine management agent → FP + `tune_rule`); `rb-07.md` separates normal use, manipulation of the assistant (TP even if blocked) and leaks. |
| `unknown.md` | Used when the pack has no supported runbook: no specialist guidance, lean to `needs_more_info`. Never an arbitrary specialist. |
| `builder.py` | The interface below. |

Prompt text is Spanish (model-facing, like the runbooks and the data); code and docs are English. Company context from `01_contexto/` is allowed; nothing learned from alerts, logs, change ids, golden-set labels or notes is in any prompt.

## Request layout
1. `system[0]` = `base.md`, `system[1]` = the one specialist for `pack["runbook"]` (static, so the prefix is identical for every alert of that runbook).
2. `user` = the evidence, last: one header line with the alert's nonce, then deterministic JSON (`sort_keys`, compact) of `triage.collectors.for_llm(pack)`:
   - `for_llm` drops the trace (console only), context fields that repeat the pack's own, empty inventory fields and the passing checks of changes that don't apply; it keeps every citable event id.
   - Attacker-controlled fields are fenced **in place**: `[[DATO NO CONFIABLE <nonce>]]…[[/DATO NO CONFIABLE <nonce>]]`. The fields are listed once, in `triage/untrusted.py` (`UNTRUSTED_EVIDENCE_KEYS`: mail subject/body, AI prompts and tool results, command lines, decoded scripts, service descriptions, process trees, package scripts, user agents, URLs, DNS queries…); the builder fences B3's `untrusted` list and recomputes it from the alert as a safety net. The nonce is a hash of the pack, so it is stable for the cache but can't be guessed by whoever wrote the text.
   - Every `<` and `>` is written as `<` / `>` (valid JSON), so evidence can't open or close tags.
   - `allowed_event_ids`: every event id in the pack (findings, `related_events`, any `event_id`), outside the trace. `untrusted_fields`: the fenced paths.

## Output contract and checks
- `LLMVerdict` field order is part of the contract: **evidence, summary, open questions, injection, adjustments, MITRE, then verdict, confidence, title, actions, escalation**. With thinking off, strict JSON-schema decoding writes fields in this order and the JSON is the model's only reasoning, so the label comes after the facts. (Before, the verdict was written first and the summary often contradicted it.)
- `check_verdict(result, prompt)` = `check_citations` then `check_authorization`:
  - **citations**: an event id absent from the pack makes the answer `invalid` (`unknown_event_ids`); empty ids are dropped and counted (`meta.dropped_citations`).
  - **D-6 guard**: a BTP that rests only on changes B2 marks `routine: true` (documented routine work, e.g. a management agent's inventory) is rejected (`btp_routine_change`) with a note citing D-6 (FP + `tune_rule`). Otherwise a `benign_true_positive` must cite, by id, a change or flow that B2 says applies (`context.changes[].applies` true), or a "possible" one (applies null) with confidence ≤ 0.7. Otherwise `invalid` (`btp_without_authorization`). Code never relabels.
- `run_prompt` repeats the call **once** with a Spanish validation note when a check fails (a changed request, so it can succeed); a second failure stays `invalid` and ends as `needs_more_info` for a human. `meta.retry_reason` says which check fired.

## How the pipeline calls it
`triage/pipeline.py` (`triage_alert`) is the only caller:
```python
pack = collect(alert)                                   # B3 EvidencePack (pack["trace"] goes to the ticket)
prompt, result = run_prompt(pack)                       # build + llm.call_structured + citation and D-6 checks (+1 retry)
verdict = result.parsed if result.ok else llm.needs_more_info_verdict(result)
facts = facts_for(pack, verdict, prompt)                # triage/facts.py: evidence + verdict -> policy facts, by code
decision = policy.evaluate(facts)                       # severity, SLA, escalation, approvers
```
- `TriagePrompt` fields: `system`, `user`, `prompt_version` (`c2-v3`), `specialist`, `runbook_supported`, `allowed_event_ids`, `untrusted_fields`, `nonce`, `alert_id`, `authorized_changes`, `possible_changes`.
- The cache key (C1) includes both system texts, the evidence, the schema and `prompt_version`, so changing a prompt file, the schema or the version never reuses an old answer.
- The runner (`triage/runner.py`) saves a ticket whose `model_info.status` is not `ok` so a person sees it, but counts it as an error: it is retried on the next run and never propagated to cluster members.

## Live check (Sat 7 Nov, 22:00–22:20, 8 workers)
22 regression alerts from the dev split plus 3 unseen routine-inventory alerts from the dev sample. Baseline (C2 as merged) vs final:

| | Baseline | Final |
|---|---|---|
| Valid answers | 22/22 | 25/25 |
| Median / mean latency | 14.6 s | 14.1 s / 16.0 s |
| Routine inventory under an approved change → FP + `tune_rule` | 0 of 3 | 5 of 6 (3 of them never used for tuning); **7 of 7 after the `routine` fix (Sun 00:30), incl. the cluster representative** |
| BTP without an applying, cited authorization | 2 | 0 (the guard fired once and the retry gave FP) |
| Planted injection notes flagged and not obeyed | 2 of 2 | 2 of 2 |
| Vela jailbreak flagged as injection against us | yes | no (judged as the alert's subject) |

The validation alerts were also the tuning alerts, so these numbers are optimistic; the holdout is the honest score.
