# Design

How the triage system is built and why. The [README](../README.md) is the overview; this page holds the decisions behind the code.

## The pipeline, step by step

1. **Entities** (`triage/entities.py`). Users, hosts, IPs, domains, hashes and message ids are taken from the alert's structured fields and normalized. Identities are matched exactly: `candela.ruiz2` is not `candela.ruiz`.
2. **Route** (`triage/cluster.py`, `triage/runner.py`). Each noisy rule has a signature, the evidence fields that make two alerts "the same". Its alerts form clusters, and the AI judges one representative per cluster. Alerts that don't fit (rare rules, critical base severity, VIP, privileged or OT assets, young domains, alerts without a signature) are judged one by one. Result: 215 AI calls for 11,061 alerts.
3. **Evidence** (`triage/context.py`, `triage/collectors/`). Each runbook's checks become queries over a DuckDB copy of the logs and inventories. Every finding carries the `event_id`s that prove it, and every query is traced for the console. The context checks answer what an analyst asks first: is there an approved change that really applies (purpose, scope, window and the alert's own evidence), an internal rule, an HR fact (travel, leaver, new hire)? Attacker-written text is listed as `untrusted`.
4. **AI verdict** (`triage/prompts/`, `triage/llm.py`). One structured call per alert with a strict JSON schema. The system prompt is the shared rules plus one specialist per runbook. Code then checks that every cited event exists in the evidence, and that a "benign true positive" cites an authorization that applies. A failed check gets one retry with a note; a second failure, or any gateway error, becomes `needs_more_info` and goes to a person.
5. **Policy** (`triage/facts.py`, `triage/policy.py`). Code turns the evidence and the verdict into facts, and the policy engine computes the final severity (the matrix with the most critical asset, identity or service involved, adjustments clamped to ±1, runbook minimums), the SLA, mandatory escalation and who must approve each action. The AI never sets any of these.
6. **Propagation** (`triage/propagate.py`, `triage/member_policy.py`). A cluster member inherits its representative's verdict only if its own context facts match (approved change, HR, internal rules); the policy runs again on the member's own assets and identities. Members whose facts differ leave the cluster and are triaged on their own (30 in the full run).
7. **Incidents** (`triage/correlate.py`, `triage/link_sources.py`). An entity graph with time windows per entity type groups related alerts. It also follows the IPs and e-mail addresses cited in findings, and user-to-host pivots in the logs. Alerts covered by an approved change, and alerts whose ticket is benign, stay out of attack incidents.
8. **Console and response** (`ui/`, `api/`). A person reviews each ticket, accepts or corrects it, and approves containment. Only `ui/containment.py` calls the SOC API: `/approvals` issues a single-use token bound to the action, target and ticket, and `/containment` re-checks the policy before it acts.

## Why a hybrid pipeline

| Option | Why not, or why |
|---|---|
| One agent per alert, with tools | Slow and costly on 11,061 alerts, and an agent can skip a runbook check. |
| A swarm of specialist agents | Strong on paper, hard to debug and to trust in 24 hours. |
| **Code gathers, the AI judges, code applies the policy** (chosen) | Runbook checks always run, severity is deterministic, every claim cites an event, and clustering makes the full queue affordable. The per-runbook specialists borrow the best idea of the swarm. |

## Facts from the data that shaped the design

From the organizers' dataset (private; this repository ships an invented mock instead).

1. **Extreme skew.** Nine rules produce 10,616 alerts (96 %). The 26 rarest rules produce 86 alerts, and that is where most incidents are.
2. **Every noisy rule has one dominant benign pattern plus a few needles.** All 1,349 `UC-EDR-002` alerts are a software inventory under an approved change; `UC-NET-001` has 744 SaaS heartbeats and 2 real C2 beacons.
3. **Twin pairs.** Some alerts share a rule but need opposite verdicts: the same action done under an approved change, and done by an attacker.
4. **Planted prompt injection.** Attacker-written text addressed to the automated triage, hidden in e-mails, service descriptions and prompts sent to the AI shopping assistant.
5. **Incidents span days and several rules.** Stolen credentials can be reused a week later, and an alert can be created after the events it describes, so timelines use event timestamps.
6. **Time zones.** Data is UTC; change windows and business hours are local, so rules are judged in `Europe/Madrid` (daylight saving ends on 25 Oct 2026).
7. **Identities.** One person appears as a UPN, a username and `TARVIA\username`, and different people have near-identical names, so identities are matched exactly and never fuzzy-merged.

## Who decides what

| Decision | AI | Person | Enforced by |
|---|---|---|---|
| Evidence gathering, enrichment, correlation | does it (read-only) | — | collectors only read |
| Verdict, summary, recommended actions | proposes, citing evidence | accepts or corrects, with a reason | console review |
| Final severity, SLA, escalation | supplies facts and ±1 proposals | can override | `triage/policy.py` |
| Any containment action | proposes only | approves in the console | `ui/containment.py` is the only caller of `/approvals` and `/containment`; a test fails if code under `triage/` imports the console or the API, or names those endpoints |
| Anything in OT | never acts | Operations | policy and API refuse it |

## Policy decisions (D-1..D-6)

The organizers' SOC policy (not included in this repository) leaves a few cases open. The team settled them as follows; `triage/policy.py` implements them and the golden-set labels follow them.

| # | Decision | Rule |
|---|---|---|
| D-1 | Identity criticality = what the identity can access | `adm.*` and domain admins → Crítica · `svc_*` → criticality of its business service · `ext.logisoft` → Alta (WMS) · regular users → Media · customers → Crítica (online store). The matrix column is the most critical asset, service or identity involved. |
| D-2 | No double-counting of VIP or privileged | The +1 for a VIP or privileged identity applies only if that same privilege hasn't already set the column. |
| D-3 | Unaffected target → Baja | If the target doesn't exist or wasn't really affected, the asset column is Baja. This reproduces the organizers' example ticket while keeping the ±1 cap. |
| D-4 | `block_ioc` and `purge_email`: the AI proposes, a person confirms | The policy lets an N1 run them, but nothing executes without a click. Dual-use services (mega.nz, AnyDesk) are never blocked globally without N2 (`policy.DUAL_USE_SERVICES`). |
| D-5 | A runbook's explicit severity is a minimum | When a runbook sets a severity for a case (an unverified IBAN change request is critical), the final severity can't be lower. It never applies to benign or false-positive verdicts. |
| D-6 | False positive vs benign true positive | **Benign true positive**: the activity is what the rule hunts for, done by someone authorized (pentest, scanner, PsExec inside an approved change). **False positive**: routine operation the rule shouldn't flag at all, even if a change documents it; the ticket proposes tuning the rule. |

The adjustment reasons shared by the policy engine and `LLMVerdict.adjustments[].reason_type` are `confirmed_execution`, `vip_privileged`, `personal_data_payments` and `blocked_no_effect`.

## Data contracts

- **`LLMVerdict`** (`triage/schemas.py`), the model's structured output: title, verdict, confidence, summary, `evidence[{event_id, source, finding}]`, `adjustments[{delta, reason_type, reason}]`, MITRE techniques, `recommended_actions[{action, target, justification}]`, escalation suggestion, open questions and `injection_detected[{field, excerpt}]`. Actions are containment actions plus workflow steps (`close`, `escalate`, `notify`, `investigate`, `tune_rule`). The model never outputs final severity, approvals or executed actions. Field order is part of the contract: evidence and summary come before the verdict, so the label follows the facts.
- **`EvidencePack`** = `triage.collectors.collect(alert)`, a plain dict: the alert and its entities, context (flags, changes that apply), inventory (assets, identities), intel, related alerts, `findings[{check, fact, source, event_ids, notable}]`, `untrusted[{field, text}]` and the query `trace`. The trace is for the console; `collectors.for_llm(pack)` is what the model sees.
- **`Ticket`**: every field of the organizers' `ticket_salida.schema.json`, validated when `triage/store.py` saves it, plus the fields the console reads (`severity_calc`, `trace`, `routing`, `model_info`, `human_review`, `action_decisions`…). `out/tickets.jsonl` is append-only; read it through `triage.store`, which keeps the latest version of each ticket.
- **`Incident`** (`out/incidents.jsonl`): `stage: "grouped"`, with alert ids, shared entities, rules and time span. The investigation report (`informe_incidente.schema.json`) is level 3 and not built.
- Ticket text is Spanish; code, comments and docs are English.

## The LLM

- **Model and gateway.** `ornith`, served by the hackathon's UAB DCC GPU gateway (OpenAI-compatible), called with the official `openai` SDK. `triage/llm.py` is the only entry point and refuses any other host.
- **Structured output.** `response_format` is a strict JSON schema built from `LLMVerdict`; pydantic validates the reply. Temperature 0 and a fixed seed.
- **Prompt layout.** The static part (role, company rules, the runbook specialist) goes in the system messages, so it is identical for every alert of a runbook; the evidence goes last. Details: [prompts.md](prompts.md).
- **Thinking off.** About 15 s per call. With the model's reasoning phase on, calls took minutes and truncated.
- **Robustness.** A disk cache keyed by the request makes re-runs instant (`LLM_OFFLINE=1` replays it without network). Errors (bad key, rate limit, timeout, malformed output, context too long) end as `needs_more_info` for a person, never as a made-up verdict.
- **Data.** Evidence leaves the machine for the gateway. Acceptable here because the dataset is synthetic; a real deployment needs a private model and pseudonymized personal data.

## Engineering rules

- **The holdout is sealed.** `eval/holdout.jsonl` is read only by `eval/run_eval.py` and by the person who labels it. Whoever tunes prompts or triage logic never opens it, and its labels never appear in prompts, code or tests. Tuning uses `eval/golden_set.jsonl`.
- **Containment needs a person.** Only `ui/containment.py`, after a click, calls `/approvals` and `/containment`. Nothing is ever done on OT.
- **The policy is the single source of truth** for severity, SLA, escalation, approvers and the dual-use list. The UI and the API call `policy.action_policy()` instead of repeating its rules.
- **Attacker-written text is data, never instructions.** Email bodies, subjects, command lines, prompts and service descriptions are fenced off in the prompt with a per-alert nonce.
- **Facts, not verdicts.** Context checks and collectors return facts with `event_id`s; the AI decides the verdict; the policy computes severity.
- **Real IOCs.** Some indicators in the dataset are real and malicious: look them up only in reputation services, never visit, download or scan them.
- **No secrets or derived files in git.** The LLM key lives only in `.env`; the DuckDB file and the LLM cache are rebuilt locally.

## Component IDs

Code comments refer to the components by the IDs of the build plan:

| ID | Component | Where |
|---|---|---|
| A1–A5 | Data platform: DuckDB loader, query primitives, fast SOC API, entity extraction, ticket and incident store | `triage/loader.py`, `data.py`, `entities.py`, `store.py`, `api/` |
| B1 | Policy engine and decisions D-1..D-6 | `triage/policy.py` |
| B2 | Context checks (approved changes, internal rules, HR) | `triage/context.py` |
| B3 | Runbook collectors and the EvidencePack | `triage/collectors/` |
| B4, B5 | Golden set and incident ground truth | `eval/` |
| C1 | LLM wrapper | `triage/llm.py` |
| C2, C3, C6 | Triage prompts, injection hardening, prompt tuning on the dev set | `triage/prompts/`, `triage/untrusted.py` |
| C4 | `triage_alert()`: evidence → AI → policy → ticket | `triage/pipeline.py`, `triage/facts.py` |
| C5 | Deep-dive agent with read-only tools | not built |
| C7 | Live mode for alerts never seen before | `triage/live.py` |
| D1, D2 | Alert profiling and clustering | `triage/profile_alerts.py`, `triage/cluster.py` |
| D3 | Evaluation harness | `eval/run_eval.py` |
| D4 | Full-queue runner | `triage/runner.py` |
| D5 | Propagation with per-member re-checks | `triage/propagate.py`, `triage/member_policy.py` |
| D6 | Incident grouping (v1: alert graph; v2: findings and log pivots) | `triage/correlate.py`, `triage/link_sources.py` |
| D7 | Level-3 investigator | not built |
| D8 | Metrics and rule-tuning proposals | [rule_tuning.md](rule_tuning.md) |
| E1–E5 | Console: queue, ticket detail, review and approval, live triage, incidents | `ui/` |
| F1–F7 | Deliverables: deck, committee one-pager, docs, demo | `docs/` |
