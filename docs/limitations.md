# Known limitations

What the system does not solve, or solves only in part. Each line was written when the weakness was found, with the number that shows it. The numbers come from the run on the organizers' dataset, which is private; the mock data in this repository is much smaller. Component IDs (B2, C2, D6…) are explained in [design.md](design.md#component-ids).

## Scope

- **Level 3 (investigation) is not built.** Alerts are grouped into incidents, and the console lists each incident's alerts in order with what links them, but nothing writes the investigation report (`informe_incidente`: patient zero, timeline, scope, root cause). A person reconstructs the attack chain from the incident view.
- **Containment is approved and executed per ticket.** There is no incident-wide containment plan run in one step.
- **The data is synthetic.** Four weeks of generated activity, without the variety and mess of a real SOC. The mock week shipped here is smaller and cleaner still: its scenarios were written to exercise each runbook.

## The AI model and the gateway

- **Evidence leaves the laptop for the UAB DCC gateway** (organizer-provided, OpenAI-compatible). Acceptable because the dataset is synthetic; production would need a private deployment and pseudonymization.
- **The gateway's limits are not published**: `/models` gives no context window or output limit, and we have not seen a rate-limit response. A realistic 11K-token evidence pack worked; an over-long prompt or a 429 ends as `context_overflow` or `rate_limited` (classified from the error message), never as a verdict.
- **Latency is ~15 s per alert with thinking off** (median 14 s, mean 16 s, max 47 s; 8 workers, latency flat from 1 to 8 workers, measured Sat 7 Nov). With thinking on, `ornith` reasoned 8–16K tokens on the C2 prompt and every call truncated. The gateway is shared with other teams and its limits are not published: more than 8 workers is untested.
- **Thinking off is a trade-off**: the model writes no hidden reasoning, so the JSON is its only reasoning. `LLMVerdict` therefore writes evidence and summary before the verdict; even so the label can still disagree with the summary at the boundary (one routine-inventory alert came back BTP with a summary describing routine inventory; 5 of 6 were FP).
- **`ornith`'s reasoning cannot be tuned from C1**: the gateway accepts `reasoning_effort` but it had no visible effect, so `effort` is logged but not sent. Reasoning tokens count against the 8,192-token output budget; running out ends as `truncated`.
- **LLM disk-cache dedup is per process** (`triage/llm.py`): concurrent identical requests in one process make one API call; two separate processes can both call the API for the same key (the cache file itself stays consistent thanks to atomic writes).
- **C2 prompt limits**: the prompts can ask for Spanish text, evidence-only reasoning and refusal of embedded instructions, but only citations are checked by code (`check_citations`); language, calibration of `confidence` and whether the model really ignored an injection are not verified automatically. The system prompt is ~13,000 characters (~3,500 tokens) on every call.
- **`for_llm(pack)` saves only ~15 %** of the pack (the trace was already dropped). The biggest parts left are findings, related alerts and the raw alert; a pack can still reach ~11K tokens.
- **Odd confidences are not checked by code**: one correct BTP came back with confidence 0.0. Only citations and the BTP authorization are enforced.
- **Whitespace loops**: once seen live (6,728 trailing blanks); the retry at temperature 0.3 is tested offline only. Validation retries (empty or schema-invalid output) now also go at temperature 0.3, since an identical request at temperature 0 repeats the same output.
- **Technical strings are sometimes flagged as injection**: live, a decoded PowerShell inventory command was listed in `injection_detected` next to a real planted note. It doesn't change the verdict, but the console shows a false warning.
- **Live mode fences free text only at the top level of `evidence`**: an unseen alert that hides prose inside a nested object or list (e.g. `evidence.mail.body`) reaches the model unfenced, unless the key is on the known list (`triage/untrusted.py`). The system prompt still treats the whole alert as data, and the AI can't act or set severity.
- **Live alerts are judged with the logs we have**: the collectors look for related events in the dataset's logs. An unseen alert about entities or times outside them gets a thin evidence pack and tends to `needs_more_info` (seen live on an alert for an unknown rule).
- **c2-v3 was tuned on the dev set and checked on cluster representatives** (no holdout). Small rewordings of the RB-09 DNS rule moved borderline alerts between FP, TP and `needs_more_info` at temperature 0 (e.g. a printer beaconing to its vendor): the final wording was chosen on dev plus those representatives, so the DNS clusters are the least stable part of the result.

## Evidence and context checks

- The entity timeline indexes structured fields, URLs in EDR command lines and IPs in EDR logon descriptions. Indicators elsewhere in free text are only found through `data.mentions()`, a plain substring search that can return false matches.
- `data.vpn_session()` treats a session as open until that user's next disconnect for that IP. 7 disconnect events have no `assigned_ip`, so a few sessions can look longer than they were.
- Full-text searches (`data.mentions()`, `data.search_logs()` with text) scan every event: about 180 ms on a quiet machine and 350 ms when memory is tight, over the 200 ms target for indexed queries.
- **Query-latency tests depend on the machine's state** (not caused by C1): on one of our laptops `tests/test_data.py::test_queries_meet_the_200ms_target[mentions]` fails at 320–770 ms against 200 ms, and `[search_logs]` sometimes fails too (251–263 ms) when the laptop is hot; the other query-latency checks pass.
- **`approved_change` (B2) matches a change by its purpose, scope, window and the alert's own evidence.** An attack that fires the same rule an approved change expects, on an in-scope host, inside the window, and whose alert carries no contrary evidence (no "ninguna"/"ninguno", no unsigned process, no other change cited), would still be reported as covered. The LLM still sees all the other evidence, and the purpose list (`context.CHANGE_PURPOSES`) only knows the kinds of change in this calendar; an unknown kind is only "possible".
- **The D-6 BTP guard checks that a change is cited, not that it is the right one for every detail**: a BTP that names an applying change passes even if the model misread what the change allows. B2 already checks purpose, scope, window and the alert's own evidence.
- **D-6 for routine management activity relies on one list** (`context.ROUTINE_PURPOSES`: today only management PowerShell / inventory). A change of a kind not in the list is treated as authorizing a risky action, so its alerts can come back BTP instead of FP. Live (Sun 00:30): the SCCM cluster representative and 6 more routine-inventory alerts came back FP + `tune_rule` (7/7, one after the corrective retry); the 8 real BTPs stayed BTP.
- **`personal_data_payments` needs a code signal** (`pack["signals"]`: DLP matches, a sensitive bucket classification, PCI scope, an IBAN/payment request, customer accounts taken over or another customer's data requested, SIEM evidence naming the CRM, or an asset of the payments/CRM/payroll services). A real personal-data case without any of these signals loses its +1 (the reason is shown in `adjustments_ignored`).
- **The RB-03 shared-exit fact is behavioural**: an IP is called a shared exit when ≥ 5 of our accounts signed in correctly from it on ≥ 2 days in ±7 days and it is not anonymous infrastructure. An attacker using a shared corporate exit (e.g. a compromised device in the office) would be described as coming from a shared exit; the other RB-03 facts (MFA, device, post-login activity) still apply.
- **RB-06.5 (known pipeline) is strict on purpose**: it needs the identity's ONLY origin in ±7 days to be the internal CMDB host. 15 of the 50 bucket alerts fail it because the same deploy identity was also used from the attacker's address (the cloud-key theft) in that window. If the cluster representative is BTP, propagation copies it to them: those 15 should be triaged on their own.

## Clustering and propagation

- Clustering by rule signature (D1) only sees the evidence fields it groups on, so some context is invisible to the cluster and needs a per-alert re-check (D5):
  - UC-WEB-001: contracted-pentest alerts sit inside the large clusters and look like ordinary scanner noise.
  - UC-EDR-002: one 1,349-alert cluster hides variation in the decoded command and the time window.
  - UC-EML-001: the sender pattern does not say whether any user clicked the link.
  - UC-EDR-003: repeated detections on the same host are not visible per cluster.
- Propagation re-checks (context facts that differ from the representative's) and the per-member policy decision run on the alert's structured fields only. The representative's LLM adjustments are reused for the members; an adjustment that holds for the representative but not for one member (for example, "blocked, no effect") is not re-judged. About 1 minute for all members.
- VIP, privileged and OT alerts are pulled out of clusters and triaged one by one (~34 extra LLM calls), but alerts pulled out only for that reason are not nodes of the incident graph: nothing about them looks odd and shared hub entities would chain them into false incidents. If the LLM judges one of them malicious it is not automatically grouped. OT assets are matched by host name only, not by IP.
- Cluster members inherit the representative's text. The 889-alert privacy-relay cluster covers 597 different users, but the ticket title and summary name only the representative's user. Verdict, severity and escalation are still re-checked per member (VIP, HR, change); the wording is not rewritten per user.
- Cluster verdicts were checked by hand only for homogeneity: the 8 largest clusters (about 6,000 alerts) share the same rule, action and key evidence fields across all members. We did not re-read the evidence events behind every representative's verdict.
- `out/tickets.jsonl` is append-only, so after propagation it holds both versions of each representative ticket (290 lines for 245 tickets). Count and score tickets through `triage.store` (latest version per id), never by counting lines; `eval/run_eval.py` and the console already do.
- **One cluster is still decided wrongly after the c2-v3 re-run (Sun 09:00)**: the WeTransfer upload of campaign photos (`UC-DLP-001:1`, 55 alerts) comes back true_positive high and escalated, although the DLP found 0 personal-data matches and the label is false_positive: the AI reads "no approved flow" as an attack. It is one ticket that a person closes; re-running gives the same answer (LLM cache). Three more clusters (`UC-AI-001:2`, `UC-NET-001:4`, `UC-NET-001:5`, ~390 alerts) end as needs_more_info and escalated: honest, but noise for N2.
- Blocked internet scans: the model calls them `false_positive` + `tune_rule`, while the golden set (following the organizers' example ticket) labels them `true_positive`, informational. Severity, SLA and escalation come out the same, so triage is unaffected, but dev accuracy counts each as a miss (one of them heads a 731-alert cluster). The label convention is not settled.

## Incidents

- Incident grouping (D6 v1) links alerts only through shared entities, so it can split one attack whose stages share nothing:
  - a poisoned package (CI/CD alert) and the later use of the stolen AWS keys end up as two incidents;
  - a remote-access session on one laptop and the later compromise of the POS terminals are not connected.
- Alerts absorbed into a benign cluster (member role) never enter the incident graph, so an attack alert that looks like noise to its signature is not grouped.
- Incidents v2 joins stages through IPs and e-mail addresses cited in the collectors' findings and through user -> host pivots in the logs. The AnyDesk session on a store laptop stays out of the POS incident on purpose: it belongs to one account and the POS terminals to another with almost the same name (two different people), and the two must never be fuzzy-merged. Linking them needs a person or the investigator.
- Alerts covered by an approved change are left out of attack incidents. That relies on the `approved_change` flag being right: if it wrongly says "covered" for an attack, the alert is still triaged on its own but is not grouped. On the labeled alerts no attack alert was excluded.
- Known-benign package installs still join the supply-chain incident until tickets exist: the graph then drops alerts whose ticket says benign or false positive. A hub IP (the CI runner) also links the benign installs to the cloud alerts, so this is the weakest point of the grouping before the full run.

## Console, approvals and audit

- Reviewer and approver names in the UI are typed in, not authenticated, and `out/reviews.jsonl` is a local file. A real deployment needs SSO and a tamper-proof audit log.
- SLA in the queue compares triage time with the policy window, because the dataset is a replay of past weeks and has no live clock. It does not track how long a ticket has waited for a person.
- The console records one named person per containment action, even when the policy lists several approvers. It relies on that person having obtained the others' approval.
- `/approvals` still gives a token to any caller and doesn't check who is asking, so a token proves a click only because `ui/containment.py` is the only code that calls it. It also doesn't record the approver's role, so the N2 or business approval the policy asks for is not verified by the API. A real deployment needs authenticated approvers.
- The live page runs one batch at a time, in the console's process: restarting the console loses the table of progress (finished tickets are already saved), and stopping waits for the alert in progress.

## Evaluation

- **The live-check alerts were also the tuning alerts** (22 regression alerts; 3 routine-inventory alerts were unseen): dev numbers are optimistic; only the new holdout is an honest score.
- **The new holdout (12 alerts) mostly repeats patterns already labelled in dev**: it measures consistency on siblings more than novelty. All 12 labels are verified.
