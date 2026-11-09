# Rule-tuning proposals from the false-positive clusters

Generated from the ticket store and `out/clusters.csv` after the full run on the organizers' dataset (Sun 8 Nov 2026). That dataset is private, so the numbers below are from that run and the patterns are described without its names. Tickets counted: `false_positive`, not escalated, with a `tune_rule` action. **5,848 of 11,061 alerts (53 %) belong to such tickets.**

> **This is an upper bound, not a promise.** The verdicts are the AI's, copied from one representative to every member of its cluster. A person must confirm each pattern before a rule is changed, and a tuned rule must keep firing on the variants that matter (VIP or privileged users, young domains, OT, any alert outside the pattern). Computed on the c2-v3 run. Blocked WAF scans (UC-WEB-001) are no longer here: with c2-v3 they are true positives at informational severity, as in the organizers' example ticket. UC-OT-001 appears with 3 alerts; nothing is ever done on OT, so those are a question for a person, never an automatic change.

## By rule

| Rule | Alerts in tuning-candidate tickets | Rule total | Share | Largest patterns |
|---|---|---|---|---|
| UC-EML-001 | 1,645 | 2,295 | 72 % | Marketing newsletters and a document-signing service reported as phishing by mistake |
| UC-EDR-002 | 1,349 | 1,349 | 100 % | Daily software inventory run by SCCM |
| UC-IDP-001 | 899 | 901 | 100 % | Corporate phones leaving through a shared privacy-relay exit |
| UC-NET-005 | 561 | 561 | 100 % | Long subdomains of cloud and CDN providers |
| UC-EDR-001 | 531 | 532 | 100 % | The ERP client launched from Excel in Finance |
| UC-NET-001 | 462 | 746 | 62 % | Windows Update, Teams and Google update traffic |
| UC-AI-001 | 308 | 415 | 74 % | Customers rephrasing their own question to the shopping assistant |
| UC-NET-006 | 79 | 91 | 87 % | CDN, anti-spam and antivirus lookups with long DNS labels |
| UC-DEV-001 | 10 | 11 | 91 % | A headless-browser package downloading its binary at install time |
| UC-OT-001 | 3 | 10 | 30 % | Engineering-workstation traffic to the OT network |
| UC-DLP-001 | 1 | 59 | 2 % | Campaign photos uploaded to a file-transfer service |

## What to propose to Tarvia (for the committee page and the Q&A)

- **Suppress or downgrade known-good management traffic** (SCCM inventory under UC-EDR-002; Windows, Teams and Google update beacons under UC-NET-001): it fires every day and always explains itself. Keep the rule for unsigned or unexpected parents.
- **Add the corporate phones' privacy-relay exit as a known shared exit for UC-IDP-001** (travel alerts). Keep the alert for admin and VIP accounts.
- **Turn blocked WAF probes (UC-WEB-001, 3,406 alerts, true positive informational) into a daily count instead of one alert each**; alert only when a probe is not blocked or the target exists.
- **Known-good CDN subdomains (UC-NET-005) and legitimate shopping-assistant corrections (UC-AI-001)** are the next biggest patterns: allowlist the CDN families and stop flagging customers who rephrase their own question.
- **Route user-reported newsletters and phishing drills (UC-EML-001) by sender reputation**: bulk senders and internal drills should not page anyone.
- **Excel to the ERP client (UC-EDR-001)** is the finance workflow: allow the signed chain.

## How it was computed

Tickets from `triage.store.default_store().load_tickets()` (latest version per id) with verdict `false_positive`, `escalation.escalate = false` and `tune_rule` in `recommended_actions`; each ticket's `alert_ids` assigned to rules through `out/clusters.csv`. Rerun after the re-triage of the corrected representatives, because the numbers will move.
