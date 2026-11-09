# Evaluation report

## dev

- Labeled alerts: 54, with a ticket: 54
- Verdict accuracy: 0.926
- True positives: 26, **missed** (judged benign): 0, deferred to a human: 1
- Benign alerts: 28, false alarms: 0
- Should escalate: 20, missed escalations: 0
- Twin pairs: 10, both alerts right: 9
- Confidence: mean 0.804 when right, 0.5 when wrong; no confidence on 0 tickets; correct but under 0.3: ['ALR-20261014-700066']
- Severity exact: 0.833, within one level: 0.944
- Incidents: 13, kept whole: 9, split across tickets: {'paperkite-finanzas': 7, 'spray-atencion-cliente': 2, 'phishing-buzon-marketing': 2, 'supply-chain-npm-aws': 2}, alerts without a ticket: {}, tickets mixing incidents: 0, mixing with benign: 0
- Cost: $0, mean seconds per ticket: 35.86

## holdout

- Labeled alerts: 13, with a ticket: 13
- Verdict accuracy: 1.0
- True positives: 9, **missed** (judged benign): 0, deferred to a human: 0
- Benign alerts: 4, false alarms: 0
- Should escalate: 9, missed escalations: 0
- Twin pairs: 3, both alerts right: 3
- Confidence: mean 0.823 when right, None when wrong; no confidence on 0 tickets; correct but under 0.3: none
- Severity exact: 0.923, within one level: 1.0
- Incidents: 8, kept whole: 7, split across tickets: {'supply-chain-npm-aws': 2}, alerts without a ticket: {}, tickets mixing incidents: 0, mixing with benign: 0
- Cost: $0, mean seconds per ticket: 33.96

## all splits together (grouping only)

- Incidents: 17, kept whole: 11, split across tickets: {'paperkite-finanzas': 7, 'spray-atencion-cliente': 3, 'phishing-buzon-marketing': 2, 'insider-compras': 2, 'ato-tienda-online': 2, 'supply-chain-npm-aws': 4}, alerts without a ticket: {}
- Tickets mixing incidents: 0, tickets mixing an incident with benign/noise alerts: 0

