# Evaluation report

## dev

- Labeled alerts: 54, with a ticket: 18
- Verdict accuracy: 0.0
- True positives: 18, **missed** (judged benign): 0, deferred to a human: 0
- Benign alerts: 0, false alarms: 0
- Should escalate: 16, missed escalations: 16
- Twin pairs: 2, both alerts right: 0
- Confidence: mean None when right, None when wrong; no confidence on 18 tickets; correct but under 0.3: none
- Severity exact: None, within one level: None
- Incidents: 13, kept whole: 9, split across tickets: {}, alerts without a ticket: {'tunel-dns-logistica': 1, 'mfa-fatigue-atencion-cliente': 1, 'logisoft-sabado-noche': 1, 'adm-domain-admins-sabado': 1}, tickets mixing incidents: 2, mixing with benign: 0
- Cost: $0, mean seconds per ticket: None
- No ticket for: ALR-20261012-700075, ALR-20261012-700086, ALR-20261012-700144, ALR-20261012-700230, ALR-20261012-700284, ALR-20261013-700041, ALR-20261013-700057, ALR-20261013-700071, ALR-20261013-700098, ALR-20261013-700212, ALR-20261013-700218, ALR-20261013-700224, ALR-20261013-700258, ALR-20261013-700273, ALR-20261014-700008, ALR-20261014-700017, ALR-20261014-700026, ALR-20261014-700035, ALR-20261014-700049, ALR-20261014-700066

## holdout

- Labeled alerts: 13, with a ticket: 6
- Verdict accuracy: 0.0
- True positives: 6, **missed** (judged benign): 0, deferred to a human: 0
- Benign alerts: 0, false alarms: 0
- Should escalate: 6, missed escalations: 6
- Twin pairs: 0, both alerts right: 0
- Confidence: mean None when right, None when wrong; no confidence on 6 tickets; correct but under 0.3: none
- Severity exact: None, within one level: None
- Incidents: 8, kept whole: 5, split across tickets: {}, alerts without a ticket: {'vela-datos-de-otro-cliente': 1, 'ot-modbus-desde-portatil': 1, 'anydesk-tienda-t05': 1}, tickets mixing incidents: 1, mixing with benign: 0
- Cost: $0, mean seconds per ticket: None
- No ticket for: ALR-20261013-700268, ALR-20261014-700126, ALR-20261014-700236, ALR-20261015-700259, ALR-20261015-700260, ALR-20261016-700123, ALR-20261016-700261

## all splits together (grouping only)

- Incidents: 17, kept whole: 10, split across tickets: {}, alerts without a ticket: {'tunel-dns-logistica': 1, 'mfa-fatigue-atencion-cliente': 1, 'logisoft-sabado-noche': 1, 'adm-domain-admins-sabado': 1, 'vela-datos-de-otro-cliente': 1, 'ot-modbus-desde-portatil': 1, 'anydesk-tienda-t05': 1}
- Tickets mixing incidents: 2, tickets mixing an incident with benign/noise alerts: 0

