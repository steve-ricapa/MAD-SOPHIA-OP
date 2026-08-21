# V2 Phase 0: Evaluation Plan

## Validation Sequence

1. Run each initial source locally against a controlled Uptime Kuma or Zabbix environment.
2. Verify extraction, filtering, normalization, validation, deduplication, persistence and delivery independently.
3. Send valid canonical payloads to the existing backend.
4. Repeat the same input to verify idempotency and duplicate prevention.
5. Simulate source, network and backend failures to verify queueing and recovery.
6. Compare the V1 and V2 outputs from equivalent input data.

## Initial Relevance Policy

- Keep critical and high security or availability records.
- Keep medium records only when a defined contextual rule applies, such as an affected critical asset, repeated condition, externally exposed service or defined operational impact.
- Drop or aggregate informational and low-value records unless they are required to calculate asset context or a summary metric.
- Record every filtering decision with a reason and policy version.

## Metrics

| Metric | Purpose |
| --- | --- |
| Input records vs accepted records | Measures noise reduction. |
| Invalid records and validation reasons | Measures data quality. |
| Duplicate records prevented | Measures deterministic identity and idempotency. |
| Delivery success, queue depth and recovery time | Measures fault tolerance. |
| End-to-end delivery latency | Measures operational usefulness. |
| Memory and CPU during controlled runs | Establishes the appliance capacity baseline. |
| V1 vs V2 output quality | Demonstrates the thesis improvement. |

## Local Retention

- Keep operational state, pending queue items and minimal diagnostic evidence for up to seven days.
- Do not retain raw source responses by default.
- Expire data automatically and record retention cleanup outcomes in metrics.
