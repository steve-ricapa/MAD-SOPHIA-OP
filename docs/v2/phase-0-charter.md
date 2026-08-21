# V2 Phase 0: Project Charter

## Thesis Topic

Mejora en la adquisicion y filtrado de eventos de red y seguridad mediante ETL automatizado en TXDXSECURE S.A.C., SMP, 2026.

## Problem Statement

TXDXSECURE recopila informacion de seguridad y monitoreo desde plataformas independientes. Consultar cada plataforma por separado fragmenta el contexto operativo, genera ruido y dificulta priorizar hallazgos relevantes. Los datos actuales pueden incluir duplicados, campos incompletos, formatos distintos y eventos de bajo valor para el analisis.

## V2 Objective

Diseñar e implementar un ETL resiliente que centralice, filtre, normalice, valide y entregue datos relevantes de red y seguridad. La salida debe ser confiable para analistas SOC, administradores TI y consumidores de IA posteriores.

## Initial Demonstration Scope

- Sources: Uptime Kuma and Zabbix.
- Execution: continuous service with a one-cycle mode for testing and operations.
- Deployment: a container running in a customer appliance with 4 CPU cores and 8 GB RAM.
- Tenancy: multi-tenant design. Tenant data must remain isolated in processing, state, queues, logs and delivery.
- Initial validation: run each source locally, verify the full ETL pipeline and deliver the resulting data to the existing backend.
- Capabilities: extraction, filtering, normalization, validation, deduplication, durable state, retries, local queue, delivery and observability.
- Data domains: availability signals, monitored assets, hosts, services and Zabbix events/problems that pass relevance policies.

## Explicitly Out of Scope for the First Demonstration

- Automated remediation.
- Blocking ETL execution on a local AI or ML model.
- Migration of Nessus, OpenVAS, InsightVM and Wazuh before the core is validated.
- A final AWS deployment design.
- Local AI or ML workloads that compromise the appliance resource budget.

## Architecture Principles

- Source connectors only acquire source-specific data.
- Processing is streaming or paginated. The service must not load full source datasets into memory.
- Resource use is bounded with connector concurrency, page-size, payload-size and queue-size limits.
- A shared pipeline applies filtering, canonical normalization, validation, deduplication and delivery.
- Data is not sent when it is empty, invalid, stale or missing required identity fields.
- Each execution and record is traceable with source, timestamps, identifiers and processing outcome.
- Delivery is at-least-once with deterministic idempotency so retries do not create duplicate business records.
- Secrets never appear in source control, logs, queues or diagnostic payloads.
- Configuration is typed, validated at startup and separated between local development and production.

## Initial Data Handling Policy

- The initial deployment uses one tenant configured through environment variables. Every canonical record still carries its tenant identifier so the data contract is ready for multi-tenant operation.
- IP addresses, hostnames, ports, software versions, CVEs and bounded technical evidence are retained when they are required to identify an asset, assess risk or support future remediation.
- Credentials, API keys, session tokens and passwords are never included in extracted records, logs, queues, diagnostics or reports.
- Operational logs use record identifiers and counts instead of raw asset details or evidence.
- Raw evidence is limited by size and field allowlists. Full raw API responses are not retained by default.
- Data sent outside the appliance must use TLS. Local state and queue storage require restricted filesystem permissions and must not be versioned.
- A future management interface may manage tenant and connector configuration through an authenticated API and secret store. It must not edit or expose .env files directly.

## Preliminary Success Criteria

- Both initial sources produce records under one versioned canonical contract.
- Configurable relevance filters reduce low-value records without losing defined critical conditions.
- Repeating the same source data does not create duplicate output records.
- A restart resumes from durable state or safely reprocesses data with idempotency.
- Network and destination failures preserve pending data in a durable queue and recover automatically.
- Invalid or incomplete records are quarantined with an explainable validation reason.
- The service provides health status, structured logs and execution metrics.
- Automated tests cover core transformation, validation, deduplication and failure recovery paths.
- Evaluation compares V1 and V2 with equivalent input data, and includes controlled failure-recovery tests.

## Decisions Pending

- Expected scale: tenants, monitored assets and events per day. Initial local tests establish the baseline load profile before appliance limits are fixed.
- Data classification and privacy rules: internal IPs, hostnames, evidence and personal data. Credentials are never persisted outside the configured secret store.
- Target availability, recovery objectives and acceptable delivery latency.
- Final destination and consumer contract in AWS.
- Exact filtering policy for Zabbix severity and Uptime Kuma status changes. The initial policy includes critical and high records, plus medium records that meet defined contextual conditions.
- Evaluation metrics and baseline measurements to demonstrate thesis improvement.
- Appliance resource budget and operational limits: CPU, memory, disk quota, network availability and expected source/API latency. The target appliance provides 4 CPU cores and 8 GB RAM.

## Future Evolution

Once the core is validated, migrate Nessus, OpenVAS, InsightVM and Wazuh through the same connector contract. AI or ML can become a separate enrichment consumer that prioritizes or summarizes validated data without blocking acquisition.
