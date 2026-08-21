# Canonical schema v1

JSON Schema Draft 2020-12 for the ETL V2 canonical contract.

Files:

- `envelope.schema.json`: delivery boundary.
- `run.schema.json`: extraction execution metadata.
- `asset.schema.json`: source-scoped asset identity.
- `observation.schema.json`: availability and operational telemetry.
- `finding.schema.json`: vulnerabilities and applicable problems.
- `detection.schema.json`: security alerts and events.
- `common.schema.json`: shared definitions.

The business payload must never include API keys, passwords, tokens or transport credentials. Optional unavailable values are omitted instead of replaced with placeholders.

Install and run the contract tests from the repository root:

```text
python -m pip install -r requirements-dev.txt
python -m unittest tests.test_canonical_schemas -v
```
