# Wazuh Integration Agent

Conector incremental para extraer alertas desde Wazuh, normalizarlas y enviarlas al backend TxDxAI.

## Que hace

- Consulta alertas del indexer en bucle (`POLL_INTERVAL_ALERTS`).
- Filtra por severidad minima (`MIN_RULE_LEVEL`).
- Evita reenvio de duplicados usando:
  - checkpoint temporal (`alerts_timestamp`), y
  - tabla de IDs procesados en SQLite (`processed_alerts`).
- Si el backend falla, guarda el payload fallido para reintento/manual review.
- Reintenta automaticamente payloads fallidos cada `RETRY_FAILED_INTERVAL_SECONDS`.
- Envía payloads al backend (`TXDXAI_INGEST_URL`).
- Guarda evidencia local de cada ciclo para auditoria y analisis.

## Estructura

```text
wazuh_integration/
  main.py
  .env.example
  requirements.txt
  src/
    aggregator.py
    api.py
    indexer.py
    sender.py
    state.py
  state/
    agent_state.db
  artifacts/
    logs/
    raw_batches/
    payloads/
    failed_payloads/
```

## Variables principales

- Wazuh API: `WAZUH_API_HOST`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD`
- Wazuh Indexer: `WAZUH_INDEXER_HOST`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`
- Backend: `TXDXAI_INGEST_URL`, `TXDXAI_COMPANY_ID`, `TXDXAI_API_KEY`
- Bucle: `POLL_INTERVAL_ALERTS=30`, `POLL_INTERVAL_AGENTS=60`
- Reintentos: `RETRY_FAILED_INTERVAL_SECONDS=30`
- Filtro: `MIN_RULE_LEVEL=7`
- Estado: `CHECKPOINT_FILE=state/agent_state.db`
- Evidencias: `ARTIFACTS_DIR=artifacts`
- Heartbeat opcional: `SEND_HEARTBEAT=false`
- Seguridad TLS: `WAZUH_API_VERIFY_TLS`, `WAZUH_INDEXER_VERIFY_TLS`

## Perfiles por cliente

Puedes tomar valores base desde:

- `wazuh_integration/config_profiles/client_realtime_30s.env`
- `wazuh_integration/config_profiles/client_standard_15m.env`
- `wazuh_integration/config_profiles/client_lowfreq_1h.env`

## Ejecucion

```bash
py -m pip install -r requirements.txt
py main.py
```

## Archivos de salida

- Logs del agente: `artifacts/logs/agent_console.json`
- Lotes crudos recibidos: `artifacts/raw_batches/raw_*.json`
- Payloads enviados: `artifacts/payloads/payload_*.json`
- Payloads fallidos: `artifacts/failed_payloads/failed_*.json`

Con esto puedes auditar exactamente que llego desde Wazuh y que se intento enviar al backend en cada ciclo.

## Tests

```bash
py -m unittest discover -s tests -p "test_*.py"
```
