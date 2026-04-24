# Zabbix Real-time Agent

Agente Python que consulta Zabbix por API, arma un reporte tipo `vuln_scan_report`, evita reenviar duplicados usando estado local y publica el resultado al backend de TxDxAI.

## Flujo

1. Carga configuracion desde `.env`.
2. Consulta problemas, hosts y triggers de Zabbix.
3. Resume findings activos y resuenes de salud por host.
4. Evita duplicados comparando fingerprints contra `state.json`.
5. Envia al backend y guarda copias de debug locales.

## Variables principales

- `ZABBIX_API_URL`, `ZABBIX_USER`, `ZABBIX_PASS`
- `OUTPUT_MODE`, `TXDXAI_INGEST_URL`, `TXDXAI_COMPANY_ID`, `TXDXAI_API_KEY_ZABBIX` (fallback: `TXDXAI_API_KEY`)
- `VERIFY_SSL`, `REQUEST_TIMEOUT`, `HTTP_RETRIES`, `BACKOFF_SECONDS`
- `PROBLEMS_LIMIT`, `TRIGGERS_LIMIT`, `EVENTS_LIMIT`, `INCLUDE_EVENTS`
- `STATE_FILE`, `DEBUG_REPORT_PATH`, `LAST_PAYLOAD_PATH`

## Ejecucion

```bash
python agent.py
```

## Archivos locales

- `state.json`: estado persistente de deduplicacion.
- `debug_report.json`: ultimo reporte generado.
- `last_payload_sent.json`: ultimo payload enviado cuando `OUTPUT_MODE=all`.

## Recomendaciones operativas

- Usa `VERIFY_SSL=true` en produccion con un certificado valido.
- Rota cualquier credencial historica que haya quedado expuesta en pruebas anteriores.
- Si el entorno crece, sube los limites o implementa paginacion en la API.
