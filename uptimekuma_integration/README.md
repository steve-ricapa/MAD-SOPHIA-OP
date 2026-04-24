# Uptime Kuma Real-time Agent

Agente Python para consumir telemetria de Uptime Kuma desde `/metrics`, convertirla al formato unificado de TxDxAI y enviarla al backend en tiempo real.

## Flujo

1. Lee metricas Prometheus de Uptime Kuma (`monitor_status`, `monitor_response_time`, `monitor_uptime_ratio`).
2. Normaliza el estado de monitores a severidades del dashboard.
3. Mantiene estado local en `state.json` para detectar cambios y evitar ruido.
4. Envia reporte al backend (`OUTPUT_MODE=webhook|all`) o imprime en consola (`stdout`).
5. Incluye `idempotency_key` por snapshot y cola local en disco para reintentos.

## Variables de entorno

- `UPTIME_KUMA_URL` (default: `http://127.0.0.1:3001`)
- `UPTIME_KUMA_METRICS_PATH` (default: `/metrics`)
- `UPTIME_KUMA_DB_PATH` (opcional, ejemplo: `C:\Users\diego\uptime-kuma\data\kuma.db`) para enriquecer con config, ultimo heartbeat, TLS y stats.
- `UPTIME_KUMA_USERNAME`, `UPTIME_KUMA_PASSWORD` (auth basica)
- `UPTIME_KUMA_API_KEY_ID`, `UPTIME_KUMA_API_KEY` (si Uptime Kuma tiene API Keys habilitadas)
- `OUTPUT_MODE` = `stdout | webhook | all`
- `TXDXAI_INGEST_URL`, `TXDXAI_COMPANY_ID`, `TXDXAI_API_KEY_UPTIMEKUMA` (fallback: `TXDXAI_API_KEY`)
- `POLL_INTERVAL_SECONDS` (default: `15`)
- `FORCE_SEND_EVERY_CYCLES` (default: `6`)
- `INCLUDE_ALL_MONITORS` (default: `false`) para incluir todos los monitores en cada reporte.
- `QUEUE_ENABLED` (default: `true`)
- `QUEUE_DIR` (default: `queue`)
- `QUEUE_FLUSH_MAX` (default: `20`)
- `REQUEST_TIMEOUT`, `HTTP_RETRIES`, `BACKOFF_SECONDS`, `VERIFY_SSL`
- `RAW_SNAPSHOT_PATH` (default: `raw_monitors_snapshot.json`)

## Ejecucion

Primero crea tu `.env` desde `.env.example`.

```bash
python agent.py
```

Ejecucion de un ciclo:

```bash
python agent.py --once
```

## Archivos locales

- `state.json`: estado persistente de cambios por monitor.
- `raw_monitors_snapshot.json`: snapshot crudo enriquecido por monitor (entrada real del ciclo).
- `debug_report.json`: ultimo payload generado.
- `last_payload_sent.json`: ultimo payload enviado cuando `OUTPUT_MODE=all`.
- `queue/*.json`: payloads pendientes cuando backend responde con errores transitorios (429/5xx o timeout/red).

## Nota de autenticacion en `/metrics`

- Si en Uptime Kuma esta desactivado `API Keys`, usa `UPTIME_KUMA_USERNAME`/`UPTIME_KUMA_PASSWORD`.
- Si `API Keys` esta activado, usa `UPTIME_KUMA_API_KEY_ID` (ID numerico) y `UPTIME_KUMA_API_KEY` (secreto).
