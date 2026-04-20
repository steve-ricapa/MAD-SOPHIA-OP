# Nessus Real-time Agent

Agente Python para consumir datos de Nessus, normalizarlos al formato unificado de TxDxAI y enviarlos al backend en tiempo real.

## Flujo

1. Consulta `/scans` para listar escaneos.
2. Filtra por estado (`completed/imported`) y opcionalmente por `NESSUS_SCAN_IDS` o `NESSUS_FOLDER_ID`.
3. Obtiene detalles de cada scan (`/scans/{id}`), resume severidades y findings.
4. Mantiene estado local en `state.json` para detectar cambios de snapshot.
5. Envia reporte al backend (`OUTPUT_MODE=webhook|all`) o imprime (`stdout`).
6. Incluye `idempotency_key` por snapshot y cola local en disco para fallos transitorios.

## Variables de entorno

- `NESSUS_BASE_URL` (ejemplo: `https://192.168.18.113:8834`)
- `NESSUS_ACCESS_KEY`, `NESSUS_SECRET_KEY`
- `NESSUS_VERIFY_SSL` (`false` si usas certificado self-signed)
- `NESSUS_MAX_SCANS_PER_CYCLE` (default: `5`)
- `NESSUS_SCAN_IDS` (opcional, IDs separados por coma)
- `NESSUS_FOLDER_ID` (opcional)
- `OUTPUT_MODE` = `stdout | webhook | all`
- `TXDXAI_INGEST_URL`, `TXDXAI_COMPANY_ID`, `TXDXAI_API_KEY`
- `POLL_INTERVAL_SECONDS` (default: `60`)
- `FORCE_SEND_EVERY_CYCLES` (default: `10`)
- `INCLUDE_ALL_FINDINGS` (default: `true`)
- `QUEUE_ENABLED` (default: `true`)
- `QUEUE_DIR` (default: `queue`)
- `QUEUE_FLUSH_MAX` (default: `20`)
- `REQUEST_TIMEOUT`, `HTTP_RETRIES`, `BACKOFF_SECONDS`

## Ejecucion

1. Instala dependencias:

```bash
pip install -r requirements.txt
```

2. Crea tu `.env` desde `.env.example`.

3. Corre el agente en bucle:

```bash
python agent.py
```

4. Corre un solo ciclo:

```bash
python agent.py --once
```

Tambien puedes usar:

```bash
python main.py --once
```

## Archivos locales

- `state.json`: estado persistente del ultimo snapshot procesado.
- `raw_scans_snapshot.json`: snapshot crudo recibido de Nessus.
- `debug_report.json`: ultimo payload generado.
- `last_payload_sent.json`: ultimo payload cuando `OUTPUT_MODE=all`.
- `queue/*.json`: payloads encolados para reintento.
