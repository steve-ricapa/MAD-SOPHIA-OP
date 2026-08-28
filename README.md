# MAD-SOPHIA-OP

MAD de integraciones de seguridad y monitoreo para enviar snapshots al backend AWS/S3 de SOPHIA/XOC.

## Integraciones

- `nessus`
- `uptime_kuma`
- `zabbix`
- `openvas`
- `wazuh`
- `insightvm`

## Backend AWS

Todas las integraciones enviadas a AWS usan el mismo flujo:

1. El agente hace `POST` a `TXDXAI_INGEST_URL` para pedir una URL prefirmada.
2. El backend responde `upload_url`.
3. El agente sube el snapshot completo con `PUT` a S3.
4. AWS procesa el objeto desde S3.

`TXDXAI_INGEST_URL` debe apuntar a:

```env
TXDXAI_INGEST_URL=https://xvwg3cvl6b.execute-api.us-east-1.amazonaws.com/scans/upload-url
```

## Instalacion En Linux

Desde cero:

```bash
cd /root/DESARROLLO
git clone https://github.com/steve-ricapa/MAD-SOPHIA-OP.git
cd /root/DESARROLLO/MAD-SOPHIA-OP
python3 -m venv myenv
source myenv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Si el repo ya existe:

```bash
cd /root/DESARROLLO/MAD-SOPHIA-OP
git pull
source myenv/bin/activate
python -m pip install -r requirements.txt
```

## Configuracion Del `.env`

Usa un `.env` en la raiz del MAD. Esa es la unica fuente oficial de configuracion para produccion:

```bash
cd /root/DESARROLLO/MAD-SOPHIA-OP
cp .env.example .env
nano .env
```

Recomendacion operativa: no uses `source .env` para la ejecucion normal. Los agentes cargan `.env` con `python-dotenv`. Esto evita problemas cuando un password contiene caracteres como `$`, `#`, `%` o `!`.

Variables comunes:

```env
TXDXAI_INGEST_URL=https://xvwg3cvl6b.execute-api.us-east-1.amazonaws.com/scans/upload-url
TXDXAI_TENANT_ID=7
TXDXAI_COMPANY_ID=7
OUTPUT_MODE=all
MAD_VERSION=2.3.0
SOURCE=mad-collector
QUEUE_ENABLED=true
QUEUE_FLUSH_MAX=20
```

Para Mi Fibra usa `tenant_id=7` y `company_id=7`. `tenant_id=8` corresponde a `XOC APPLIANCE`, no a Mi Fibra.

Agent API keys por integracion:

```env
TXDXAI_API_KEY_NESSUS=replace_me
TXDXAI_API_KEY_UPTIMEKUMA=replace_me
TXDXAI_API_KEY_ZABBIX=replace_me
TXDXAI_API_KEY_WAZUH=replace_me
TXDXAI_API_KEY_INSIGHTVM=replace_me
TXDXAI_API_KEY_OPENVAS=replace_me
```

Recomendado separar colas para evitar payloads cruzados:

```env
NESSUS_QUEUE_DIR=runtime/nessus/queue
UPTIME_QUEUE_DIR=runtime/uptimekuma/queue
ZABBIX_QUEUE_DIR=runtime/zabbix/queue
INSIGHTVM_QUEUE_DIR=runtime/insightvm/queue
QUEUE_FLUSH_MAX=20
```

## Variables Por Integracion

Nessus:

```env
NESSUS_BASE_URL=https://your-nessus:8834
NESSUS_ACCESS_KEY=replace_me
NESSUS_SECRET_KEY=replace_me
NESSUS_VERIFY_SSL=false
NESSUS_MAX_SCANS_PER_CYCLE=5
```

Uptime Kuma:

```env
UPTIME_KUMA_URL=https://your-uptime-kuma
UPTIME_KUMA_METRICS_PATH=/metrics
UPTIME_KUMA_USERNAME=admin
UPTIME_KUMA_PASSWORD=replace_me
VERIFY_SSL=true
```

Zabbix:

```env
ZABBIX_API_URL=https://your-zabbix/zabbix/api_jsonrpc.php
ZABBIX_API_TOKEN=
ZABBIX_USER=Admin
ZABBIX_PASS=replace_me
VERIFY_SSL=true
```

OpenVAS/GVM:

```env
OPENVAS_OUTPUT_MODE=http
OPENVAS_COLLECTOR=gmp
GVM_TRANSPORT=plain
GVM_HOST=your-gvm-host
GVM_PORT=9390
GVM_USERNAME=admin
GVM_PASSWORD=replace_me
OPENVAS_DETAIL_LEVEL=findings
```

Wazuh:

```env
WAZUH_INDEXER_HOST=https://your-wazuh-indexer:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=replace_me
WAZUH_INDEXER_VERIFY_TLS=false
WAZUH_API_ENABLED=true
WAZUH_API_HOST=https://your-wazuh-server:55000
WAZUH_API_USER=replace_me
WAZUH_API_PASSWORD=replace_me
WAZUH_API_VERIFY_TLS=false
MIN_RULE_LEVEL=7
STARTUP_MENU_ENABLED=true
STARTUP_MENU_DEFAULT_OPTION=1
STARTUP_REQUIRE_ALL_TESTS=false
```

InsightVM:

```env
INSIGHTVM_BASE_URL=https://your-insightvm:3780/api/3
INSIGHTVM_USER=replace_me
INSIGHTVM_PASSWORD=replace_me
INSIGHTVM_TIMEOUT=30
INSIGHTVM_VERIFY_SSL=false
```

Nota InsightVM: `INSIGHTVM_BASE_URL` debe incluir `/api/3`. Si `/assets?page=0&size=50` da timeout, prueba reducirlo puntualmente con `--page-size 10` o `--insight-timeout 30`.

## Entrypoints

| Integracion | Comando |
|---|---|
| Nessus | `python3 nessus_integration/agent.py` |
| Uptime Kuma | `python3 uptimekuma_integration/agent.py` |
| Zabbix | `python3 zabix_integration/agent.py` |
| OpenVAS | `python3 openVAS_integration/main.py` |
| Wazuh | `python3 wazuh_integration/main.py` |
| InsightVM | `python3 insightVM_integration/main.py` |

Usa `--once` para un solo ciclo. Sin `--once`, el agente queda corriendo en modo servicio.

## Troubleshooting AWS Upload

Flujo esperado por integracion:

1. `POST /scans/upload-url`
2. backend responde `upload_url`
3. agente hace `PUT` del snapshot a S3 con `Content-Type: application/json`

Errores tipicos:

- `403` en `POST /scans/upload-url`: `tenant_id`, `api_key` o permiso incorrecto.
- `400` en `POST /scans/upload-url`: request invalido o falta `scanner_type` / `idempotency_key` esperado.
- `403` o `400` en `PUT` a S3: presigned URL expirada o payload subido con headers incorrectos.
- `409` en upload-url: snapshot ya aceptado antes; se trata como idempotencia exitosa.

Cada agente debe dejar en logs: `scan_id`, `idempotency_key`, `tenant_id`, `scanner_type`, `upload_url status`, `PUT status` y, si viene en la respuesta, `upload_id`, `s3_key`, `expires_in_seconds`.

## Correr Uno Por Uno

Activa el entorno y corre siempre desde la raiz:

```bash
cd /root/DESARROLLO/MAD-SOPHIA-OP
source myenv/bin/activate
```

Nessus:

```bash
python3 nessus_integration/agent.py --once 2>&1 | tee run_once_nessus.log
```

Uptime Kuma:

```bash
python3 uptimekuma_integration/agent.py --once 2>&1 | tee run_once_uptimekuma.log
```

Zabbix:

```bash
python3 zabix_integration/agent.py --once 2>&1 | tee run_once_zabbix.log
```

OpenVAS:

```bash
python3 openVAS_integration/main.py --once 2>&1 | tee run_once_openvas.log
```

Wazuh:

```bash
STARTUP_REQUIRE_ALL_TESTS=false python3 wazuh_integration/main.py --once 2>&1 | tee run_once_wazuh.log
```

InsightVM:

```bash
python3 insightVM_integration/main.py --once --log-level INFO 2>&1 | tee run_once_insightvm.log
```

> Nota: ya NO uses `--page-size 1`. Tras el fix del recolector (definiciones por ID), el default (`--page-size 200`) es el correcto y rápido.

## Correr En Modo Servicio

Quita `--once`.

Ejemplo Nessus:

```bash
cd /root/DESARROLLO/MAD-SOPHIA-OP
source myenv/bin/activate
python3 nessus_integration/agent.py
```

Ejemplo InsightVM:

```bash
cd /root/DESARROLLO/MAD-SOPHIA-OP
source myenv/bin/activate
python3 insightVM_integration/main.py --log-level INFO
```

## Correr Todos A La Vez

Sin orquestador global, corre cada agente como proceso separado:

```bash
cd /root/DESARROLLO/MAD-SOPHIA-OP
source myenv/bin/activate
mkdir -p runtime/logs

nohup python3 nessus_integration/agent.py > runtime/logs/nessus.log 2>&1 &
nohup python3 uptimekuma_integration/agent.py > runtime/logs/uptimekuma.log 2>&1 &
nohup python3 zabix_integration/agent.py > runtime/logs/zabbix.log 2>&1 &
nohup python3 openVAS_integration/main.py > runtime/logs/openvas.log 2>&1 &
nohup env STARTUP_REQUIRE_ALL_TESTS=false python3 wazuh_integration/main.py > runtime/logs/wazuh.log 2>&1 &
nohup python3 insightVM_integration/main.py --log-level INFO > runtime/logs/insightvm.log 2>&1 &
```

Ver procesos:

```bash
ps -ef | grep -E "nessus|uptimekuma|zabix|openVAS|wazuh|insightVM"
```

Ver logs:

```bash
tail -f runtime/logs/nessus.log
tail -f runtime/logs/uptimekuma.log
tail -f runtime/logs/zabbix.log
tail -f runtime/logs/openvas.log
tail -f runtime/logs/wazuh.log
tail -f runtime/logs/insightvm.log
```

Detener procesos manualmente:

```bash
pkill -f "nessus_integration/agent.py"
pkill -f "uptimekuma_integration/agent.py"
pkill -f "zabix_integration/agent.py"
pkill -f "openVAS_integration/main.py"
pkill -f "wazuh_integration/main.py"
pkill -f "insightVM_integration/main.py"
```

## Programacion Horaria (systemd) — Recomendada Para Produccion

Las 6 integraciones corren **una vez por hora** usando `--once` (un solo ciclo).
Como cada agente ya persiste su `state.json` y usa el **smart-cache** (`decide_snapshot_send` +
`FORCE_SEND_EVERY_CYCLES`), una invocacion horaria **no reenvia** snapshots sin cambios:
solo envía cuando la firma cambió, en el primer envío, o en el heartbeat forzado por
`FORCE_SEND_EVERY_CYCLES`. No hace falta modo servicio continuo.

### Instalacion (una sola vez, en el servidor)

Archivos de referencia versionados en `scripts/`:

- `scripts/run_hourly.sh` — orquestador (detecta el venv, `flock` por integración,
  escalona lanzamientos, devuelve exit != 0 si algo falla).
- `scripts/mad-6x.service` — unit `Type=oneshot` que ejecuta el script.
- `scripts/mad-6x.timer` — dispara cada hora en punto con `Persistent=true`.

Copia los units a systemd (ajusta la ruta del repo en el `.service` si difiere):

```bash
cd /root/DESARROLLO/MAD-SOPHIA-OP
cp scripts/mad-6x.service scripts/mad-6x.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now mad-6x.timer
```

### Comandos utiles

```bash
systemctl start mad-6x.timer        # disparar ya (una recoleccion)
systemctl list-timers mad-6x        # ver proxima ejecucion
systemctl status mad-6x.timer       # estado del timer
systemctl status mad-6x.service     # estado de la ultima recoleccion (failed si algo fallo)
journalctl -u mad-6x.service -f     # logs del service
```

### Logs de cada integracion

El script escribe en `runtime/logs/<nombre>.log` (con rotacion interna a ~5MB/5 archivos):
`nessus.log`, `uptimekuma.log`, `zabbix.log`, `openvas.log`, `wazuh.log`, `insightvm.log`,
y el resumen del último run en `runtime/logs/last_run.status`.

### Probar una sola integracion sin esperar la hora

```bash
cd /root/DESARROLLO/MAD-SOPHIA-OP
INV_ONLY=nessus bash scripts/run_hourly.sh   # solo nessus (debug)
bash scripts/run_hourly.sh                   # todas
```

### Forzar el envio de una integracion en una corrida horaria

```bash
NESSUS_SNAPSHOT_ALWAYS_SEND=true bash scripts/run_hourly.sh
```

> El orquestador usa el Python del venv del repo (`myenv/` o `venv/`) o `python3` global,
> y define `STARTUP_REQUIRE_ALL_TESTS=false` para Wazuh automaticamente.

## Logs Y Artifacts

Logs generados con `tee`:

```text
run_once_nessus.log
run_once_uptimekuma.log
run_once_zabbix.log
run_once_openvas.log
run_once_wazuh.log
run_once_insightvm.log
```

Logs de procesos `nohup`:

```text
runtime/logs/nessus.log
runtime/logs/uptimekuma.log
runtime/logs/zabbix.log
runtime/logs/openvas.log
runtime/logs/wazuh.log
runtime/logs/insightvm.log
```

Artifacts por integracion:

```text
runtime/nessus/
runtime/uptimekuma/
runtime/zabbix/
runtime/openvas/artifacts/
runtime/wazuh/artifacts/
runtime/insightvm/
```

Wazuh guarda logs JSON adicionales:

```text
runtime/wazuh/artifacts/logs/agent_console.json
runtime/wazuh/artifacts/logs/startup_precheck.json
runtime/wazuh/artifacts/raw_batches/
runtime/wazuh/artifacts/payloads/
runtime/wazuh/artifacts/failed_payloads/
```

Archivos comunes utiles:

```text
state.json
debug_report.json
last_payload_sent.json
last_delivery_meta.json
raw_scans_snapshot.json
raw_monitors_snapshot.json
last_report_built.json
queue/*.json
```

## Forzar Envio De Snapshot

Usalo solo para pruebas. Puede enviar snapshots sin cambios.

Nessus:

```bash
NESSUS_SNAPSHOT_ALWAYS_SEND=true python3 nessus_integration/agent.py --once
```

Uptime Kuma:

```bash
UPTIME_SNAPSHOT_ALWAYS_SEND=true python3 uptimekuma_integration/agent.py --once
```

Zabbix:

```bash
ZABBIX_SNAPSHOT_ALWAYS_SEND=true python3 zabix_integration/agent.py --once
```

OpenVAS:

```bash
OPENVAS_SNAPSHOT_ALWAYS_SEND=true python3 openVAS_integration/main.py --once
```

Wazuh:

```bash
WAZUH_SNAPSHOT_ALWAYS_SEND=true STARTUP_REQUIRE_ALL_TESTS=false python3 wazuh_integration/main.py --once
```

InsightVM:

```bash
INSIGHTVM_SNAPSHOT_ALWAYS_SEND=true python3 insightVM_integration/main.py --once --log-level INFO
```

## Validacion Esperada

Envio correcto suele verse asi:

```text
Data ingestion completed.
sent=True queued=False
```

OpenVAS muestra:

```text
OK backend upload_url (200) + s3 (200)
```

Nessus muestra:

```text
[SUCCESS] Data ingestion completed.
Report prepared | scans=... findings=... sent=True queued=False
```

InsightVM correcto:

```text
Fin de paginacion para /assets
Total de definiciones de vulnerabilidades obtenidas: ...
Report sent | findings=... sent=True queued=False
```

## Troubleshooting

`No backend URL configured. Skipping delivery.`:

```text
Falta TXDXAI_INGEST_URL o el agente no esta leyendo el .env correcto.
Ejecuta desde la raiz del repo y verifica .env.
```

`NESSUS_BASE_URL es requerido.`:

```text
Falta NESSUS_BASE_URL en .env o estas ejecutando con variables no cargadas.
```

InsightVM timeout en `/assets`:

```text
Si pagina por defecto responde lento, prueba reducirlo puntualmente con --page-size 10 --insight-timeout 30.
NO uses --page-size 1 en el orquestador horario (ver seccion de programacion).
```

Wazuh precheck falla pero el Indexer responde:

```text
Usa STARTUP_REQUIRE_ALL_TESTS=false para no abortar por prechecks no criticos.
```

Warnings `InsecureRequestWarning`:

```text
No son error. Indican VERIFY_SSL=false o TLS desactivado. En produccion usa certificados validos si aplica.
```

Cola cruzada o error de scanner type/API key:

```text
Separa QUEUE_DIR por integracion y limpia colas antiguas si tienen payloads de otra integracion.
```

## Tests

Desde la raiz:

```bash
python -m pytest "nessus_integration/tests" "zabix_integration/tests" "uptimekuma_integration/tests" "openVAS_integration/tests" "wazuh_integration/tests"
```

InsightVM tiene tests con rootdir propio:

```bash
cd /root/DESARROLLO/MAD-SOPHIA-OP/insightVM_integration
python -m pytest tests
```

## Docker

El `Dockerfile` actual referencia `app.py`, pero `app.py` no existe en este repo. Por ahora usa ejecucion directa en Linux con venv y entrypoints por integracion.

## Buenas Practicas

- No subir `.env` ni secretos al repo.
- Versionar solo el `.env.example` de la raiz (unico archivo de ejemplo de configuracion).
- Rotar credenciales si fueron expuestas en logs, chats o commits.
- Mantener `runtime/`, logs, colas y artifacts fuera de git.
