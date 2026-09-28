# Análisis del MAD-SOPHIA-OP — Módulo de Adquisición de Datos

## 1. Qué es el MAD

El MAD (Módulo de Adquisición de Datos) es un sistema de recolección automática de información de seguridad y monitoreo que ejecuta de forma periódica seis integraciones con herramientas externas, compara los datos capturados contra el ciclo anterior (smart-cache), y sube snapshots al backend AWS/S3 de SOPHIA/XOC únicamente cuando los datos han cambiado o se alcanza un umbral de envío periódico forzado.

**Objetivo:** Llevar datos de vulnerabilidades y disponibilidad desde fuentes locales (Nessus, Uptime Kuma, Zabbix, OpenVAS, Wazuh, InsightVM) hasta un backend central en AWS, manteniendo trazabilidad completa de cada envío y minimizando transferencias redundantes.

---

## 2. Arquitectura General

```
┌─────────────────────────────────────────────────────────────────────┐
│                       MAD-SOPHIA-OP                                 │
│                                                                     │
│  ┌───────────────┐   ┌───────────────┐   ┌───────────────┐         │
│  │  nessus_integration/  │   │ uptimekuma_integration/ │   │  zabix_integration/  │         │
│  │  agent.py      │   │  agent.py      │   │  agent.py      │         │
│  └───────┬───────┘   └───────┬───────┘   └───────┬───────┘         │
│          │                     │                     │                 │
│  ┌───────┴───────┐   ┌───────┴───────┐   ┌───────┴───────┐         │
│  │ openVAS_integration/ │   │ wazuh_integration/ │   │ insightVM_integration/ │         │
│  │  main.py       │   │  main.py       │   │  main.py       │         │
│  └───────┬───────┘   └───────┬───────┘   └───────┬───────┘         │
│          │                     │                     │                 │
│          └─────────────────────┼─────────────────────┘               │
│                                │                                     │
│                       ┌────────┴────────┐                            │
│                       │  mad_common/     │                            │
│                       │  snapshot.py     │  (smart-cache + idemp)    │
│                       └────────┬────────┘                            │
│                                │                                     │
└────────────────────────────────┼─────────────────────────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │  Backend AWS (SOPHIA/XOC) │
                    │  POST → presigned URL      │
                    │  PUT  → S3 (JSON payload)  │
                    └──────────────────────────┘
```

### Componentes clave

| Componente | Función |
|---|---|
| `mad_common/snapshot.py` | Lógica compartida: `decide_snapshot_send()` y `build_idempotency_key()` |
| `scripts/run_hourly.sh` | Orquestador horario de las 6 integraciones |
| `scripts/mad-6x.timer` | Timer systemd que dispara cada hora |
| `scripts/mad-6x.service` | Unit Type=oneshot que ejecuta el orquestador |
| `app.py` | Módulo de prechecks/diagnóstico (actualmente solo Uptime Kuma) |
| `.env` / `.env.example` | Configuración centralizada vía python-dotenv |

---

## 3. Flujo Común de Todas las Integraciones

Todas las integraciones siguen la misma secuencia general de 10 pasos:

```
┌──────────────────────────────────────────────────────────────┐
│  1. Cargar configuración (.env)                              │
│  2. Crear clientes/colección (API o protocolo específico)    │
│  3. Cargar estado previo (state.json)                        │
│  4. Recolectar datos crudos del sistema externo              │
│  5. Guardar snapshot crudo en disco                          │
│  6. Calcular firma del snapshot (build_snapshot_signature)   │
│  7. Decidir envío (decide_snapshot_send — smart-cache)       │
│  8. Si no enviar → actualizar estado, fin de ciclo           │
│  9. Si enviar → normalizar → generar report → subir          │
│ 10. Persistir estado actualizado (state.json)                │
└──────────────────────────────────────────────────────────────┘
```

---

## 4. Smart-Cache: decide_snapshot_send()

La función `decide_snapshot_send()` en `mad_common/snapshot.py:7-45` implementa la lógica central de control de envío. Recibe una firma (signature) del snapshot actual y decide si es necesario enviarlo al backend.

### Árbol de decisión

```
¿snapshot_always_send=True?
  └─ SÍ → enviar, reason = "always_snapshot"

¿Es el primer envío (has_sent_once=False)?
  └─ SÍ → enviar, reason = "first_snapshot"

¿unchanged_cycles >= force_send_every_cycles?
  └─ SÍ → enviar, reason = "force_send_cycle"

¿La firma actual es diferente a la anterior?
  └─ SÍ → enviar, reason = "snapshot_changed"
  └─ NO → NO enviar, reason = "no_change"
```

### Variables de control

| Variable | Efecto |
|---|---|
| `snapshot_always_send` | Si `true`, siempre envía (ignora cambios) |
| `force_send_every_cycles` | Cada N ciclos sin cambios, envía de todas formas (heartbeat) |
| `unchanged_cycles` | Contador de ciclos sin cambio, se resetea a 0 al enviar |
| `has_sent_once` | Flag que indica si hubo al menos un envío previo |

### Firma del snapshot

Cada integración construye su propia firma (hash compacto) a partir de los metadatos del snapshot:

- **Nessus:** `[{scan_id, last_modification_date, status}]` ordenado
- **Uptime Kuma:** `{monitor_id: status}` ordenado por ID
- **Zabbix:** Conteos + `problem_ids` + `trigger_ids` ordenados
- **OpenVAS:** `[{task_id, report_id, status, modification_time}]` ordenado
- **Wazuh:** Conteos severidad + `finding_ids` ordenados
- **InsightVM:** Conteos severidad + `finding_ids` + `asset_ids` ordenados

### Idempotency Key

```
sha256: SHA256("{company_id}:{scanner_type}:{event_type}:{snapshot_signature}")
```

Generada en `mad_common/snapshot.py:48-53`. Asegura que el mismo snapshot, empresa, escáner y evento produzcan siempre la misma clave. Si el backend recibe una clave duplicada, responde `409` (éxito idempotente, sin reprocesar).

---

## 5. Flujo de Envío al Backend AWS

Todas las integraciones usan el mismo protocolo de dos fases:

### Fase 1: Solicitar URL presignada (POST)

```
POST {TXDXAI_INGEST_URL}
Content-Type: application/json

{
  "tenant_id": <int>,
  "api_key": "<string>",
  "scanner_type": "<nessus|uptime_kuma|zabbix|openvas|wazuh|insightvm>",
  "idempotency_key": "sha256:<hex>"
}
```

Respuesta esperada (2xx):
```json
{"upload_url": "https://s3...presigned-url..."}
```

### Fase 2: Subir payload a S3 (PUT)

```
PUT {upload_url}
Content-Type: application/json

<payload JSON compacto, sin espacios>
```

### Manejo de errores

| Código HTTP | Significado | Acción |
|---|---|---|
| 2xx | Éxito | OK |
| 409 | Duplicado idempotente | OK silencioso (ya procesado) |
| 429, 500, 502, 503, 504 | Transitorio | Reintento con backoff exponencial + jitter (máx. 60s) |
| 400, 401, 403 | Permanente | Error fatal, no se reintenta |
| Timeout/red | Transitorio | Reintento; agotado → cola local si está habilitada |

### Cola de respaldo

Si la cola está habilitada (`QUEUE_ENABLED=true`), un fallo transitorio guarda el payload en disco (`queue/`) y se reintenta en el próximo ciclo (`flush_queue`). Los fallos permanentes se mueven a `dead-letter/`.

---

## 6. Orquestación

### Orquestador horario (`scripts/run_hourly.sh`)

- Detecta automáticamente un Python válido (venv del repo o `python3` global)
- Ejecuta cada integración con `--once` (un solo ciclo)
- Usa `flock` por integración para evitar solapamientos
- Escalona lanzamientos con 25 segundos de separación (`MAD_STAGGER_SECONDS`)
- Exporta `STARTUP_REQUIRE_ALL_TESTS=false` para Wazuh automáticamente
- Devuelve código de salida global != 0 si alguna integración falla

### Timer systemd (`scripts/mad-6x.timer`)

- Se dispara cada hora en punto (`OnCalendar=*-*-* *:00:00`)
- `Persistent=true` ejecuta lo pendiente si la máquina estaba apagada
- `AccuracySec=30s` permite hasta 30 segundos de desviación

### Unit systemd (`scripts/mad-6x.service`)

- `Type=oneshot` — ejecución puntual, no persiste
- `Restart=on-failure`, `RestartSec=60`
- `TimeoutStartSec=1800` — máximo 30 minutos por corrida
- Hardening: `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=full`

---

## 7. Las 6 Integraciones

---

### 7.1 Nessus (`nessus_integration/`)

**Tipo:** Scanner de vulnerabilidades (Tenable Nessus)
**Scanner type:** `nessus`
**Event type:** `vuln_scan_report`
**Estado:** Producción

#### Arquitectura interna

| Archivo | Función |
|---|---|
| `agent.py` | Entryppoint, bucle principal, orquestación del ciclo |
| `collector.py` | Conexión con API Nessus, obtención de scans |
| `summarizer.py` | Normalización de findings, construcción del report |
| `deliver.py` | Envío al backend (POST + PUT S3), cola local |
| `snapshot.py` | Construcción de firma, re-exporta `decide_snapshot_send` |
| `config.py` | Carga de configuración desde `.env` |

#### Conexión con Nessus

- **Protocolo:** HTTPS con autenticación por API keys
- **Headers:** `X-ApiKeys: accessKey=...; secretKey=...`
- **Sesión:** `requests.Session` persistente con reintentos (backoff + jitter)
- **Códigos reintentables:** 429, 500, 502, 503, 504

#### Endpoints utilizados

| Método | Ruta | Función |
|---|---|---|
| GET | `/scans` | Listar todos los scans disponibles |
| GET | `/scans/{scan_id}` | Detalle de un scan (hosts, vulnerabilidades, info) |
| POST | `/scans/{scan_id}/export` | Solicitar export Nessus (formato XML) |
| GET | `/scans/{scan_id}/export/{file_id}/status` | Verificar estado de export |
| GET | `/scans/{scan_id}/export/{file_id}/download` | Descargar export |

#### Recolección de datos

1. `list_scans()` → filtrado por `scan_ids_filter`/`folder_id_filter`/status (completed/imported)
2. Ordenamiento por `last_modification_date` descendente
3. Truncado a `max_scans_per_cycle` (default 5)
4. Por scan: `get_scan_details()` → hosts, vulnerabilidades, severidad summary
5. Enriquecimiento opcional (`NESSUS_ENABLE_EXPORT=true`): export XML → parseo → extracción detallada de vulnerabilidades (plugin_id, CVE, CVSS, solución, descripción, port, protocolo, hosts afectados)

#### Construcción de findings

`summarizer.py:44-141` — `build_findings()`:
- Detecta delta por scan (compara `last_modification_date` vs estado previo)
- Solo incluye scans modificados (a menos que `INCLUDE_ALL_FINDINGS=true`)
- Scan sin vulnerabilidades → finding `scan_summary` con `occurrence_count=0`
- Vulnerabilidad → finding tipo `vulnerability_summary` con:
  - `name`: plugin name
  - `severity`: label normalizado (critical/high/medium/low/info)
  - `cvss`: cvss3 primero, fallback cvss2, fallback default
  - `cve`: lista deduplicada o `"N/A"`
  - `oid`: `nessus-plugin-{plugin_id}`
  - `host`, `port`, `protocol`
  - `description`: texto concatenado descriptivo
  - `occurrence_count`: número de hosts afectados

#### Flujo específico

```
1. GET /scans → lista de scans
2. Filtrar por scope (ids/folder/status)
3. Top N scans por fecha
4. Por scan: GET /scans/{id} → detalle + vulnerabilidades
5. (Opcional) Export XML → parse → enriquecimiento completo
6. Firma del snapshot → decide_snapshot_send()
7. build_findings() → delta por scan modificado
8. build_report() → envelope con scan_summary + findings
9. POST upload-url → PUT S3
10. Persistir state.json
```

**Configuración clave:**
- `NESSUS_BASE_URL` (requerido): `https://tu-nessus:8834`
- `NESSUS_ACCESS_KEY` / `NESSUS_SECRET_KEY` (requeridos)
- `NESSUS_MAX_SCANS_PER_CYCLE` (default: 5)
- `NESSUS_FORCE_SEND_EVERY_CYCLES` (default: 10)
- `NESSUS_ENABLE_EXPORT` (default: true)

---

### 7.2 Uptime Kuma (`uptimekuma_integration/`)

**Tipo:** Monitor de disponibilidad y uptime
**Scanner type:** `uptime_kuma`
**Event type:** `availability`
**Estado:** Producción

#### Arquitectura interna

| Archivo | Función |
|---|---|
| `agent.py` | Entrypoint, bucle principal |
| `collector.py` | Fetch métricas Prometheus, enriquecimiento con DB SQLite |
| `summarizer.py` | Normalización de monitores, construcción del report |
| `deliver.py` | Envío al backend, cola local |
| `snapshot.py` | Firma del snapshot |
| `config.py` | Configuración |

#### Conexión con Uptime Kuma

- **Método principal:** Scraping de métricas Prometheus (`GET /metrics`)
- **Auth:** API Key (`UPTIME_KUMA_API_KEY_ID` + `UPTIME_KUMA_API_KEY`) o Basic Auth (`USERNAME` + `PASSWORD`)
- **Opcional:** Enriquecimiento con base de datos SQLite de Uptime Kuma (`UPTIME_KUMA_DB_PATH`)

#### Métricas recolectadas

| Métrica Prometheus | Campo destino |
|---|---|
| `monitor_status` | `status` (0=down, 1=up, 2=pending, 3=maintenance) |
| `monitor_response_time` | `response_time_ms` |
| `monitor_uptime_ratio` (1d/30d/365d) | `uptime_1d`, `uptime_30d`, `uptime_365d` |
| `monitor_cert_days_remaining` | `cert_days_remaining` |
| `monitor_cert_is_valid` | `cert_is_valid` |

Si hay DB configurada, se agregan: config del monitor, últimos heartbeats, tags, info TLS, stats 24h/30d.

#### Construcción de findings

`summarizer.py:116-245` — `build_findings()`:
- Detecta cambio de `status` vs monitor previo
- Incluye si: `include_all_monitors` O cambió O (`include_ongoing_non_up` y status ≠ 1)
- Descripción incluye: response time, uptime %, cert days remaining
- `monitor_meta` extendido: config, tags, heartbeats recientes, TLS info, stats

#### Flujo específico

```
1. GET {URL}/metrics → texto Prometheus
2. Parse → diccionario de monitores
3. (Opcional) Enriquecer con SQLite (config, heartbeats, tags, TLS, stats)
4. Firma del snapshot → decide_snapshot_send()
5. build_findings() → monitores con cambio de status
6. build_report() → scan_summary con availability, performance, certificates
7. POST upload-url → PUT S3
8. Persistir state.json
```

**Configuración clave:**
- `UPTIME_KUMA_URL` (requerido): `https://tu-uptime-kuma`
- `UPTIME_KUMA_METRICS_PATH` (default: `/metrics`)
- `UPTIME_FORCE_SEND_EVERY_CYCLES` (default: 6)
- `UPTIME_INCLUDE_ALL_MONITORS` (default: false)
- `UPTIME_KUMA_DB_PATH` (opcional): ruta a `kuma.db`

---

### 7.3 Zabbix (`zabix_integration/`)

**Tipo:** Sistema de monitoreo de infraestructura
**Scanner type:** `zabbix`
**Event type:** `noc_health` (en report)
**Estado:** Producción

#### Arquitectura interna

| Archivo | Función |
|---|---|
| `agent.py` | Entrypoint, bucle principal, orquestación |
| `zbx_api.py` | Cliente JSON-RPC para API Zabbix |
| `summarizer.py` | Normalización de problemas/triggers, construcción del report |
| `deliver.py` | Envío al backend, cola local |
| `snapshot.py` | Firma del snapshot |
| `config.py` | Configuración |

#### Conexión con Zabbix

- **Protocolo:** JSON-RPC 2.0 sobre HTTPS
- **Auth:** Token Bearer (`ZABBIX_API_TOKEN`) o login por user/pass
- **Reintentos:** Status HTTP no-2xx, errores JSON-RPC, errores de auth → re-login automático

#### Métodos JSON-RPC utilizados

| Método | Función |
|---|---|
| `apiinfo.version` | Verificar conectividad |
| `problem.get` | Obtener problemas activos (con tags, acknowledges, hosts enriquecidos) |
| `trigger.get` | Obtener triggers (hosts, interfaces, tags) |
| `host.get` | Obtener hosts activos |
| `event.get` | Obtener eventos (opcional, `INCLUDE_EVENTS=true`) |
| `user.login` | Login si no hay token |

#### Construcción de findings

`summarizer.py:42-252` — `summarize()`:
- Cuenta problemas activos por severidad
- Por trigger activo: finding tipo `problem` o `recovery` con:
  - `description` con `{HOST.NAME}` reemplazado
  - Severity mapeado (5→critical, 4→high, 3→medium, 2→low, 1/0→info)
  - Tags: CVE, CVSS, solution, impact si están disponibles
  - IP/port de la interfaz principal del host
- Triggers sin problema activo agrupados como `health_summary` por host

#### Flujo específico

```
1. api_version() → verificar conectividad
2. problem.get (con hosts enriquecidos) → problemas activos
3. (Opcional) event.get → eventos recientes
4. host.get → hosts activos
5. trigger.get → todos los triggers (con interfaces, tags)
6. Dump raw snapshot atómico
7. Firma del snapshot → decide_snapshot_send()
8. summarize() → findings por trigger/problem, health_score por host
9. POST upload-url → PUT S3
10. Persistir state.json
```

**Configuración clave:**
- `ZABBIX_API_URL` (requerido): `https://tu-zabbix/zabbix/api_jsonrpc.php`
- `ZABBIX_API_TOKEN` o `ZABBIX_USER` + `ZABBIX_PASS`
- `ZABBIX_HOURS` (default: 24) — ventana de análisis
- `ZABBIX_PROBLEMS_LIMIT` (default: 2000)
- `ZABBIX_TRIGGERS_LIMIT` (default: 5000)

---

### 7.4 OpenVAS/GVM (`openVAS_integration/`)

**Tipo:** Scanner de vulnerabilidades open source (Greenbone/OpenVAS)
**Scanner type:** `openvas`
**Event type:** `vuln_scan_report`
**Estado:** Producción

#### Arquitectura interna

| Archivo | Función |
|---|---|
| `main.py` | Entryppoint (monolítico grande, ~730 líneas) |
| `gvm_client.py` | Conexión con GVM (TLS, Unix socket, o TCP plain) |
| `services.py` | Normalización, extracción de findings, envío al backend |
| `snapshot.py` | Firma del snapshot |
| `config.py` | Configuración |

#### Conexión con GVM

Tres transportes soportados:

| Transporte | Configuración | Uso típico |
|---|---|---|
| **TLS** | `GVM_HOST`, `GVM_PORT` (default: 9390) | Producción con certificados |
| **Unix** | `GVM_SOCKET` | GVM local |
| **Plain TCP** | `GVM_ALLOW_PLAIN_TCP=true` | Debug, requiere flag explícito |

- **Auth:** `gvm.connections` + `gvm.protocols.gmp.GMP` → `authenticate(user, password)`
- **Plain TCP:** autenticación manual via XML GMP

#### Comandos GVM

| Comando | Función |
|---|---|
| `<get_tasks/>` | Listar tareas de escaneo |
| `<get_report report_id="X" ...>` | Obtener reporte con findings detallados |

#### Procesamiento por tarea

1. Extraer `task_id`, `report_id`, `status`, `modification_time`
2. Filtrar tareas no terminales (pending/running → skip)
3. Extraer severidades desde `result_count` del task
4. Si `DETAIL_LEVEL=findings` → `get_report()` con filtro por severidad
5. Parse XML → extraer findings (name, host, port, CVSS, CVE, solution)
6. `build_dashboard_blocks()` → risk score, top hosts/ports/CVEs

#### Flujo específico

```
1. GVMClient.__enter__ → conexión (TLS/Unix/plain)
2. get_tasks() → lista de tareas
3. Firma del snapshot → decide_snapshot_send()
4. Por cada tarea completada:
   a. get_report() → XML con findings
   b. extract_findings() → lista normalizada
   c. idempotency_key = sha256(company:openvas:event:report_id:findings_hash)
   d. emit_payload() → POST upload-url → PUT S3
   e. sent_map[report_id] = timestamp (cache en memoria)
5. Persistir state.json (solo sent_map, firma, unchanged_cycles)
```

**Diferencia importante:** OpenVAS no usa cola en disco. Un reporte fallido se reintenta automáticamente en el próximo ciclo (no está en `sent_map`).

**Configuración clave:**
- `GVM_HOST` / `GVM_PORT` / `GVM_USERNAME` / `GVM_PASSWORD` (requeridos para GMP)
- `GVM_TRANSPORT` (default: unix si socket, tls si no)
- `OPENVAS_COLLECTOR` (default: `simulated` → cambiar a `gmp`)
- `OPENVAS_DETAIL_LEVEL` (default: `findings`)
- `OPENVAS_TOP_N` (default: 50)

---

### 7.5 Wazuh (`wazuh_integration/`)

**Tipo:** Sistema de detección y respuesta de endpoints (IDS/EDR)
**Scanner type:** `wazuh`
**Event type:** `vuln_scan_report`
**Estado:** Producción

#### Arquitectura interna

| Archivo | Función |
|---|---|
| `main.py` | Entryppoint, prechecks, daemon asyncio, menú interactivo |
| `src/indexer.py` | Consultas al Wazuh Indexer (OpenSearch) |
| `src/api.py` | API REST de Wazuh (agentes, status) |
| `src/aggregator.py` | Normalización de alertas → findings |
| `src/sender.py` | Envío al backend (POST + PUT S3) |
| `src/state.py` | Estado SQLite (checkpoints, alertas procesadas) |
| `snapshot.py` | Firma del snapshot |

**Nota:** Wazuh es la única integración que corre como daemon asyncio en modo servicio, con health check HTTP en puerto configurable.

#### Conexión con Wazuh Indexer

- **Protocolo:** OpenSearch API (HTTPS)
- **Librería:** `opensearch-py` (AsyncOpenSearch)
- **Auth:** `http_auth=(user, password)`, `use_ssl=True`
- **Índice:** `wazuh-alerts-*`
- **Query:** rango de timestamp (`now-2h` a `now`), orden `timestamp asc`

#### Conexión con Wazuh REST API

- **Protocolo:** HTTPS, API v4
- **Auth:** `BasicAuth(user, password)` → token JWT
- **Endpoints:** `/agents/summary/status`, `/agents`

#### Normalización de alertas

`src/aggregator.py:9-70` — `normalize_alert()`:

| Campo alerta | Campo finding |
|---|---|
| `rule.level` | `severity` (≥15→critical, 12-14→high, 7-11→medium, 0-6→low) |
| `rule.id` | `rule_id` |
| `rule.description` | `description` |
| `agent.id` | `host_id` |
| `agent.name` | `host` |
| `data.srcip`, `data.dstip` | `source_ip`, `dest_ip` |
| MITRE (ids, techniques, tactics) | `mitre` enrichment |
| pci_dss, hipaa, etc. | `compliance` |

#### Filtrado

Solo se procesan alertas con `rule.level >= MIN_RULE_LEVEL` (default: 7).

#### Flujo específico (daemon asyncio)

```
1. Parse args, load_dotenv, cargar config
2. Crear clientes: IndexerClient, WazuhApiClient, Sender
3. Precheck: env requerido, API auth, Indexer ping, backend probe
4. Iniciar servidor /health (asyncio)
5. Loop principal (asyncio.gather):
   a. poll_alerts (cada 30s):
      - Query OpenSearch: alertas de las últimas 2 horas
      - Filtrar por MIN_RULE_LEVEL
      - normalize_alert() → findings
      - build_snapshot_signature()
      - decide_snapshot_send()
      - create_report() → envelope con findings + agent_summary
      - sender.send_report() → POST + PUT S3
   b. poll_agents (cada 60s, si API habilitada):
      - GET /agents/summary/status → resumen de agentes
      - GET /agents → lista de agentes activos
   c. retry_failed_payloads (cada 30s):
      - Leer failed_*.json → reintento send_report()
      - OK → mover a payloads/; fallo → conservar
```

**Diferencia importante:** Wazuh usa ventana deslizante de 2 horas (`now-2h` a `now`). La dedup se hace por firma de contenido + idempotency key, no por cursor incremental. La tabla `processed_alerts` en SQLite existe pero no se usa en el flujo principal.

**Configuración clave:**
- `WAZUH_INDEXER_HOST` / `USER` / `PASSWORD` (requeridos)
- `WAZUH_API_HOST` / `USER` / `PASSWORD` (si API habilitada)
- `MIN_RULE_LEVEL` (default: 7)
- `INITIAL_LOOKBACK_HOURS` (default: 2)
- `ALERT_BATCH_SIZE` (default: 500)
- `STARTUP_MENU_ENABLED` (default: true)
- `STARTUP_REQUIRE_ALL_TESTS` (default: true)

---

### 7.6 InsightVM (`insightVM_integration/`)

**Tipo:** Scanner de vulnerabilidades (Rapid7 Nexpose)
**Scanner type:** `insightvm`
**Event type:** `vuln_scan_report`
**Estado:** Producción

#### Arquitectura interna

| Archivo | Función |
|---|---|
| `main.py` | Entryppoint, orquestación del ciclo |
| `agents/insightvm_agent.py` | Paginación y recolección de assets/vulns |
| `agents/unified_agent.py` | Wrapper del agente |
| `clients/insightvm_client.py` | Cliente HTTP para API InsightVM |
| `clients/backend_client.py` | Envío al backend (POST + PUT S3) |
| `models/normalize.py` | Normalización de assets y findings |
| `models/schemas.py` | Modelos de datos (Asset, Finding, SourceResult) |
| `reports/assets_export.py` | Export de tabla assets (CSV/JSON) |
| `utils/state_manager.py` | Gestión de estado (JSON + flock) |
| `snapshot.py` | Firma del snapshot |
| `config/insightvm_config.py` | Configuración (InsightVM + backend) |

#### Conexión con InsightVM

- **Protocolo:** REST API v3 (`/api/3`)
- **Auth:** Basic Auth (`INSIGHTVM_USER` + `INSIGHTVM_PASSWORD`)
- **Paginación:** HATEOAS (`page`, `size`), items bajo clave `resources`
- **Reintentos:** urllib3 Retry (total=5, backoff=0.6, status_forcelist 429/5xx)
- **Timeout:** configurable (default 30s)

#### Endpoints utilizados

| Método | Ruta | Función |
|---|---|---|
| GET | `/assets` | Listar assets paginados (default page_size=200) |
| GET | `/assets/{id}/vulnerabilities` | IDs de vulns por asset |
| GET | `/vulnerabilities/{id}` | Definición de una vuln específica |
| GET | `/vulnerabilities` | Catálogo paginado (respaldo si >size IDs) |

#### Construcción de findings

`models/normalize.py:235-274`:
- Por cada asset: recorre `vulnerabilities_ids`
- Resuelve definición desde `/vulnerabilities/{id}`
- Severity normalizado: strings (informational/moderate/severe → info/medium/high) + numérico
- IDs sha1: `sha1("asset", key)` para assets, `sha1("finding", aid, v_id)` para findings

#### Flujo específico

```
1. InsightVMAgent.run():
   a. Paginar /assets (page_size configurable, default 200)
   b. Por asset: GET /assets/{id}/vulnerabilities
   c. Por vuln ID: GET /vulnerabilities/{id} → definición
2. Guardar raw JSON
3. normalize_unified() → assets + findings normalizados
4. build_snapshot_signature()
5. decide_snapshot_send()
6. build_insightvm_report() → payload final
7. BackendClient.send_data():
   a. flush_queue() (cola pendiente)
   b. POST upload-url → PUT S3
8. Persistir state.json
```

**Configuración clave:**
- `INSIGHTVM_BASE_URL` (requerido): `https://tu-insightvm:3780/api/3`
- `INSIGHTVM_USER` / `INSIGHTVM_PASSWORD` (requeridos)
- `INSIGHTVM_TIMEOUT` (default: 30)
- `--page-size` (default: 200, máx: 500)
- `INSIGHTVM_FORCE_SEND_EVERY_CYCLES` (default: 10)

---

## 8. Tabla Comparativa de las 6 Integraciones

| Aspecto | Nessus | Uptime Kuma | Zabbix | OpenVAS | Wazuh | InsightVM |
|---|---|---|---|---|---|---|
| **Tipo** | Scanner vuln | Monitor uptime | Monitoreo infra | Scanner vuln | IDS/EDR | Scanner vuln |
| **Protocolo** | HTTPS REST | Prometheus metrics | JSON-RPC 2.0 | GMP (TLS/Unix/plain) | OpenSearch + REST | HTTPS REST |
| **Auth** | API Keys | API Key / Basic | Token / Basic | User/Pass GVM | JWT (API) / Basic (Indexer) | Basic |
| **Estado** | JSON file | JSON file | JSON file | JSON file (sent_map) | SQLite + JSON checkpoints | JSON file |
| **Firma snapshot** | Mod dates de scans | Status de monitores | Problems + triggers | Task status + mod time | Finding IDs + severidades | Finding IDs + severidades |
| **Force send default** | 10 ciclos | 6 ciclos | 10 ciclos | 6 ciclos | 10 ciclos | 10 ciclos |
| **Cola disco** | Sí | Sí | Sí | No (reintento natural) | Sí (failed_*.json) | Sí |
| **Entrypoint** | `agent.py` | `agent.py` | `agent.py` | `main.py` | `main.py` (asyncio) | `main.py` |
| **Modo servicio** | Loop + sleep | Loop + sleep | Loop + sleep | Loop + sleep | Daemon asyncio | Loop + sleep |
| **Health check HTTP** | No | No | No | No | Sí (puerto 8000) | No |

---

## 9. Gestión de Estado

### state.json (Nessus, Uptime Kuma, Zabbix, InsightVM)

```json
{
  "snapshot_signature": "<última firma>",
  "unchanged_cycles": 0,
  "has_sent_once": false,
  "last_idempotency_key": "sha256:...",
  "last_send_result": "sent|queued|skipped_no_change",
  "processed_scans": {"123": 1725000000},
  "monitor_status": {"1": 1, "2": 0}
}
```

Escritura atómica: `.tmp` + `os.replace()`.

### state.json (OpenVAS)

```json
{
  "sent": {"report-id-1": 1725000000, "report-id-2": 1725000100},
  "snapshot_signature": "...",
  "unchanged_cycles": 0
}
```

Incluye TTL purge: reportes > 30 días se eliminan automáticamente. Máximo 5000 entradas.

### SQLite (Wazuh: `state/agent_state.db`)

Tablas:
- `checkpoints(key PK, value, updated_at)` — signature, cycles, has_sent_once, agent_summary, agents_map
- `processed_alerts(alert_id PK, seen_at)` — existe pero no se usa en flujo principal

### State Manager (InsightVM: `utils/state_manager.py`)

JSON con `fcntl.flock` (Linux). Windows: best-effort sin bloqueo real.

---

## 10. Configuración General

### Variables comunes a todas las integraciones

| Variable | Función | Default |
|---|---|---|
| `TXDXAI_INGEST_URL` | URL del backend para upload-url | Requerido |
| `TXDXAI_COMPANY_ID` | ID de empresa | Requerido (>0) |
| `TXDXAI_TENANT_ID` | ID de tenant | = company_id |
| `TXDXAI_API_KEY_<SCANNER>` | API key específica por integración | Requerido |
| `OUTPUT_MODE` | Modo de salida: `stdout`, `webhook`, `all` | `all` |
| `QUEUE_ENABLED` | Habilitar cola de respaldo | `true` |
| `QUEUE_FLUSH_MAX` | Máximo items por flush de cola | `20` |
| `QUEUE_DIR` | Directorio de cola por integración | `runtime/<scanner>/queue` |
| `MAD_VERSION` | Versión del MAD | `2.3.0` |
| `SOURCE` | Identificador del origen | `mad-collector` |

### Variables por integración

Ver sección específica de cada integración arriba.

---

## 11. Artefactos Generados

### Por integración

```
runtime/<scanner>/
  ├── state.json                    # Estado persistente
  ├── debug_report.json             # Reporte generado (debug)
  ├── last_payload_sent.json        # Último payload enviado
  ├── last_delivery_meta.json       # Metadatos del último envío
  ├── raw_scans_snapshot.json       # Snapshot crudo (Nessus/UptimeKuma/Zabbix)
  ├── raw_snapshot.json             # Snapshot crudo (Zabbix)
  ├── queue/                        # Cola de respaldo
  │   └── <timestamp>_<uuid>.json
  └── dead-letter/                  # Fallos permanentes
```

### Wazuh (adicional)

```
runtime/wazuh/artifacts/
  ├── raw_batches/                  # Batches crudos de alertas
  ├── payloads/                     # Payloads exitosos (reintentos)
  ├── failed_payloads/              # Payloads fallidos para reintento
  └── logs/
      ├── agent_console.json        # Log de consola
      ├── startup_precheck.json     # Resultado del precheck
      └── cycle_errors.jsonl        # Errores de ciclo
```

### Logs horarios

```
runtime/logs/
  ├── nessus.log
  ├── uptimekuma.log
  ├── zabbix.log
  ├── openvas.log
  ├── wazuh.log
  ├── insightvm.log
  └── last_run.status              # Estado de la última corrida horaria
```

---

## 12. Tests

```bash
# Todas menos InsightVM (desde la raíz)
python -m pytest "nessus_integration/tests" "zabix_integration/tests" \
  "uptimekuma_integration/tests" "openVAS_integration/tests" "wazuh_integration/tests"

# InsightVM (rootdir propio)
cd insightVM_integration && python -m pytest tests
```

---

## 13. Hallazgos y Notas Importantes

1. **Código muerto en OpenVAS:** `gvm_client.py:266-277` contiene un fallback inalcanzable tras un `raise` anterior. No afecta funcionalidad pero debería limpiarse.

2. **Tabla huérfana en Wazuh:** `processed_alerts` en SQLite existe pero `main.py` nunca la usa para dedup. La dedup real se hace por firma de contenido + idempotency key.

3. **Firma de Wazuh limitada:** Solo cuenta severidad + IDs de findings. Un cambio que mantiene la misma distribución de severidades puede no detectarse como "cambio" hasta el `force_send_cycle`.

4. **OpenVAS sin cola en disco:** A diferencia de las demás integraciones, OpenVAS no persiste payloads fallidos en cola. El reintento es natural: si un reporte falla, no se agrega a `sent_map` y se reintenta en el próximo ciclo.

5. **Discrepancia de estado en Uptime Kuma:** El `state.json` del repositorio tiene formato antiguo (`uptimekuma-snapshot-*`). El código actual genera `sha256:*`. El merge defensivo lo acepta, pero las claves nuevas estarán vacías si nunca hubo envío nuevo con el código actual.

6. **Hardening del servicio systemd:** El unit usa `NoNewPrivileges`, `PrivateTmp`, y `ProtectSystem=full` con acceso de escritura solo a `runtime/`.

7. **Docker no funcional:** El `Dockerfile` referencia `app.py` pero el MAD real corre con entrypoints por integración. La ejecución directa en Linux con venv es el método actual.
