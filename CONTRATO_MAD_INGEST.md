# MAD -> Backend Ingest Contract (v1.2)

Documento oficial para el equipo MAD que envia snapshots normalizados al backend.

Esta version mantiene compatibilidad con v1.0/v1.1 y formaliza dos perfiles genericos de ingesta:

- SOC: seguridad, vulnerabilidades, eventos, alertas y hallazgos de riesgo.
- NOC: disponibilidad, salud operativa, rendimiento, caidas, degradaciones, problemas activos y eventos operativos.

Internamente, el backend debe persistir en:

- SOC:
  - `scan_summaries_soc`
  - `scan_findings`

- NOC:
  - `scan_summaries_noc`
  - `scan_noc_events`

El endpoint externo se mantiene unico para no acoplar al MAD con la arquitectura interna del backend.

---

## 1) Endpoint

- `POST /api/scans/ingest`
- `Content-Type: application/json`

Nota: aunque el endpoint conserva el nombre `/scans/ingest` por compatibilidad, debe entenderse como endpoint universal de ingesta MAD.

El MAD no debe elegir directamente la tabla destino.  
El backend debe resolver el destino interno usando:

- `api_key`
- `scan_summary.scanner_type`
- `scan_summary.summary_type`

---

## 2) Contrato obligatorio

Campos obligatorios:

- `company_id` (o `companyId`) integer > 0
- `api_key` (o `apiKey`) string
- `scan_id` (o `scanId`) string
- `scan_summary.scanner_type` string canonico
- `scan_summary.scanned_at` ISO8601 UTC (`...Z`)
- `idempotency_key` string estable por snapshot con formato `sha256:<hex>`

Campos recomendados desde v1.2:

- `scan_summary.summary_type` string canonico

Por item en `findings[]`:

- `name` obligatorio
- `severity` obligatorio

Nota:

- Para SOC, `findings[]` representa vulnerabilidades, eventos, alertas o hallazgos de seguridad.
- Para NOC, `findings[]` representa eventos operativos, problemas activos, incidentes, degradaciones, caidas o recuperaciones.
- El nombre externo se mantiene como `findings[]` por compatibilidad.
- Internamente, el backend puede persistirlo como:
  - SOC -> `scan_findings`
  - NOC -> `scan_noc_events`

---

## 3) Idempotency key

Especificacion de `idempotency_key`:

- Formato exacto: `sha256:<hex>`
- `<hex>`: 64 caracteres hexadecimales en lowercase (`[0-9a-f]`)
- Longitud maxima total: 71 caracteres
- Ejemplo valido: `sha256:7f83b1657ff1fc53b92dc18148a1d65dfa135014...`

La `idempotency_key` debe ser estable por snapshot y debe calcularse sobre el contenido normalizado.

---

## 4) Valores canonicos de `scanner_type`

Solo se aceptan estos valores:

- `openvas`
- `insightvm`
- `nessus`
- `qualys`
- `tenable`
- `rapid7`
- `zabbix`
- `uptime_kuma`
- `wazuh`
- `nmap`
- `other`

Regla: MAD siempre envia el valor canonico en lowercase.

---

## 5) Valores canonicos de `summary_type`

`summary_type` indica la naturaleza funcional del snapshot recibido.

Valores aceptados:

- `vulnerability`
- `security_events`
- `noc_health`
- `availability`
- `network_discovery`
- `other`

Mapeo recomendado por `scanner_type`:

| scanner_type | summary_type recomendado | Dominio interno |
|---|---|---|
| `openvas` | `vulnerability` | SOC |
| `nessus` | `vulnerability` | SOC |
| `insightvm` | `vulnerability` | SOC |
| `qualys` | `vulnerability` | SOC |
| `tenable` | `vulnerability` | SOC |
| `rapid7` | `vulnerability` | SOC |
| `wazuh` | `security_events` | SOC |
| `zabbix` | `noc_health` | NOC |
| `uptime_kuma` | `availability` | NOC |
| `nmap` | `network_discovery` | NOC/SOC segun uso |
| `other` | `other` | Indefinido |

Reglas:

- En v1.2, `summary_type` es recomendado, no obligatorio.
- Si MAD no envia `summary_type`, el backend debe derivarlo desde `scanner_type`.
- Si MAD envia `summary_type`, el backend debe validarlo contra `scanner_type`.
- Si existe inconsistencia entre `scanner_type` y `summary_type`, el backend debe rechazar el payload con error de validacion.
- `summary_type` no reemplaza a `scanner_type`; lo complementa.

---

## 6) Politica de unicidad de `scan_id` 24/7

`scan_id` debe ser unico por corrida logica del snapshot dentro de la empresa.

Recomendacion practica:

- Incluir `integration + scope + window_start + window_end + sequence/hash`.

Ejemplos:

- `soc-dmz-2026-05-17T10:00Z-2026-05-17T10:05Z-0001`
- `noc-core-2026-05-17T10:00Z-2026-05-17T10:05Z-0001`
- `zabbix-core-2026-05-17T10:00Z-2026-05-17T10:05Z-0001`
- `uptime-kuma-public-apps-2026-05-17T10:00Z-2026-05-17T10:05Z-0001`

Objetivo:

- Evitar colisiones de upsert en ejecuciones 24/7.
- Permitir trazabilidad exacta por ventana de captura.

---

## 7) Normalizacion universal en MAD antes de enviar

MAD debe normalizar:

- `scanner_type`
  - Ejemplo: `uptimekuma` -> `uptime_kuma`

- `summary_type` cuando sea enviado

- `severity` a:
  - `critical`
  - `high`
  - `medium`
  - `low`
  - `info`

- `scanned_at` en UTC con sufijo `Z`

- Timestamps de items:
  - `started_at`
  - `ended_at`
  - cualquier fecha enviada debe estar en ISO8601 UTC si aplica

- Strings:
  - aplicar `trim`
  - remover caracteres de control
  - evitar payload corrupto

- Faltantes:
  - convertir a `null` solo donde el contrato lo permite
  - usar `0` cuando sea contador agregado y el valor real sea cero

---

## 8) Estructura universal del payload

El payload externo mantiene esta forma:

```json
{
  "company_id": 12,
  "api_key": "<AGENT_KEY>",
  "scan_id": "integration-scope-window-001",
  "idempotency_key": "sha256:2d2d...",
  "scan_summary": {},
  "findings": []
}
```

El backend interpreta `scan_summary` segun `summary_type`.

---

# PERFIL SOC

## 9) Payload generico SOC

Este perfil aplica para herramientas de seguridad, vulnerabilidades, eventos, alertas o riesgo.

Ejemplos de integraciones SOC:

- `openvas`
- `nessus`
- `insightvm`
- `qualys`
- `tenable`
- `rapid7`
- `wazuh`

Payload generico:

```json
{
  "company_id": 12,
  "api_key": "<AGENT_KEY>",
  "scan_id": "soc-dmz-2026-05-16T12:00Z-2026-05-16T12:30Z-001",
  "idempotency_key": "sha256:2d2d...",
  "scan_summary": {
    "scanner_type": "nessus",
    "summary_type": "vulnerability",
    "status": "completed",
    "scanned_at": "2026-05-16T12:30:00Z",
    "scan_name": "SOC Security Snapshot",
    "target": "dmz-segment",

    "total_hosts": 42,
    "total_findings": 64,

    "cvss_max": 9.8,
    "risk_score": 87.5,
    "risk_label": "critical",

    "results": {
      "critical": 3,
      "high": 17,
      "medium": 29,
      "low": 11,
      "info": 4
    },

    "meta": {
      "schema_version": "1.2",
      "snapshot_signature": "sha256:ab12...",
      "send_reason": "changed",
      "snapshot_mode": "delta_with_periodic_forced",
      "mad_version": "2.3.0",
      "integration_version": "generic-soc-1.0.0",
      "source": "mad-collector",
      "raw_source": "soc-integration",
      "collection_window_start": "2026-05-16T12:00:00Z",
      "collection_window_end": "2026-05-16T12:30:00Z"
    }
  },
  "findings": [
    {
      "name": "Security finding title",
      "severity": "high",

      "host": "10.20.1.5",
      "port": "443",
      "protocol": "tcp",

      "cvss": 8.1,
      "cve": "CVE-2026-0001",
      "oid": null,

      "description": "...",
      "solution": "...",
      "impact": "...",

      "raw": {}
    }
  ]
}
```

---

## 10) Estructura de `scan_summary` SOC

Campos principales:

| Campo | Tipo | Descripcion |
|---|---|---|
| `scanner_type` | string | Integracion origen |
| `summary_type` | string | `vulnerability`, `security_events`, `network_discovery` u `other` |
| `status` | string | Estado del snapshot |
| `scanned_at` | string ISO8601 UTC | Fecha/hora UTC del snapshot |
| `scan_name` | string | Nombre legible del snapshot |
| `target` | string | Scope, segmento, grupo o ambiente evaluado |
| `total_hosts` | integer | Total de activos/hosts evaluados |
| `total_findings` | integer | Total de hallazgos SOC |
| `cvss_max` | number/null | CVSS maximo detectado, si aplica |
| `risk_score` | number/null | Score agregado de riesgo |
| `risk_label` | string/null | Etiqueta agregada de riesgo |
| `results` | object | Conteo por severidad |
| `meta` | object | Metadata tecnica y operativa |

---

## 11) Estructura de `findings[]` SOC

Campos obligatorios:

- `name`
- `severity`

Campos recomendados:

| Campo | Tipo | Descripcion |
|---|---|---|
| `name` | string | Nombre del hallazgo |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `host` | string/null | Host, asset o IP afectada |
| `port` | string/null | Puerto relacionado |
| `protocol` | string/null | Protocolo relacionado |
| `cvss` | number/null | CVSS del hallazgo, si aplica |
| `cve` | string/null | CVE asociado, si aplica |
| `oid` | string/null | Identificador propio del scanner, si aplica |
| `description` | string/null | Descripcion |
| `solution` | string/null | Recomendacion/remediacion |
| `impact` | string/null | Impacto |
| `raw` | object/null | Payload original o campos especificos no normalizados |

---

# PERFIL NOC

## 12) Payload generico NOC

Este perfil aplica para herramientas de monitoreo operativo, disponibilidad, salud, rendimiento, red, infraestructura o aplicaciones.

Ejemplos de integraciones NOC:

- `zabbix`
- `uptime_kuma`
- futuras integraciones de monitoreo operativo

Payload generico:

```json
{
  "company_id": 12,
  "api_key": "<AGENT_KEY>",
  "scan_id": "noc-core-2026-05-16T12:00Z-2026-05-16T12:05Z-001",
  "idempotency_key": "sha256:2d2d...",
  "scan_summary": {
    "scanner_type": "zabbix",
    "summary_type": "noc_health",
    "status": "completed",
    "scanned_at": "2026-05-16T12:05:00Z",
    "scan_name": "NOC Health Snapshot",
    "target": "core-network",

    "total_hosts": 42,
    "total_monitors": 18,
    "total_services": 10,
    "total_events": 12,

    "results": {
      "critical": 1,
      "high": 3,
      "medium": 5,
      "low": 2,
      "info": 1
    },

    "health": {
      "health_score": 74.5,
      "health_label": "degraded",
      "availability_percentage": 97.8,
      "avg_response_time_ms": 482
    },

    "availability": {
      "hosts_up": 40,
      "hosts_down": 2,
      "monitors_up": 15,
      "monitors_down": 1,
      "monitors_degraded": 2
    },

    "performance": {
      "avg_cpu_usage": 71.4,
      "avg_memory_usage": 68.2,
      "avg_disk_usage": 63.7,
      "interfaces_down": 3,
      "packet_loss_percentage": 1.2
    },

    "certificates": {
      "ssl_expiring_soon": 0,
      "ssl_invalid": 0,
      "ssl_expired": 0
    },

    "meta": {
      "schema_version": "1.2",
      "snapshot_signature": "sha256:ab12...",
      "send_reason": "changed",
      "snapshot_mode": "delta_with_periodic_forced",
      "mad_version": "2.3.0",
      "integration_version": "generic-noc-1.0.0",
      "source": "mad-collector",
      "raw_source": "noc-integration",
      "collection_window_start": "2026-05-16T12:00:00Z",
      "collection_window_end": "2026-05-16T12:05:00Z"
    }
  },
  "findings": [
    {
      "name": "Operational event title",
      "severity": "high",

      "event_kind": "problem",
      "status": "active",

      "host": "switch-core-01",
      "host_id": "10084",

      "service_name": null,
      "monitor_name": null,
      "monitor_id": null,

      "port": null,
      "protocol": null,

      "metric_name": "ifOperStatus",
      "metric_value": "down",
      "threshold_value": "up",

      "started_at": "2026-05-16T11:40:00Z",
      "ended_at": null,
      "duration_seconds": 1500,

      "acknowledged": false,
      "maintenance": false,

      "description": "Interface Gi1/0/24 is down.",
      "solution": "Verify physical link, cable, transceiver, VLAN configuration or upstream provider.",
      "impact": "Possible connectivity degradation for dependent network segment.",

      "raw": {}
    }
  ]
}
```

---

## 13) Estructura de `scan_summary` NOC

Campos principales:

| Campo | Tipo | Descripcion |
|---|---|---|
| `scanner_type` | string | Integracion origen |
| `summary_type` | string | `noc_health`, `availability`, `network_discovery` u `other` |
| `status` | string | Estado del snapshot |
| `scanned_at` | string ISO8601 UTC | Fecha/hora UTC del snapshot |
| `scan_name` | string | Nombre legible del snapshot |
| `target` | string | Scope, grupo, ambiente, red, aplicacion o servicio monitoreado |
| `total_hosts` | integer | Total de hosts monitoreados |
| `total_monitors` | integer | Total de monitores configurados |
| `total_services` | integer | Total de servicios observados |
| `total_events` | integer | Total de eventos operativos detectados |
| `results` | object | Conteo por severidad operativa |
| `health` | object | Resumen de salud y disponibilidad |
| `availability` | object | Estado agregado de hosts/monitores |
| `performance` | object | Metricas operativas agregadas |
| `certificates` | object | Estado agregado de certificados |
| `meta` | object | Metadata tecnica y operativa |

Notas:

- `total_events` reemplaza a `total_problems` desde v1.2.
- Campos que no apliquen deben enviarse como `null` o `0` segun corresponda.
- Para integraciones tipo infraestructura/red, suelen aplicar `total_hosts`, `hosts_up`, `hosts_down`, `performance`, `interfaces_down`.
- Para integraciones tipo disponibilidad web/API, suelen aplicar `total_monitors`, `monitors_up`, `monitors_down`, `availability_percentage`, `avg_response_time_ms`, `certificates`.

---

## 14) Estructura de `findings[]` NOC

En el perfil NOC, `findings[]` debe mapearse internamente a `scan_noc_events`.

Campos obligatorios:

- `name`
- `severity`

Campos recomendados:

| Campo | Tipo | Descripcion |
|---|---|---|
| `name` | string | Nombre del evento operativo |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `event_kind` | string/null | Tipo de evento: `problem`, `incident`, `degradation`, `recovery`, `maintenance`, `availability_change`, `metric_threshold`, `certificate`, `other` |
| `status` | string/null | Estado: `active`, `resolved`, `acknowledged`, `maintenance`, `unknown` |
| `host` | string/null | Host, equipo, IP o FQDN afectado |
| `host_id` | string/null | Identificador del host en la herramienta origen |
| `service_name` | string/null | Servicio afectado |
| `monitor_name` | string/null | Monitor afectado |
| `monitor_id` | string/null | Identificador del monitor en la herramienta origen |
| `port` | string/null | Puerto relacionado |
| `protocol` | string/null | Protocolo relacionado |
| `metric_name` | string/null | Metrica relacionada |
| `metric_value` | string/null | Valor observado |
| `threshold_value` | string/null | Umbral esperado |
| `started_at` | string/null | Fecha/hora de inicio del evento |
| `ended_at` | string/null | Fecha/hora de cierre del evento, si aplica |
| `duration_seconds` | integer/null | Duracion del evento |
| `acknowledged` | boolean/null | Si el evento fue reconocido por un operador o por la herramienta |
| `maintenance` | boolean/null | Si el evento cae dentro de ventana de mantenimiento |
| `description` | string/null | Descripcion |
| `solution` | string/null | Recomendacion operativa |
| `impact` | string/null | Impacto operativo |
| `raw` | object/null | Payload original o campos especificos no normalizados |

Valores recomendados para `event_kind`:

- `problem`
- `incident`
- `degradation`
- `recovery`
- `maintenance`
- `availability_change`
- `metric_threshold`
- `certificate`
- `other`

Valores recomendados para `status`:

- `active`
- `resolved`
- `acknowledged`
- `maintenance`
- `unknown`

---

## 15) Politica `findings: []`

`findings: []` es valido y esperado.

- Debe persistir/actualizar `scan_summary` igualmente.
- Conteos quedan en 0 o recalculados en 0.
- Es clave para snapshots sin cambios.

Para SOC:

- `findings: []` significa que no hay hallazgos de seguridad/vulnerabilidad/eventos relevantes en ese snapshot.

Para NOC:

- `findings: []` significa que no hay eventos operativos activos o relevantes en ese snapshot.

---

## 16) Snapshot policy 24/7 recomendada

Modo recomendado:

- `snapshot_mode = delta_with_periodic_forced`

Enviar snapshot cuando:

- `snapshot_changed = true`
- o ciclo forzado cada `force_send_every_cycles = N`
- o `snapshot_always_send = true`

En `scan_summary.meta` incluir:

- `schema_version` = `"1.2"`
- `snapshot_signature`
- `send_reason`:
  - `changed`
  - `forced_cycle`
  - `always`
  - `first_snapshot`
- `snapshot_mode`
- `mad_version`
- `integration_version`
- `source`
- `raw_source`
- `collection_window_start`
- `collection_window_end`

---

## 17) Cadencia de ejecucion en Docker

Separar dos frecuencias:

- `poll cadence`: cada cuanto recolecta de la integracion.
- `send cadence`: cada cuanto evalua envio de snapshot.

Recomendado:

- poll: 1 a 5 min
- envio efectivo: por cambio + forzado periodico, por ejemplo cada 60 min

Operacion:

- healthcheck habilitado
- restart policy `unless-stopped`

---

## 18) Limites y anti-truncamiento

MAD debe aplicar limites soft para evitar payloads gigantes.

Campos cortos:

- `name` max 500 chars
- `host` max 255 chars
- `host_id` max 255 chars
- `service_name` max 255 chars
- `monitor_name` max 255 chars
- `monitor_id` max 255 chars
- `port` max 50 chars
- `protocol` max 50 chars
- `event_kind` max 100 chars
- `status` max 50 chars
- `metric_name` max 255 chars
- `metric_value` max 255 chars
- `threshold_value` max 255 chars

Campos largos:

- `description` max 8000 chars
- `solution` max 8000 chars
- `impact` max 8000 chars

Si MAD trunca campos:

- hacerlo de forma consistente
- registrar en `scan_summary.meta.truncated_fields`

---

## 19) Seguridad key vs scanner

Regla backend:

- `api_key.integration_type` debe coincidir con `scan_summary.scanner_type`
- `scan_summary.summary_type` debe ser coherente con `scan_summary.scanner_type`
- el backend decide la tabla destino

Regla MAD:

- validar antes de enviar para fallar temprano
- evitar ciclos que terminan en `401 AUTH_ERROR` o `400 VALIDATION_ERROR`

---

## 20) Idempotencia y reintentos

- `idempotency_key` estable por snapshot
- el hash debe calcularse sobre el contenido normalizado
- reintentos con backoff para `5xx` y timeouts
- cola local persistente para `sent=false`, `queued=true`
- flush automatico al recuperar backend

Comportamiento esperado ante duplicados en paralelo:

- Si llega el mismo `idempotency_key` en paralelo o repetido, la operacion debe resolverse como exito idempotente.
- No debe crear duplicados de la misma corrida logica.

---

## 20.1) Codigos de respuesta para idempotencia

Comportamiento oficial:

- `201` -> ingesta nueva creada
- `200` -> repeticion idempotente, ya procesado, mismo resultado
- `409` -> conflicto idempotente, misma key con payload distinto

En resumen:

- `scan_id` identifica el estado logico del snapshot.
- `idempotency_key` protege contra duplicados de ingest.

---

## 21) Observabilidad minima

Log/metricas por ciclo:

- `collected`
- `sent`
- `queued`
- `dropped`
- `send_reason`
- `scanner_type`
- `summary_type`
- `scan_id`
- `idempotency_key`

Recomendado para backend:

- `resolved_domain`
- `resolved_summary_table`
- `resolved_items_table`

Ejemplo:

```json
{
  "scanner_type": "zabbix",
  "summary_type": "noc_health",
  "resolved_domain": "noc",
  "resolved_summary_table": "scan_summaries_noc",
  "resolved_items_table": "scan_noc_events"
}
```

---

## 22) Reglas de ruteo interno backend

El backend debe aplicar este ruteo:

| scanner_type | summary_type | Summary table | Items table |
|---|---|---|---|
| `openvas` | `vulnerability` | `scan_summaries_soc` | `scan_findings` |
| `nessus` | `vulnerability` | `scan_summaries_soc` | `scan_findings` |
| `insightvm` | `vulnerability` | `scan_summaries_soc` | `scan_findings` |
| `qualys` | `vulnerability` | `scan_summaries_soc` | `scan_findings` |
| `tenable` | `vulnerability` | `scan_summaries_soc` | `scan_findings` |
| `rapid7` | `vulnerability` | `scan_summaries_soc` | `scan_findings` |
| `wazuh` | `security_events` | `scan_summaries_soc` | `scan_findings` |
| `zabbix` | `noc_health` | `scan_summaries_noc` | `scan_noc_events` |
| `uptime_kuma` | `availability` | `scan_summaries_noc` | `scan_noc_events` |

Reglas:

- El MAD no debe mandar el nombre de la tabla.
- El backend debe derivar la tabla.
- El backend debe rechazar combinaciones inconsistentes.
- El backend debe aceptar payloads v1.0/v1.1 sin `summary_type` y derivarlo cuando sea posible.

---

## 23) Labels recomendados para UI

La UI no debe mostrar siempre `Scan Findings`.

Debe mostrar el label segun `summary_type`:

| summary_type | Label UI recomendado |
|---|---|
| `vulnerability` | Vulnerability Findings |
| `security_events` | Security Findings |
| `noc_health` | NOC Events |
| `availability` | Availability Events |
| `network_discovery` | Discovered Assets |
| `other` | Findings |

Tambien puede usar labels mas comerciales:

| summary_type | Label comercial |
|---|---|
| `vulnerability` | Hallazgos de vulnerabilidad |
| `security_events` | Eventos de seguridad |
| `noc_health` | Eventos operativos |
| `availability` | Incidentes de disponibilidad |
| `network_discovery` | Activos descubiertos |
| `other` | Hallazgos |

---

## 24) Estado de alineacion backend

Backend debe quedar alineado con este contrato para:

- `scanner_type` obligatorio sin fallback implicito
- `summary_type` recomendado y validado si viene presente
- derivacion automatica de `summary_type` cuando no venga presente
- validacion explicita de `findings[].name`
- validacion explicita de `findings[].severity`
- deduplicacion por `idempotency_key`
- manejo de conflicto idempotente por payload distinto
- codigos estables para dedupe (`200/201/409`)
- ruteo interno por dominio:
  - SOC -> `scan_summaries_soc` + `scan_findings`
  - NOC -> `scan_summaries_noc` + `scan_noc_events`

---

## 25) Nota de compatibilidad

Este contrato mantiene compatibilidad con v1.0/v1.1:

- Se conserva `POST /api/scans/ingest`
- Se conserva `scan_summary`
- Se conserva `findings[]`
- Se conserva `scan_id`
- Se conserva `idempotency_key`

Cambios v1.2:

- Se mantiene `scan_summary.summary_type`
- Se formaliza el payload generico SOC
- Se formaliza el payload generico NOC
- Se cambia el concepto NOC de `problems` a `events`
- Se formaliza la tabla interna NOC como `scan_noc_events`
- Se formaliza el ruteo interno del backend hacia tablas SOC o NOC