# Análisis de Integración: WazuhC Agent → VICTOR / Sophia

> **Fecha:** 2026-03-09  
> **Objetivo:** Auditar el estado actual del WazuhC Agent, identificar bugs y datos faltantes,  
> y definir el plan de trabajo para que la data llegue completa y correcta al Dashboard/VICTOR.

---

## 1. Contexto y Objetivo

Actualmente trabajamos con **VICTOR** (agente intermediario) que procesa tickets generados por **Sophia** (con contexto de OpenVAS, Rapid7, Zabbix, etc.). VICTOR genera tickets en estado "Por Procesar" → al hacer clic en "Remediar", ejecuta un plan de pasos y eventualmente lanzará un **Agente de Remediación**.

**Pre-requisito obligatorio antes de construir el Agente de Remediación:**

> El WazuhC Agent debe mandar la data correcta → que llegue bien → que se muestre bien  
> → y si no manda algo, que tenga una razón documentada de por qué no.

---

## 2. Comparativa: ¿Qué tenemos vs. Qué nos falta?

### ✅ Lo que YA FUNCIONA

| Capacidad | Archivo | Estado |
|---|---|---|
| Extracción de alertas desde Wazuh Indexer (OpenSearch) | `src/indexer.py` | ✅ Funcional |
| Polling del inventario de agentes (salud, estado) | `src/api.py` | ✅ Funcional |
| Autenticación JWT con la API de Wazuh | `src/api.py` | ✅ Con re-auth automático en 401 |
| Normalización básica de alertas (severity, dedup_id) | `src/aggregator.py` | ✅ Funcional |
| Persistencia de checkpoints (SQLite) | `src/state.py` | ✅ Funcional |
| Envío HTTP con reintentos y backoff exponencial | `src/sender.py` | ✅ Funcional |
| Modo Dry-Run (guarda JSON localmente sin enviar) | `main.py` | ✅ Funcional |
| Pre-cálculo de Top Agents y Top Rules | `src/aggregator.py` | ✅ Funcional |
| Detección de cambios de estado de agentes | `src/aggregator.py` | ✅ Funcional |
| Healthcheck HTTP en `/health` (para Docker/K8s) | `main.py` | ✅ Funcional |
| Logs estructurados en JSON con rotación | `main.py` (loguru) | ✅ Funcional |
| Endpoints de SCA y Vulnerabilidades listos en API | `src/api.py` | ⚠️ Implementados pero no usados |

---

### 🔴 BUGS ENCONTRADOS EN EL CÓDIGO

Estos son problemas reales que **van a causar errores** o ya los están causando:

#### BUG 1: Estructura del `finding` inconsistente con el código y los tests
**Archivos:** `src/aggregator.py` línea 39-50 vs `main.py` línea 51

El `normalize_alert()` retorna los campos `host`, `name`, `rule_id`, `rule_level`, `agent_id` como claves planas:
```json
{ "host": "kumita", "rule_id": "510", "agent_id": "005", "severity": "high" }
```

Pero el reporte real generado en `debug_output/report_*.json` muestra una **estructura DIFERENTE** con objetos anidados `rule: {}` y `agent: {}`:
```json
{ "rule": {"id": "510", "level": 7, "description": "..."}, "agent": {"id": "005", "name": "kumita"} }
```

**Impacto:** Hay una discrepancia entre lo que el código dice que hace y lo que realmente sale. El test unitario `test_aggregator.py` línea 16 espera `normalized['agent']['name']` pero `normalize_alert` retorna `normalized['host']`. **El test unitario está fallando silenciosamente o se actualizó el código y no los tests.**

#### BUG 2: `eval()` usado para deserializar estado — Riesgo de seguridad e inestabilidad
**Archivo:** `main.py` líneas 41 y 118

```python
agent_summary = eval(agent_summary)   # línea 41
prev_agents_map = eval(prev_agents_str)  # línea 118
```

`eval()` puede ejecutar código arbitrario y causa crashes si el string guardado en SQLite tiene un formato inesperado. **Debe usarse `json.loads()`**.

#### BUG 3: El checkpoint avanza aunque el envío falle después de reintentos
**Archivos:** `main.py` línea 80 + `src/sender.py` línea 37

En `sender.py`, si se agotan los 3 reintentos, retorna `False`. En `main.py`:
```python
if success:
    state.update_checkpoint("alerts_timestamp", new_last_ts)
```
Esto parece correcto, **PERO solo si `DRY_RUN=false`**. Cuando `DRY_RUN=true`, `success` siempre es `True` (línea 76) y el checkpoint avanza, lo cual está bien para pruebas. Sin embargo, en producción, si `sender.send_report()` falla (retorna `False`) y el checkpoint no avanza, el **siguiente ciclo re-extrae las mismas alertas** — esto es correcto y es el comportamiento deseado (at-least-once). **Verificado: este flujo está OK.** ~~No es bug~~.

> ⚠️ **NOTA:** Sin embargo, actualmente `max_retries=3` y el intervalo de polling es 10s. Si el backend se cae 30+ segundos esas alertas se pierden hasta que el checkpoint no avanzado las re-extraiga. Considerar aumentar `max_retries` a 5 o más.

#### BUG 4: `limit=5` hardcodeado en producción
**Archivo:** `main.py` línea 32

```python
raw_alerts = await indexer.get_new_alerts(last_ts, limit=5)
```

El `IndexerClient.get_new_alerts()` acepta `limit=500` por defecto, pero `main.py` lo sobreescribe con `limit=5`. Esto significa que **el agente solo procesa 5 alertas por ciclo** (cada 10 segundos). Si Wazuh genera un burst de 200 alertas, tardará `200/5 × 10s = ~7 minutos` en procesarlas todas. **Esto probablemente fue dejado así durante desarrollo/debug y debería ser `limit=500` en producción.**

---

### 🟡 DATOS QUE WAZUH ENVÍA PERO EL AGENTE ESTÁ DESCARTANDO

Comparando `raw_alerts_inspection.json` (datos crudos de Wazuh) contra el output del `normalize_alert()`:

| Campo de Wazuh | ¿Se envía al Backend? | Impacto para VICTOR/Sophia |
|---|---|---|
| `rule.mitre.id` (ej: `T1078`) | ✅ Sí | Sophia puede clasificar la táctica |
| `rule.mitre.technique` (ej: `"Valid Accounts"`) | ❌ **NO** — se descarta | Sophia pierde el nombre legible de la técnica |
| `rule.mitre.tactic` (ej: `"Defense Evasion"`) | ❌ **NO** — se descarta | Sophia pierde el contexto táctico completo |
| `rule.groups` (ej: `["pam","syslog"]`) | ❌ **NO** | El Dashboard no puede categorizar por tipo |
| `rule.pci_dss` (ej: `"10.2.5"`) | ❌ **NO** | No se puede reportar cumplimiento PCI |
| `rule.hipaa` (ej: `"164.312.b"`) | ❌ **NO** | No se puede reportar cumplimiento HIPAA |
| `rule.nist_800_53` (ej: `"AU.14"`) | ❌ **NO** | No se puede reportar cumplimiento NIST |
| `rule.gdpr` (ej: `"IV_32.2"`) | ❌ **NO** | No se puede reportar cumplimiento GDPR |
| `agent.ip` (ej: `"192.168.18.172"`) | ❌ **NO** | El Dashboard no sabe la IP del equipo afectado |
| `full_log` (log completo crudo) | ❌ **NO** | VICTOR no puede ver el detalle del evento para remediación |
| `data.*` (metadata contextual del evento) | ❌ **NO** | Se pierde info como usuarios, IPs fuente, dispositivos |
| Cambios de estado de agentes (active→disconnected) | ❌ **NO** — solo se loguea | VICTOR no sabe que un servidor se cayó |
| SCA (Security Configuration Assessment) | ❌ **NO** — API existe pero no se usa | No hay datos de hardening/compliance |
| Vulnerabilidades por agente | ❌ **NO** — API existe pero no se usa | No hay datos de vulnerabilidades conocidas |

---

### 🟢 DATOS QUE DELIBERADAMENTE NO SE ENVÍAN (Justificado)

| Campo omitido | Razón |
|---|---|
| Alertas con `rule.level < MIN_RULE_LEVEL` | Reducción de ruido. Nivel 3 = "Login exitoso", no es un incidente. Enviar todo saturaría Sophia de falsos tickets |
| `decoder.*` (detalles internos del parser de Wazuh) | Irrelevante para la remediación, es metadata interna del engine |
| `predecoder.*` (pre-parsing de Wazuh) | Idem, solo útil para debugging interno de Wazuh |
| `input.*` (tipo de fuente del log) | Redundante, el `location` ya indica la fuente |
| `manager.*` | Siempre será el mismo servidor Wazuh, no aporta valor para VICTOR |
| Campos de `syscheck` con hashes completos de ficheros | Demasiado pesado para el feed global. VICTOR debería consultar bajo demanda si los necesita |

---

## 3. Plan de Acción — Prioridades para Pulir el Agente

### Fase 1: Corrección de Bugs Críticos (Antes de cualquier prueba)

| # | Tarea | Archivo | Prioridad |
|---|---|---|---|
| 1.1 | Subir `limit=5` a `limit=500` (o hacerlo configurable via `.env`) | `main.py:32` | 🔴 Crítica |
| 1.2 | Reemplazar `eval()` por `json.loads()` para deserializar estado | `main.py:41,118` | 🔴 Crítica |
| 1.3 | Reconciliar el formato de `normalize_alert()` con lo que realmente necesita el Dashboard | `src/aggregator.py` | 🔴 Crítica |
| 1.4 | Arreglar/actualizar el test unitario para que refleje la estructura real | `tests/test_aggregator.py` | 🟡 Media |

### Fase 2: Enriquecimiento de Datos (Para que Sophia/VICTOR tengan la data completa)

| # | Tarea | Archivo | Prioridad |
|---|---|---|---|
| 2.1 | Incluir MITRE completo: `technique`, `tactic` además de `id` | `src/aggregator.py` | 🔴 Crítica |
| 2.2 | Incluir `agent.ip` en el finding | `src/aggregator.py` | 🔴 Crítica |
| 2.3 | Incluir `rule.groups` para categorización | `src/aggregator.py` | 🟡 Media |
| 2.4 | Incluir compliance frameworks: `pci_dss`, `hipaa`, `nist_800_53`, `gdpr` | `src/aggregator.py` | 🟡 Media |
| 2.5 | Opcional: incluir `full_log` truncado (primeros 500 chars) para contexto | `src/aggregator.py` | 🟢 Baja |
| 2.6 | Convertir cambios de estado de agentes (disconnected) en findings sintéticos | `main.py` | 🟡 Media |

### Fase 3: Validación End-to-End

| # | Tarea | Descripción |
|---|---|---|
| 3.1 | Ejecutar en `DRY_RUN=true` y validar el JSON contra el esquema del Dashboard | Verificar que los nuevos campos no rompan el backend |
| 3.2 | Apuntar con `DRY_RUN=false` al entorno de staging del Dashboard | Verificar visualización en tiempo real (< 15s latencia) |
| 3.3 | Validar que VICTOR/Sophia pueden leer los campos de MITRE y compliance | Test funcional con ticket de ejemplo |

---

## 4. Esquema JSON Propuesto para el `finding` Enriquecido

Así debería verse cada `finding` después de aplicar las Fases 1 y 2:

```json
{
    "dedup_id": "wazuh-da2c01096048dd4e9619581b4adde121",
    "timestamp": "2026-01-30T22:01:23.854+0000",
    "severity": "high",
    "rule": {
        "id": "510",
        "level": 7,
        "description": "Host-based anomaly detection event (rootcheck).",
        "groups": ["rootcheck"]
    },
    "agent": {
        "id": "005",
        "name": "kumita",
        "ip": "192.168.50.10"
    },
    "mitre": {
        "ids": ["T1078"],
        "techniques": ["Valid Accounts"],
        "tactics": ["Defense Evasion", "Persistence"]
    },
    "compliance": {
        "pci_dss": ["10.2.5"],
        "hipaa": ["164.312.b"],
        "nist_800_53": ["AU.14", "AC.7"],
        "gdpr": ["IV_32.2"]
    }
}
```

---

## 5. Conclusión

El agente **tiene una base sólida y funcional** (polling, checkpoints, heartbeats, dry-run, reintentos). Sin embargo, hay **bugs concretos que corregir** (eval, limit=5, estructura inconsistente del finding) y **datos críticos que se están descartando** (MITRE completo, IP del agente, compliance) que Sophia y VICTOR necesitan para generar tickets accionables.

**Recomendación:** Ejecutar la Fase 1 y Fase 2 antes de cualquier prueba de integración con el Dashboard. Solo después de que la data llegue completa y correcta, proceder con el Agente de Remediación.
