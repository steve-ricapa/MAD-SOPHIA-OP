# Reporte de Alineación de Versiones e Integraciones

Fecha: 2026-05-06  
Repositorio: `MAD-SOPHIA-OP`

## 1) Objetivo
Validar si las integraciones del proyecto están alineadas con las versiones objetivo solicitadas, identificando:

- Cambios relevantes en releases oficiales.
- Impacto real en el código de cada integración.
- Estado de alineación (`Alineado` / `Parcial` / `No alineado`).
- Riesgos y posibles fallas.

## 2) Versiones objetivo solicitadas

- InsightVM: `8.43.0`
- OpenVAS (gvmd): `26.13.0`
- Nessus: `10.12.0`
- Uptime Kuma: `2.2.1`
- Zabbix: `7.4.9`

---

## 3) Resumen ejecutivo (rápido)

- **InsightVM 8.43.0**: `Alineado`
- **OpenVAS 26.13.0**: `Alineado (con validación recomendada de parser XML)`
- **Nessus 10.12.0**: `Alineado (con cautela: versión Early Access)`
- **Uptime Kuma 2.2.1**: `Alineado`
- **Zabbix 7.4.9**: `Alineado`

Riesgo global: **Bajo a medio** (medio principalmente por Nessus 10.12.0 Early Access y por variaciones de schema XML/JSON en runtime).

---

## 4) Análisis por integración

## 4.1 InsightVM `8.43.0`

### Cambios relevantes investigados
- En release notes de abril 2026 se reportan cambios/fixes, incluyendo uno de API para persistencia de cambios en custom scan templates.
- También hay mención previa (8.41) de ajuste en endpoint de scan engines para historial.

### Qué usa el agente en este repo
- Archivo clave: `insightVM_integration/agents/insightvm_agent.py`
- Endpoints observados:
  - `GET /assets`
  - `GET /assets/{asset_id}/vulnerabilities`
  - `GET /vulnerabilities/{vuln_id}`

### Evaluación de alineación
- **Estado: Alineado**
- Motivo: la integración no usa endpoints de modificación de scan templates ni `scan_engines/{id}/scans`.

### Qué podría fallar
- Cambios de schema en campos de assets/vulnerabilities (renombres, nullability, tipos).
- Respuestas parciales o errores HTTP transitorios (ya hay reintentos en cliente, pero no validación estricta de contrato).

---

## 4.2 OpenVAS / gvmd `26.13.0`

### Cambios relevantes investigados
- Existe release `gvmd 26.13.0` (enero 2026), con mejoras y fixes en manager/credenciales/discovery.
- No se detectó cambio disruptivo explícito para el flujo básico `get_tasks`/`get_report`.

### Qué usa el agente en este repo
- Archivo clave: `openVAS_integration/gvm_client.py`
- Protocolo: **GMP** vía `python-gvm`.
- Operaciones:
  - `get_tasks()`
  - `get_report(report_id, ...)`

### Evaluación de alineación
- **Estado: Alineado (con validación recomendada)**
- Motivo: uso estándar de GMP; dependencia pinneada `python-gvm==26.9.0`.

### Qué podría fallar
- Variaciones en XML de reportes que rompan parsing en `services.py/main.py`.
- Diferencias de entorno (TLS/socket/permisos gvmd).
- Compatibilidad fina entre versión de gvmd y parser esperado por el agente.

---

## 4.3 Nessus `10.12.0`

### Cambios relevantes investigados
- `10.12.0` aparece como **Early Access** (abril 2026).
- Cambios mencionados: UI, OpenSSL/FIPS, ajustes de permisos de API para ciertos endpoints.

### Qué usa el agente en este repo
- Archivo clave: `nessus_integration/collector.py`
- Endpoints observados:
  - `GET /scans`
  - `GET /scans/{id}`
- Autenticación: `X-ApiKeys`.

### Evaluación de alineación
- **Estado: Alineado (con cautela)**
- Motivo: el flujo usado por el agente no depende de endpoints señalados como restringidos en la nota.

### Qué podría fallar
- Al ser Early Access, puede haber cambios antes de GA.
- Cambios en estructura de `vulnerabilities`, `hosts` o `status`.
- Políticas de permisos más estrictas en cuentas con roles limitados.

---

## 4.4 Uptime Kuma `2.2.1`

### Cambios relevantes investigados
- Release `2.2.1` (10 marzo 2026) con fixes y security update.
- Se reporta fix relacionado con métricas Prometheus (`uptime ratio` / `avg response time`).

### Qué usa el agente en este repo
- Archivo clave: `uptimekuma_integration/collector.py`
- Fuente: `GET /metrics`
- Métricas clave parseadas:
  - `monitor_status`
  - `monitor_response_time`
  - `monitor_uptime_ratio`

### Evaluación de alineación
- **Estado: Alineado**
- Motivo: el agente está diseñado para ese modelo de métricas y maneja parsing por etiquetas.

### Qué podría fallar
- Si `/metrics` no expone `monitor_status`, el agente falla por validación explícita.
- Cambios de nombre en métricas o labels.
- Entornos con auth en `/metrics` mal configurada.

---

## 4.5 Zabbix `7.4.9`

### Cambios relevantes investigados
- Release notes oficiales `7.4.9` (8 abril 2026): mejoras de compatibilidad (PHP/DB) y correcciones.
- No se identificó breaking change público en JSON-RPC para los métodos usados por el agente.

### Qué usa el agente en este repo
- Archivo clave: `zabix_integration/zbx_api.py`
- Métodos JSON-RPC:
  - `apiinfo.version`
  - `user.login` (con fallback `username` y `user`)
  - `problem.get`, `trigger.get`, `host.get`, `event.get`
- Manejo de auth Bearer y relogin.

### Evaluación de alineación
- **Estado: Alineado**
- Motivo: compatibilidad de login ya contemplada en código y uso de métodos estables de API.

### Qué podría fallar
- Permisos insuficientes del usuario API para `problem.get/trigger.get`.
- Cambios de performance/volumen (límites altos sin paginación fina).
- Certificados SSL/self-signed mal gestionados.

---

## 5) Hallazgos técnicos en el repo (importantes)

1. `insightVM_integration/requirements.txt` está poco estricto (`requests`, `python-dotenv` sin pin exacto).  
   Riesgo: drift de dependencias por actualizaciones automáticas.

2. `openVAS_integration` sí está pinneado (`python-gvm==26.9.0`, `requests==2.32.3`), mejor controlado.

3. Varias integraciones dependen de contratos de respuesta no versionados localmente (sin tests de contrato contra respuestas reales del vendor).

---

## 6) Conclusión final

Con la evidencia revisada, las integraciones están **mayormente alineadas** con las versiones solicitadas y **deberían funcionar** en condiciones normales.

El mayor riesgo no está en “endpoint inexistente”, sino en:
- cambios de schema de respuesta,
- permisos/autenticación en entornos reales,
- y drift de dependencias no pinneadas.

---

## 7) Recomendaciones inmediatas (prácticas)

1. Ejecutar smoke test por integración con una corrida `--once` y guardar evidencia de JSON de salida.
2. Agregar matriz de compatibilidad en repo (`COMPATIBILITY_MATRIX.md`) con versiones aprobadas.
3. Pinear dependencias faltantes (especialmente InsightVM).
4. Añadir tests de contrato mínimos por conector (campos obligatorios por endpoint).
5. Para Nessus 10.12.0, considerar validar en ambiente de prueba por ser Early Access.

---

## 8) Fuentes consultadas

- Rapid7 April 2026 Release Notes:  
  https://docs.rapid7.com/insight/release-notes-2026-april/

- Tenable Nessus 2026 Release Notes / Nessus docs:  
  https://docs.tenable.com/release-notes/Content/nessus/2026.htm  
  https://docs.tenable.com/Nessus.htm

- Uptime Kuma Releases:  
  https://github.com/louislam/uptime-kuma/releases

- Greenbone / python-gvm / gvmd references:  
  https://greenbone.github.io/python-gvm/  
  https://greenbone.github.io/python-gvm/usage.html  
  https://greenbone.github.io/python-gvm/api/protocols.html  
  https://newreleases.io/project/github/greenbone/gvmd/release/v26.13.0

- Zabbix 7.4.9 release notes:  
  https://www.zabbix.com/release_notes  
  https://www.zabbix.com/rn/rn7.4.9

