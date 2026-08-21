# Fase 2: Contrato canonico de datos

## Estado

| Campo | Valor |
| --- | --- |
| Estado | En desarrollo |
| Version inicial | `1.0.0` |
| JSON Schema | Draft 2020-12 |
| Directorio | `schemas/v1/` |

Esta fase define el contrato interno de V2. El formato que consume el backend V1 sera una proyeccion de compatibilidad y no condicionara el dominio canonico.

## Decisiones

- Un envelope pertenece a un solo tenant y una sola instancia de fuente.
- `tenant_id` es un string canonico no vacio. Los IDs numericos V1 se convierten a su representacion decimal.
- Los secretos pertenecen al transporte y nunca al envelope, registros, spool o diagnosticos.
- Assets, observations, findings y detections tienen semanticas diferentes.
- Uptime Kuma genera observations; no genera CVSS ni vulnerability findings.
- Zabbix puede generar observations y detections o findings operativos segun el objeto fuente.
- Los scanners generan findings y scan activity; Wazuh genera principalmente detections.
- Los campos opcionales desconocidos se omiten. No se inventan `N/A`, `0`, puerto `161`, timestamps ni scores.
- Todos los timestamps se normalizan a RFC 3339 UTC.
- Los schemas usan `additionalProperties: false` salvo `attributes`, que es una extension controlada por allowlist del mapper.

## Envelope

`DeliveryEnvelope` contiene:

- version del contrato;
- identidad determinista de entrega;
- tenant y fuente;
- ejecucion de adquisicion;
- assets referenciados;
- observations, findings y detections aceptados.

El envelope de delivery solo debe contener registros cuya decision sea `accepted`. Los registros `rejected` se contabilizan en el run y los `quarantined` se almacenan localmente con su razon. Los schemas de entidad admiten los tres resultados para poder validar etapas internas, pero el boundary de delivery aplica esta regla adicional.

## Entidades

### Run

Representa una ejecucion de una fuente, no un evento de negocio. Conserva ventana, resultado, parcialidad, contadores y errores clasificados.

### Asset

Representa la identidad y contexto minimo de un objetivo observado. No obliga a tener IP, hostname o URL cuando la fuente no los ofrece. `source_asset_id` conserva la identidad original y `identity_quality` indica si es nativa o derivada.

### Observation

Representa disponibilidad, estado, latencia, uptime, certificado o una metrica operacional. Mantiene el estado fuente sin convertirlo en severidad de vulnerabilidad.

### Finding

Representa una vulnerabilidad o problema aplicable a un asset. `source_severity` y `severity` son afirmaciones separadas. CVSS solo existe dentro de `scores` cuando la fuente aporta un score real con sistema y version.

### Detection

Representa una alerta o evento de seguridad. Conserva regla, tiempo de ocurrencia, referencias MITRE y referencias de cumplimiento sin forzarlas dentro de un finding.

## Identidad

Todos los hashes usan SHA-256 sobre JSON UTF-8 canonico. La serializacion exacta, implementada en `src/txdx_etl/domain/identity.py`, es:

- los componentes se representan como un objeto JSON con nombres de clave estables;
- claves ordenadas lexicograficamente y separadores sin espacios;
- `ensure_ascii` desactivado; la salida se codifica en UTF-8;
- valores `None` o vacios se omiten del objeto antes de serializar;
- para `delivery_id`, la lista de `record_id` se ordena lexicograficamente antes del hash, de modo que reordenes del lote no cambian la identidad.

Los componentes se almacenan como strings antes de serializar. Un campo no-string o vacio en un componente obligatorio es un error, no se silencia.

### Asset

```text
asset_id = sha256(
  tenant_id,
  source.type,
  source.instance_id,
  source_asset_id
)
```

Formato recomendado:

```text
asset:sha256:<64 hex>
```

Si la fuente no ofrece ID nativo, el conector construye `source_asset_id` con los campos de identidad documentados y marca `identity_quality=derived`.

### Record

Base comun:

```text
tenant_id + source.type + source.instance_id + record_type + source_object_id
```

Discriminador por entidad:

| Entidad | Discriminador |
| --- | --- |
| Observation de evento fuente | ID o tiempo fuente y hecho observado |
| Observation inferida | estado anterior, estado actual y bucket de observacion |
| Observation de refresh | estado y bucket de refresh |
| Observation inicial | estado actual y bucket de primera adquisicion |
| Finding | source finding ID, asset y estado fuente |
| Detection | source event ID |

Formato recomendado:

```text
record:sha256:<64 hex>
```

El mismo hecho reextraido conserva `record_id`. Un cambio real de estado o nueva ocurrencia genera otro ID.

### Delivery

```text
delivery_id = sha256(
  schema_version,
  tenant_id,
  source.type,
  source.instance_id,
  lista ordenada de record_id
)
```

Formato recomendado:

```text
delivery:sha256:<64 hex>
```

Un retry conserva `delivery_id`, objeto de spool e `Idempotency-Key`.

## Proveniencia

Cada asset y registro conserva:

- `connector_version`;
- `mapping_version`;
- `policy_version`;
- `collected_at`;
- `raw_record_hash`.

`raw_record_hash` identifica el registro fuente saneado usado por el mapper. No implica retener el payload crudo. La fuente e instancia se heredan del envelope.

## Filtrado

Cada registro tiene una decision auditable:

| Resultado | Significado |
| --- | --- |
| `accepted` | Pasa a outbox y delivery |
| `rejected` | Valido, pero no relevante para la politica actual |
| `quarantined` | No puede procesarse con seguridad por error de contrato o identidad |

La decision incluye `reason_code`, `policy_version` y `decided_at`. Los codigos son strings estables para metricas y auditoria; los mensajes humanos no forman parte de la identidad.

## Politica de nulos y tipos

- Omitir un campo opcional cuando la fuente no lo ofrece.
- Usar arrays vacios cuando la coleccion fue evaluada y no contiene elementos.
- No usar strings vacios para representar ausencia.
- No convertir ausencia numerica en cero.
- No convertir estados operativos en CVSS.
- `port` es integer entre 1 y 65535 cuando existe.
- Ratios usan numeros entre 0 y 1.
- Duraciones y latencias declaran su unidad.
- `source_event_time` solo existe si procede de la fuente; `observed_at` siempre indica adquisicion ETL.

## Extensiones

`attributes` permite metadata especifica de fuente despues de aplicar:

- allowlist de claves;
- redaccion de secretos;
- limites de profundidad, propiedades y bytes;
- normalizacion de tipos;
- pruebas de contrato.

No se permite copiar respuestas completas bajo nombres como `raw`, `payload` o `response`.

## Compatibilidad con backend V1

El adaptador de delivery podra proyectar registros aceptados hacia:

```text
scan_id
company_id
idempotency_key
scanned_at
event_type
scanner_type
scan_summary
findings
```

Reglas de compatibilidad:

- `api_key` nunca se agrega al payload; solo se usa al solicitar la URL de upload.
- observations no reciben CVSS sintetico.
- `company_id` se obtiene de configuracion de compatibilidad, no del dominio.
- summaries son derivados del run y registros; no son fuente de verdad.
- los IDs canonicos se conservan en la proyeccion para deduplicacion.

La compatibilidad final requiere confirmar el schema del backend receptor, que no esta presente en este repositorio.

## Versionado

- `schema_version`: contrato del envelope y entidades.
- `connector_version`: comportamiento de extraccion.
- `mapping_version`: transformacion fuente a canonico.
- `policy_version`: filtrado y priorizacion.

Cambio incompatible incrementa la version mayor. Campos opcionales nuevos incrementan la menor. Correcciones documentales o restricciones equivalentes incrementan patch.

## Criterios de salida

- Todos los schemas pasan `Draft202012Validator.check_schema`.
- Existe al menos un fixture valido de Uptime Kuma.
- Los tests rechazan secretos y propiedades desconocidas en el envelope.
- Los tests diferencian ausencia de cero y timestamps fuente de observacion.
- Identidad y politica de nulos estan aprobadas.
- La proyeccion de compatibilidad queda separada del modelo canonico.
- Los conectores pueden comenzar sin inventar campos fuera del contrato.

## Implementacion actual

- `src/txdx_etl/domain/identity.py`: funciones deterministas `asset_id`, `record_id`, `delivery_id` y `raw_record_hash`, con validacion estricta de componentes y vectores dorados en `tests/unit/test_identity.py`.
- `src/txdx_etl/pipeline/validation.py`: validador cross-record del envelope que comprueba referencias asset-registro, unicidad de IDs, conteos del run, frontera solo-accepted, coherencia del `delivery_id` recalculado y orden temporal del run; pruebas en `tests/contract/test_envelope_cross_record.py`.
- `src/txdx_etl/pipeline/envelope.py`: builder que arma el envelope, calcula conteos por tipo y decision y genera `delivery_id` con las funciones de identidad.
- El fixture de Uptime Kuma es auto-consistente: sus `asset_id`, `record_id` y `delivery_id` fueron generados con la implementacion real.
