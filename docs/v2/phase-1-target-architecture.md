# Fase 1: Arquitectura objetivo V2

## Decision principal

V2 sera un monolito modular en Python, ejecutado como un unico servicio dentro de un contenedor por appliance. Internamente tendra conectores independientes y un nucleo ETL compartido.

Esta decision evita el costo de Kafka, Spark, Airflow, Celery, Redis o microservicios por integracion. Ninguno es necesario para seis fuentes, un solo appliance y un presupuesto de 4 CPU y 8 GB RAM. La arquitectura conserva puertos claros para sustituir SQLite o el destino sin reescribir los conectores.

## Flujo

```text
Scheduler
  -> Connector.extract(cursor, limits)
  -> RawRecord
  -> Mapper.normalize()
  -> CanonicalRecord
  -> Validator
  -> RelevancePolicy
  -> Identity + exact deduplication
  -> Durable spool + SQLite outbox/checkpoint
  -> Delivery worker
  -> backend/S3 acknowledgement
```

El orden es intencional:

1. La extraccion produce paginas o registros, no inventarios completos.
2. La normalizacion conserva hechos antes de aplicar decisiones de negocio.
3. La validacion impide que datos incompletos contaminen el destino.
4. El filtrado registra una decision auditable y su version de politica.
5. La identidad determinista evita duplicados por polling, solapamiento o retry.
6. El dato se hace durable antes de avanzar el checkpoint.
7. La entrega puede repetirse porque utiliza la misma clave idempotente.

## Estructura del repositorio

```text
MAD-SOPHIA-OP/
|-- pyproject.toml
|-- uv.lock
|-- Dockerfile
|-- .dockerignore
|-- docs/
|   `-- v2/
|-- migrations/
|   `-- versions/
|-- schemas/
|   `-- v1/
|       |-- common.schema.json
|       |-- envelope.schema.json
|       |-- run.schema.json
|       |-- asset.schema.json
|       |-- observation.schema.json
|       |-- finding.schema.json
|       `-- detection.schema.json
|-- src/
|   `-- txdx_etl/
|       |-- __init__.py
|       |-- cli.py
|       |-- config/
|       |   |-- loader.py
|       |   `-- models.py
|       |-- domain/
|       |   |-- enums.py
|       |   |-- identity.py
|       |   |-- models.py
|       |   `-- provenance.py
|       |-- ports/
|       |   |-- connector.py
|       |   |-- delivery.py
|       |   `-- state.py
|       |-- pipeline/
|       |   |-- deduplication.py
|       |   |-- filtering.py
|       |   |-- runner.py
|       |   `-- validation.py
|       |-- connectors/
|       |   |-- uptime_kuma/
|       |   |   |-- client.py
|       |   |   |-- connector.py
|       |   |   |-- mapper.py
|       |   |   `-- parser.py
|       |   `-- zabbix/
|       |       |-- client.py
|       |       |-- connector.py
|       |       `-- mapper.py
|       |-- infrastructure/
|       |   |-- database.py
|       |   |-- delivery.py
|       |   |-- http.py
|       |   |-- migrations.py
|       |   `-- spool.py
|       |-- observability/
|       |   |-- logging.py
|       |   `-- metrics.py
|       `-- runtime/
|           |-- health.py
|           |-- scheduler.py
|           `-- service.py
`-- tests/
    |-- unit/
    |-- contract/
    |-- integration/
    |-- resilience/
    `-- fixtures/
```

## Responsabilidades

### `domain`

Contiene modelos y reglas que no dependen de HTTP, SQLite, Docker ni proveedores. No importa desde `infrastructure` o `connectors`.

Entidades iniciales:

- `Asset`: identidad y contexto de un activo.
- `Observation`: estado, metrica o disponibilidad observada.
- `Finding`: problema o vulnerabilidad aplicada a un activo.
- `Detection`: actividad o alerta de seguridad.
- `ScanRun`: ejecucion, ventana, contadores y resultado de una fuente.
- `Provenance`: origen, tiempos, versiones y hashes de transformacion.
- `DeliveryEnvelope`: lote versionado sin credenciales de transporte.

No se utilizara una tabla generica de `alerts` para todo. Uptime Kuma produce principalmente observaciones; Zabbix puede producir observaciones y problemas; los scanners producen findings; Wazuh produce detections y, en algunos casos, findings.

### `ports`

Define interfaces pequenas entre el nucleo y la infraestructura:

```python
class Connector(Protocol):
    async def extract(self, cursor: Cursor | None, limits: ExtractionLimits) -> AsyncIterator[RawPage]: ...

class StateStore(Protocol):
    async def commit_batch(self, batch: DurableBatch) -> None: ...

class Delivery(Protocol):
    async def send(self, item: OutboxItem) -> DeliveryReceipt: ...
```

Los conectores no conocen S3, la cola, el frontend ni la estructura de SQLite.

### `connectors`

Cada conector contiene solamente:

- cliente y autenticacion del proveedor;
- paginacion/cursor especifico;
- parser de respuesta;
- mapper fuente a canonico;
- clasificacion de errores de la fuente.

No contiene scheduler, `.env`, delivery, outbox o persistencia global.

### `pipeline`

Ejecuta etapas comunes y deterministas. Las politicas de filtrado se versionan y producen `accepted`, `rejected` o `quarantined`, siempre con codigo de razon.

### `infrastructure`

Implementa HTTP, SQLite, migraciones, spool de archivos y el protocolo actual de URL prefirmada. Puede cambiarse sin alterar dominio o conectores.

### `runtime`

Coordina ciclos, concurrencia limitada, apagado ordenado, health/readiness y workers de delivery. Solo permite un ciclo activo por `(tenant_id, source)`.

## Persistencia durable

SQLite almacenara metadata transaccional. Los payloads grandes se almacenaran como archivos, no BLOBs.

Tablas iniciales:

| Tabla | Proposito |
| --- | --- |
| `checkpoints` | Cursor confirmado por tenant, fuente y stream. |
| `dedup_records` | Identidades canonicas vistas y su expiracion. |
| `outbox` | Entregas pendientes, intentos y proximo retry. |
| `dead_letters` | Fallos permanentes o agotados. |
| `quarantine` | Registros invalidos con razones de validacion. |
| `leases` | Evita ciclos simultaneos de la misma fuente. |
| `runs` | Metricas y resultado de cada ejecucion. |
| `schema_migrations` | Version del almacenamiento local. |

Reglas:

- Un unico escritor logico de SQLite.
- `foreign_keys=ON`, `busy_timeout` y transacciones cortas.
- Base y spool en volumen local persistente, nunca dentro de la imagen.
- Checkpoint y outbox se confirman en la misma transaccion.
- Escritura de payload a `*.partial`, `fsync`, rename atomico y registro en outbox.
- Reconciliacion de archivos huerfanos al iniciar.
- Retencion inicial de siete dias para dedup, diagnosticos y entregas terminales; pendientes no se eliminan por antiguedad sin una decision explicita.

## Entrega y tolerancia a fallos

La garantia sera `at-least-once`, no una promesa irreal de `exactly-once` distribuido.

- Cada registro tiene `record_id` determinista.
- Cada lote tiene `delivery_id` determinista.
- El mismo retry conserva `Idempotency-Key` y nombre de objeto.
- Timeout, DNS temporal, `408`, `429` y `5xx` recuperables usan backoff exponencial con jitter.
- Errores de autenticacion o contrato bloquean la configuracion o pasan a dead-letter, no se reintentan infinitamente.
- Cada item tiene `next_attempt_at`; un item malo no bloquea toda la cola.
- La outbox se mide por cantidad y bytes para aplicar backpressure.

## Procesamiento y limites iniciales

Los valores se validaran con las pruebas locales de Fase 0:

| Limite | Inicio propuesto |
| --- | ---: |
| Ciclos de extraccion globales | 2 |
| Ciclos por tenant/fuente | 1 |
| Uploads simultaneos | 1 |
| Paginas en memoria por pipeline | 2 |
| Tamano de pagina | 100 registros, ajustable por fuente |
| Respuesta/pagina normalizada objetivo | 1 a 8 MB |
| Thread pool para SDKs bloqueantes | 4 |

Una cola acotada propaga backpressure. Cuando el spool alcance su limite blando, se pausan extracciones y se prioriza delivery. En el limite duro, el servicio entra en estado degradado y nunca borra pendientes silenciosamente.

## Modelo canonico y estandares

El nucleo usara un modelo propio pequeno. No se forzara STIX como esquema universal porque no modela bien disponibilidad, metricas ni inventario operativo.

- OCSF sera una proyeccion futura recomendada para vulnerability findings, detections, inventario y scan activity.
- CVE, CWE, CPE y CVSS se conservan como identificadores o afirmaciones con fuente y version.
- CVSS no sera el unico criterio de riesgo.
- STIX 2.1 se utilizara solo si se requiere intercambio de inteligencia de amenazas.
- ECS sera una proyeccion opcional si Elastic se convierte en consumidor.

Versiones separadas:

- `schema_version`: contrato canonico.
- `connector_version`: extraccion por proveedor.
- `mapping_version`: fuente a canonico.
- `policy_version`: filtros, dedup y priorizacion.

## Stack recomendado

| Area | Eleccion | Motivo |
| --- | --- | --- |
| Lenguaje | Python 3.13 inicialmente | Madurez y compatibilidad con librerias de proveedores; revisar 3.14 tras pruebas. |
| Packaging | `pyproject.toml`, `src` layout, Hatchling | Imports reproducibles y paquete instalable. |
| Dependencias | `uv` con `uv.lock` | Resolucion rapida y entorno reproducible. |
| Modelos/config | Pydantic 2 y `pydantic-settings` | Validacion estricta y secretos tipados. |
| HTTP | HTTPX | Sync/async, streaming, limites y timeouts separados. |
| Estado | SQLite + SQLAlchemy Core 2 | Transacciones explicitas sin acoplar dominio a ORM. |
| Migraciones | Alembic | Evolucion controlada del estado local. |
| CLI | Click | Comandos estables sin mezclar modelos y CLI. |
| Logs | `structlog` sobre `logging` | JSON estructurado con redaccion central. |
| Metricas/traces | OpenTelemetry | Estandar abierto; telemetria nunca bloquea ETL. |
| Tests | pytest, AnyIO, coverage, HTTPX MockTransport | Unitarios, async, contratos y transporte simulado. |
| Calidad | Ruff y mypy | Formato/lint rapido y tipos en fronteras criticas. |

No se usaran Pandas, Spark o Dask por defecto. El flujo es I/O-bound y debe procesar iteradores o paginas con memoria acotada.

## Configuracion

La configuracion sera una abstraccion, no llamadas dispersas a `os.getenv`.

Inicialmente:

- entorno y archivos de secretos montados por el contenedor;
- un tenant configurado, pero claves de estado y registros siempre incluyen `tenant_id`;
- validacion completa al arranque;
- TLS verificado por defecto y CA privada configurable;
- vista de configuracion redactada, nunca secretos en logs.

Posteriormente, el frontend administrara configuracion mediante una API autenticada y un secret store. El runtime consumira el mismo modelo tipado; no dependera de que la fuente sea `.env`.

## Docker

La imagen sera una unidad de despliegue, no almacenamiento:

- build multi-stage;
- imagen oficial `python:3.13-slim` fijada y actualizada de forma controlada;
- wheel y dependencias bloqueadas en la etapa final;
- usuario no root con UID/GID explicitos;
- `ENTRYPOINT` en forma exec hacia la CLI;
- filesystem raiz read-only;
- solo `/data` y, si hace falta, `/tmp` son escribibles;
- volumen `/data` contiene SQLite y spool;
- healthcheck sin credenciales ni llamadas destructivas;
- una instancia por archivo SQLite.

## Comandos previstos

```text
txdx-etl run
txdx-etl run-once --source uptime-kuma
txdx-etl check-config
txdx-etl check-source --source zabbix
txdx-etl migrate
txdx-etl health
txdx-etl queue status
txdx-etl queue redrive --delivery-id ...
txdx-etl version
```

No se implementara un menu interactivo como interfaz principal. Una CLI no interactiva es automatizable, testeable y apropiada para contenedores. El frontend futuro utilizara una API de administracion separada.

## Estrategia de pruebas

- `unit`: identidad, filtros, validacion, mapping y retry sin I/O.
- `contract`: respuestas anonimizadas de cada API y JSON Schema del destino.
- `integration`: HTTP simulado y SQLite real en archivos temporales.
- `resilience`: crash antes/despues de commit, reinicio, cola llena, 429, timeout y backend caido.
- `container`: usuario no root, filesystem read-only, volumen persistente y apagado ordenado.
- `comparison`: misma entrada V1/V2 para medir ruido, nulos y duplicados.

## Alternativas descartadas por ahora

- Go o Rust: no solucionan por si solos contrato, idempotencia o calidad; aumentan el costo de reescribir clientes de seguridad.
- PostgreSQL: requiere otro servicio; SQLite es adecuado mientras exista un escritor por appliance.
- Kafka/RabbitMQ/Redis: operacion innecesaria para una cola local durable.
- Airflow/Prefect/Dagster: orientados a orquestacion de workflows; este caso es un collector continuo y acotado.
- Microservicio por integracion: aumenta imagenes, configuracion, memoria y coordinacion.
- IA dentro del pipeline: no debe afectar adquisicion ni entrega; sera consumidor opcional posterior.

## Fuentes principales

- Python Packaging, `src` layout: https://packaging.python.org/en/latest/discussions/src-layout-vs-flat-layout/
- Python `asyncio.Queue`: https://docs.python.org/3/library/asyncio-queue.html
- Python `sqlite3`: https://docs.python.org/3/library/sqlite3.html
- SQLite WAL: https://sqlite.org/wal.html
- SQLite UPSERT: https://sqlite.org/lang_upsert.html
- Pydantic Settings: https://docs.pydantic.dev/latest/concepts/pydantic_settings/
- HTTPX async y timeouts: https://www.python-httpx.org/async/ y https://www.python-httpx.org/advanced/timeouts/
- SQLAlchemy 2.0: https://docs.sqlalchemy.org/en/20/
- Alembic: https://alembic.sqlalchemy.org/en/latest/
- OpenTelemetry Python: https://opentelemetry.io/docs/languages/python/
- Docker build best practices: https://docs.docker.com/build/building/best-practices/
- JSON Schema 2020-12: https://json-schema.org/draft/2020-12/release-notes
- OCSF: https://schema.ocsf.io/
- STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
- CVSS v4.0: https://www.first.org/cvss/v4-0/specification-document
