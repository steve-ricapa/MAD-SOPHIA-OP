# Documentacion ETL V2

## Estado general

**En desarrollo.** El contrato canonico de Fase 2 tiene schemas, fixtures, identidad determinista y validacion cross-record implementados y probados. El conector Uptime Kuma fue verificado contra una instancia real 1.23.17 de laboratorio: parsea, mapea y valida el ciclo completo; el runtime ejecuta lectura-deteccion-encolado-envio con reintentos sobre outbox SQLite. Faltan el envio HTTP real al backend, el scheduler y aprobaciones del gate.

El resumen consolidado de avances, pendientes, bloqueos y riesgos se mantiene en `development-status.md`.

| Fase | Documento | Estado |
| --- | --- | --- |
| General | `development-status.md` | **En desarrollo** |
| 0 | `phase-0-charter.md` | Completa |
| 0 | `phase-0-evaluation.md` | Completa |
| 1 | `phase-1-v1-assessment.md` | Completa |
| 1 | `phase-1-target-architecture.md` | Completa |
| 2 | `phase-2-canonical-contract.md` | **En desarrollo; schemas, fixtures, nucleo de dominio y validador creados** |
| 3 | `phase-3-uptime-kuma-research.md` | **En desarrollo** |
| 3 | Investigacion de Zabbix | Pendiente |
| 4 | Diseno operativo y de seguridad | Pendiente |
| 5 | Implementacion y validacion local | Pendiente |

## Trabajo actual

- Contrato canonico `1.0.0` en JSON Schema Draft 2020-12.
- Schemas de envelope, run, asset, observation, finding y detection.
- Fixtures y pruebas automatizadas del contrato inicial.
- Nucleo de dominio iniciado en `src/txdx_etl`: identidad determinista con vectores dorados, validacion cross-record y builder de envelope.
- Parser de `/metrics` con sondeo de capacidades y mapper fuente-canonico para Uptime Kuma, probados offline contra fixtures 1.23.x y 2.x.
- Cliente HTTP `/metrics` con Basic Auth, limite de bytes y errores clasificados, validado contra la instancia real de laboratorio.
- Version desplegada confirmada: Uptime Kuma `1.23.17`; identidad derivada obligatoria y labels `"null"` normalizados.
- Fixture anonimizado con la forma real del laboratorio.
- Motor de cambios entre snapshots: `initial`, `refresh`, `change`, `discovered` y `disappeared`. Los ciclos tranquilos no envian nada; solo eventos al instante mas un latido periodico por monitor (desaparicion confirmada tras varios scrapes sin el monitor).
- Spool durable en SQLite: outbox de envios pendientes con deduplicacion exacta por `record_id` y estado persistente del detector, de modo que un reinicio no pierda ni duplique eventos.
- Ciclo completo ejecutable (`pipeline/runtime.py`): lectura, deteccion, encolado y envio con reintentos de espera creciente; fallos transitorios pausan solo el envio y los permanentes apartan el envelope sin bloquear el resto.
- 126 pruebas automatizadas de schema, identidad, validacion cross-record, parser, mapper, cliente, detector de cambios, outbox, runtime y forma real.
- Comparacion oficial de `/metrics`, API interna, webhook y acceso SQLite de Uptime Kuma.
- Compatibilidad identificada entre Uptime Kuma 1.23.x y 2.x.
- Diseno de sondeo de capacidades porque la version desplegada aun no se conoce.
- Diseno preliminar de identidad, reconciliacion, deduplicacion, seguridad y pruebas.
- Decision provisional: `/metrics` como fuente principal y webhook como complemento opcional.

El expediente completo, incluidos hallazgos, alternativas, riesgos, decisiones y preguntas pendientes, esta en `phase-3-uptime-kuma-research.md`.

## Decisiones actuales

- Monolito modular Python en un contenedor por appliance.
- Layout de paquete `src` y una CLI no interactiva.
- Extraccion paginada o por streaming con concurrencia acotada.
- Modelo canonico que distingue assets, observations, findings y detections.
- SQLite para checkpoints, deduplicacion y outbox; spool de archivos para payloads grandes.
- Entrega `at-least-once` con idempotencia determinista.
- Uptime Kuma y Zabbix como primeros conectores completos.
- Compatibilidad con el backend existente antes de decidir la arquitectura AWS final.
- IA/ML como enriquecimiento downstream opcional y no bloqueante.

## Proximo gate

Antes de implementar el runtime y los conectores debe aprobarse lo ya definido en Fase 2:

- entidades canonicas y campos obligatorios;
- reglas de identidad determinista;
- envelope y versionado de schemas;
- politicas de validacion y valores nulos;
- formato de decisiones de filtrado;
- campos de proveniencia y aislamiento por tenant.

Para Uptime Kuma tambien deben obtenerse la version desplegada, un fixture real anonimizado de `/metrics` y el modo de autenticacion disponible.
