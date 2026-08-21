# Estado de desarrollo ETL V2

## Estado actual

| Campo | Valor |
| --- | --- |
| Estado general | En desarrollo |
| Fase funcional activa | Fase 2: contrato canonico y Fase 3: investigacion Uptime Kuma |
| Proximo gate obligatorio | Aprobar contrato canonico y fixture real de Uptime Kuma |
| Implementacion V2 | Contrato, nucleo de dominio y conector Uptime Kuma offline iniciados; runtime, HTTP y delivery no iniciados |
| Fuentes iniciales | Uptime Kuma y Zabbix |
| Despliegue objetivo | Un contenedor continuo por appliance |
| Recursos objetivo | 4 CPU y 8 GB RAM |

La investigacion de fuentes comenzo antes de cerrar Fase 2 para reducir incertidumbre sobre los datos reales disponibles. Ya existe una primera version ejecutable del contrato, pero el conector definitivo requiere su aprobacion y un fixture real de la fuente.

## Objetivo consolidado

Disenar e implementar una V2 resiliente del ETL para mejorar la adquisicion y el filtrado automatizado de eventos de red y seguridad en TXDXSECURE S.A.C. La primera demostracion integrara Uptime Kuma y Zabbix y dejara un nucleo reutilizable para Nessus, OpenVAS, InsightVM y Wazuh.

La V2 debe resolver los problemas observados en V1:

- integraciones aisladas sin nucleo compartido;
- formatos y semanticas incompatibles;
- snapshots y estados JSON sin transaccion;
- deduplicacion agregada o no determinista;
- delivery, retry y colas duplicados;
- datos operativos tratados como vulnerabilidades;
- posibilidad de secretos o artefactos dentro del repositorio;
- limites de memoria, cola y concurrencia no uniformes;
- errores vacios o parciales dificiles de distinguir de una extraccion valida.

## Trabajo completado

### Fase 0

- Definicion del problema, objetivo y alcance inicial.
- Seleccion de Uptime Kuma y Zabbix para la demostracion.
- Definicion de appliance, multi-tenancy preparada y ejecucion continua.
- Criterios preliminares de exito y plan de evaluacion V1 contra V2.
- Politica inicial de relevancia: critical, high y medium contextual.
- Retencion operativa inicial de siete dias.
- Delimitacion de alcance: sin remediacion, tickets, correlacion avanzada ni IA bloqueante.

### Fase 1

- Auditoria estructural y funcional de V1.
- Matriz para reutilizar, adaptar o reemplazar componentes.
- Decision de monolito modular Python en un contenedor.
- Separacion propuesta entre dominio, puertos, conectores, pipeline, infraestructura y runtime.
- Seleccion de SQLite para estado transaccional y outbox.
- Seleccion de spool de archivos para payloads grandes.
- Garantia realista `at-least-once` con idempotencia determinista.
- Estrategias de extraccion diferenciadas por tipo de fuente.
- Stack, estructura de repositorio, CLI, Docker, observabilidad y pruebas propuestos.

### Fase 2

- Documento inicial del contrato canonico `1.0.0`.
- JSON Schema Draft 2020-12 para envelope, run y definiciones comunes.
- Entidades separadas para asset, observation, finding y detection.
- Identidad determinista propuesta para assets, registros y entregas.
- Proveniencia, decision de filtrado y politica de nulos definidas.
- Credenciales excluidas del payload de negocio.
- Proyeccion de compatibilidad V1 separada del dominio canonico.
- Fixtures anonimizados de observation, finding y detection.
- Siete pruebas automatizadas de schema ejecutadas correctamente.
- Funciones deterministas `asset_id`, `record_id`, `delivery_id` y `raw_record_hash` en `src/txdx_etl/domain/identity.py`.
- Serializacion canonica especificada e implementada: objeto JSON, claves ordenadas, sin espacios, UTF-8, omision de valores ausentes.
- Validador cross-record del envelope en `src/txdx_etl/pipeline/validation.py`: referencias asset-registro, IDs unicos, conteos del run, frontera solo-accepted, coherencia del `delivery_id` y orden temporal.
- Fixture de Uptime Kuma auto-consistente generado con la implementacion real de identidad.
- 32 pruebas automatizadas (schemas, identidad con vectores dorados y validacion cross-record) ejecutandose correctamente.

### Implementacion temprana del nucleo

Se inicio la implementacion antes de cerrar las fases de diseno, siguiendo el patron ya usado con la investigacion de fuentes:

- Builder de envelope en `src/txdx_etl/pipeline/envelope.py` que calcula conteos del run y `delivery_id`.
- Parser de exposicion Prometheus en `connectors/uptime_kuma/parser.py`: agrupacion por monitor, fusion de labels sin arrastrar `window`, escapes de Prometheus, sondeo de capacidades (`monitor_id`, familias, ventanas) y rechazo estricto de estados o familias desconocidas.
- Mapper fuente-canonico en `connectors/uptime_kuma/mapper.py`: asset nativo o derivado, observation de disponibilidad y de certificado, buckets de refresh de 300 segundos, omision de latencias negativas y decisiones aceptadas con codigos estables.
- Fixtures de `/metrics` estilo 2.x (con `monitor_id`, metricas agregadas y ruido de proceso) y estilo 1.23.x (identidad derivada).
- Ciclo completo probado offline: parse, map, build envelope, validacion JSON Schema y validacion cross-record sin violaciones.
- Cliente HTTP `/metrics` en `connectors/uptime_kuma/client.py` sobre HTTPX: Basic Auth con la API key completa como contrasena y usuario vacio, modo credenciales y anonimo solo explicito, TLS verificado por defecto, streaming con limite de bytes, `follow_redirects` desactivado y clasificacion de errores (401/403 bloqueante, 429 recuperable con `Retry-After`, 5xx/408/transporte recuperables, resto contrato).
- Vista de configuracion redactada que nunca expone secretos.
- 79 pruebas automatizadas ejecutandose correctamente.

### Higiene del repositorio

Se limpiaron localmente artefactos que no deben formar parte del codigo fuente:

- payloads y reportes generados;
- estados JSON y bases de estado;
- logs y archivos lock;
- bytecode `__pycache__` y `.pyc`;
- exports CSV/JSON y snapshots;
- tarballs y diagnosticos temporales;
- datos de runtime de las integraciones.

Tambien se eliminaron tres scripts legacy de la raiz:

- `fetch_openvas.py`
- `fetch_uptime_kuma.py`
- `fetch_zabbix.py`

`.gitignore` fue ampliado para bloquear runtime, estados, colas, payloads, snapshots, locks, bases locales y otros artefactos generados. Se verifico que no quedaran referencias activas a los scripts legacy ni artefactos `.pyc`, `.lock`, `.db` o `.tar.gz` en el arbol de trabajo esperado.

### Investigacion de estrategias por fuente

Estrategias preliminares definidas:

| Fuente | Estrategia |
| --- | --- |
| Uptime Kuma | Snapshot `/metrics`, comparacion de estados y webhook opcional |
| Zabbix | Extraccion incremental por `eventid` y frontera temporal |
| Nessus | Export job asincrono |
| OpenVAS | Reportes completados y XML streaming |
| InsightVM | Paginacion `page/size` |
| Wazuh / OpenSearch | PIT y `search_after` |

No se impondra paginacion universal. Cada conector implementara la estrategia soportada por su fuente, manteniendo memoria y concurrencia acotadas.

### Investigacion Uptime Kuma

Se revisaron documentacion y codigo oficial para `/metrics`, autenticacion, API interna, webhooks y SQLite. Las conclusiones completas estan en `phase-3-uptime-kuma-research.md`.

Decisiones actuales:

- `/metrics` sera la fuente principal de snapshot y reconciliacion.
- webhook sera opcional para reducir latencia, nunca la unica fuente.
- Socket.io interno no se usara inicialmente por falta de estabilidad contractual.
- SQLite de Uptime Kuma solo podra utilizarse como enriquecimiento opcional de solo lectura.
- el conector detectara capacidades porque la version desplegada aun se desconoce;
- Uptime Kuma 1.23.x requiere identidad derivada porque no expone `monitor_id`;
- Uptime Kuma 2.x permite identidad nativa por `monitor_id`;
- disponibilidad se normalizara como `Observation`, no como vulnerability finding.

Verificacion con instancia real de laboratorio (2026-08-21):

- Version confirmada `1.23.17` mediante la metrica `app_version`; perfil 1.x sin `monitor_id`.
- Autenticacion confirmada: usuario/contrasena via Basic Auth; API Keys deshabilitadas.
- Escala observada: 10 monitores (http x4, keyword x1, dns x1, port x1, ping x2, push x1), 28 series, 9 up y 1 down.
- Hallazgo nuevo: labels ausentes llegan como literal `"null"`; el parser los normaliza a ausencia antes de identidad y mapping, con pruebas de regresion.
- Cliente HTTP validado en vivo: credencial incorrecta produce error bloqueante clasificado; credenciales validas producen snapshot parsable en ~130 ms.
- Fixture anonimizado con forma real agregado; 105 pruebas automatizadas ejecutandose correctamente.
- Motor de cambios implementado (`connectors/uptime_kuma/detector.py`): clasifica monitores como `initial`, `refresh`, `change`, `discovered` o `disappeared`; la desaparicion se confirma solo tras varios scrapes exitosos consecutivos sin el monitor (umbral configurable, 3 por defecto). Los ciclos sin cambios no emiten registros; el latido periodico sale una vez por ventana configurable (300 s por defecto) y un cambio de validez de certificado se emite de inmediato aunque el estado no varie.

## Arquitectura acordada

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

Reglas centrales:

- normalizar antes de filtrar para conservar los hechos fuente;
- registrar toda decision de filtrado con razon y version;
- hacer durable el dato antes de avanzar el checkpoint;
- conservar IDs de tenant y fuente en estado, cola, registros y logs;
- no mezclar metadata de una integracion dentro de otra;
- usar registros separados para una correlacion futura;
- pausar extraccion ante backpressure en lugar de borrar pendientes;
- no usar Kafka, Spark, Airflow, Celery, Redis ni microservicios en la primera version.

## Trabajo pendiente por fase

### Fase 2: contrato canonico

- Revisar y aprobar los schemas iniciales con los consumidores.
- Confirmar el schema real del backend y la proyeccion de compatibilidad.
- Cerrar reglas de aislamiento por tenant en almacenamiento y delivery.
- Definir politicas concretas de filtrado por fuente sobre el contrato.

### Fase 3: fuentes

- Obtener version y fixture real anonimizado de Uptime Kuma.
- Confirmar autenticacion disponible y escala de monitores.
- Investigar oficialmente Zabbix con el mismo nivel de detalle.
- Convertir hallazgos de fuentes en fixtures y pruebas de contrato.

### Fase 4: seguridad y operacion

- Cerrar modelo de secretos y permisos locales.
- Definir cuotas de disco, limites blandos y duros y alertas.
- Definir recovery objectives y latencia aceptable.
- Cerrar politica de redaccion de URLs, hostnames y evidencia.
- Definir health, readiness, metricas y runbooks.
- Corregir y endurecer Docker para usuario no root y filesystem read-only.

### Fase 5: implementacion

- Completar paquete `src/txdx_etl` con configuracion reproducible y dependencias bloqueadas.
- Implementar dominio restante, puertos, migraciones, estado y outbox.
- Implementar delivery compartido y spool durable.
- Implementar Uptime Kuma y luego Zabbix.
- Ejecutar pruebas unitarias, contrato, integracion, resiliencia y contenedor.
- Comparar entradas equivalentes V1/V2 y medir resultados de tesis.

## Bloqueos y limitaciones conocidas

- `pytest` no esta instalado en el entorno actual; los tests nuevos usan `unittest`.
- Las pruebas Wazuh requieren dependencias ausentes como `loguru`, `python-dotenv` y `aiohttp`.
- Docker no esta instalado en el equipo actual, por lo que no se pueden validar imagen ni contenedor localmente.
- El `Dockerfile` actual referencia `app.py`, que no existe, y continua roto hasta la fase de implementacion.
- Los cambios de limpieza y la documentacion V2 aun no tienen commit.

Estas limitaciones no bloquean la documentacion ni el diseno, pero si parte de la validacion ejecutable.

## Riesgos abiertos

### Secretos historicos

Eliminar payloads del arbol actual no elimina secretos del historial Git. Toda credencial que haya sido versionada debe considerarse expuesta, rotarse y, si se requiere eliminarla del historial, tratarse mediante un procedimiento separado y coordinado.

### Contrato del backend

La V2 debe mantener compatibilidad suficiente con el backend existente durante la demostracion. La arquitectura AWS final no esta decidida y no debe acoplar el dominio a URLs prefirmadas o detalles de S3.

### Escala y recursos

Los limites propuestos son iniciales. Cantidad de monitores, eventos diarios, latencia de fuentes, cuota de disco y disponibilidad de red deben medirse antes de afirmar capacidad del appliance.

### Filtrado

La politica critical/high/medium contextual necesita reglas concretas por fuente. Para Uptime Kuma aun deben definirse criticidad del activo, persistencia de `PENDING`, mantenimiento, recuperaciones y umbrales de certificado.

### Credenciales de laboratorio y tokens push

El acceso al laboratorio usa una contrasena compartida por chat y transporte HTTP plano dentro de la LAN; debe rotarse al cerrar la demostracion. Los monitores tipo `push` colocan su token en `monitor_url`, por lo que la redaccion de URLs es requisito antes de tratar ese tipo como activo observable.

## Siguiente movimiento recomendado

1. Revisar y aprobar el contrato canonico, su implementacion de identidad y el validador cross-record.
2. Aprobar redaccion de URLs (tokens push), frecuencia y politica de desaparicion de Uptime Kuma.
3. Continuar con deduplicacion exacta, spool durable y outbox SQLite.
4. Definir reglas de filtrado concretas para Uptime Kuma sobre el contrato aprobado.

## Regla para actualizar este registro

Actualizar este documento cuando:

- una fase cambie de estado;
- una decision provisional se confirme o descarte;
- aparezca o se resuelva un bloqueo;
- se complete una prueba o medicion relevante;
- cambie el alcance de la demostracion;
- comience la implementacion de codigo V2.
