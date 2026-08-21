# Fase 3: Investigacion y diseno del conector Uptime Kuma

## Estado de la fase

| Campo | Valor |
| --- | --- |
| Estado | En desarrollo |
| Inicio documentado | 2026-08-21 |
| Fuente inicial | Uptime Kuma |
| Version desplegada | Aun no identificada |
| Alcance actual | Investigacion de extraccion, autenticacion, metadata, compatibilidad y recuperacion |
| Implementacion V2 | No iniciada; depende del contrato canonico de Fase 2 |

Este documento consolida el trabajo realizado y las decisiones pensadas hasta el momento. Las secciones marcadas como propuestas deben validarse durante las fases de contrato, implementacion y pruebas. No representan todavia un contrato de produccion cerrado.

## Relacion con las fases anteriores

La Fase 0 definio el objetivo, alcance y evaluacion de la tesis. La Fase 1 evaluo V1 y selecciono una arquitectura de monolito modular. Este trabajo de Fase 3 aplica esas decisiones al primer conector completo.

Decisiones heredadas:

- Uptime Kuma y Zabbix son las primeras fuentes de demostracion.
- Uptime Kuma produce principalmente observaciones de disponibilidad, no vulnerabilidades.
- El ETL se ejecutara continuamente en un contenedor sobre un appliance de 4 CPU y 8 GB RAM.
- La extraccion y el procesamiento deben tener memoria, concurrencia, respuesta y cola acotadas.
- SQLite almacenara checkpoints, deduplicacion y outbox; los payloads grandes iran a un spool de archivos.
- La entrega sera `at-least-once` con identidad e idempotencia deterministas.
- La configuracion inicial tendra un tenant, pero todo estado e identidad incluira `tenant_id`.
- La retencion operativa inicial sera de siete dias.
- IA, tickets, remediacion y correlacion avanzada entre fuentes no forman parte de esta implementacion inicial.

Documentos relacionados:

- `phase-0-charter.md`
- `phase-0-evaluation.md`
- `phase-1-v1-assessment.md`
- `phase-1-target-architecture.md`

## Objetivo de esta investigacion

Determinar como adquirir de Uptime Kuma datos confiables y suficientes para:

- conocer el estado actual de cada monitor;
- detectar cambios de estado sin generar duplicados;
- conservar metadata util del activo o servicio observado;
- operar ante reinicios, fallos de red y entregas repetidas;
- evitar acoplar V2 a interfaces internas inestables;
- soportar de forma controlada las diferencias entre Uptime Kuma 1.x y 2.x.

## Material revisado

### Implementacion V1 local

- `uptimekuma_integration/collector.py`
- `uptimekuma_integration/config.py`
- `uptimekuma_integration/agent.py`
- `uptimekuma_integration/snapshot.py`
- `uptimekuma_integration/README.md`
- `uptimekuma_integration/tests/test_parser.py`

### Documentacion y codigo oficial

- Wiki `Prometheus Integration`.
- Wiki `Prometheus API Keys`.
- Wiki `Internal API`.
- Wiki `Notification Methods`.
- `server/prometheus.js` de las ramas 1.23.x, 2.0.0 y `master`.
- `server/server.js` para confirmar la ruta `/metrics`.
- `server/auth.js` para confirmar autenticacion y rate limiting.
- `server/notification-providers/webhook.js` para revisar el payload HTTP.
- `server/notification.js` y `server/model/monitor.js` para revisar activacion y errores de notificaciones.
- `server/routers/api-router.js` para separar rutas publicas e internas.

La revision de `master` observada corresponde a Uptime Kuma 2.5.0. No debe asumirse que la instalacion del cliente utiliza esa version.

## Resultado principal

La estrategia recomendada es hibrida:

| Mecanismo | Rol propuesto | Decision actual |
| --- | --- | --- |
| `/metrics` | Snapshot completo y reconciliacion periodica | Fuente principal |
| Webhook de notificaciones | Aviso de transiciones con menor latencia | Complemento opcional |
| Socket.io interno | Eventos y administracion en tiempo real | No usar en V2 inicial |
| SQLite de Uptime Kuma | Enriquecimiento o diagnostico local | Opcional y solo lectura |
| Status pages y badges | Datos publicos parciales | No usar como fuente principal |

`/metrics` es la interfaz documentada mas estable y no requiere modificar Uptime Kuma. Sin embargo, representa el estado visible al momento del scrape y puede perder una transicion corta ocurrida completamente entre dos consultas. El webhook puede reducir esa ventana, pero no sustituye la reconciliacion porque Uptime Kuma no implementa una cola durable de notificaciones.

## Contrato observado de `/metrics`

La ruta es:

```text
GET /metrics
```

La respuesta usa el formato de exposicion de Prometheus. No esta paginada: cada solicitud devuelve el snapshot disponible completo. Tambien puede incluir metricas internas del proceso y de Express que el conector debe ignorar mediante una allowlist.

### Labels comunes en Uptime Kuma 2.5

| Label | Uso |
| --- | --- |
| `monitor_id` | Identificador interno del monitor; disponible en 2.x |
| `monitor_name` | Nombre amigable |
| `monitor_type` | Tipo de monitor |
| `monitor_url` | URL configurada, cuando aplica |
| `monitor_hostname` | Host configurado, cuando aplica |
| `monitor_port` | Puerto configurado, cuando aplica |
| labels derivados de tags | Contexto adicional sanitizado por Uptime Kuma |
| `window` | Ventana de una metrica agregada |

Los nombres y valores de tags se sanitizan para Prometheus. Tags creados despues de iniciar Uptime Kuma pueden requerir reiniciar Uptime Kuma para que aparezcan como nuevos labels. Dos nombres diferentes pueden colisionar despues de la sanitizacion; por ello, estos labels no deben utilizarse como identidad primaria.

### Metricas observadas en Uptime Kuma 2.5

| Metrica | Unidad o dominio | Observacion |
| --- | --- | --- |
| `monitor_status` | `0`, `1`, `2`, `3` | Estado actual |
| `monitor_response_time` | milisegundos | Ultima latencia; puede ser `-1` si no existe valor numerico |
| `monitor_uptime_ratio` | `0.0` a `1.0` | Uptime agregado por `window` |
| `monitor_response_time_seconds` | segundos | Latencia promedio por `window` |
| `monitor_cert_days_remaining` | dias | Solo cuando existe informacion TLS |
| `monitor_cert_is_valid` | `0` o `1` | Validez de certificado |

Ventanas observadas para metricas agregadas:

- `1d`
- `30d`
- `365d`

Semantica de `monitor_status`:

| Valor | Estado fuente |
| ---: | --- |
| 0 | DOWN |
| 1 | UP |
| 2 | PENDING |
| 3 | MAINTENANCE |

### Limitaciones del snapshot

- No incluye un cursor ni identificador de heartbeat.
- No incluye el mensaje original del heartbeat.
- No incluye necesariamente la hora fuente del ultimo cambio.
- Una transicion detectada comparando snapshots es inferida por V2.
- `observed_at` sera la hora de adquisicion del ETL; no debe presentarse como hora exacta del evento fuente.
- Una caida y recuperacion completas entre dos scrapes pueden no observarse.
- El endpoint no ofrece paginacion; la proteccion debe realizarse con limites de bytes, series y monitores.
- En 1.23.17 los labels ausentes se exponen con el literal `"null"` (`monitor_hostname`, `monitor_port`, `monitor_url`); el parser debe normalizarlos a ausencia antes de identidad y mapping.

## Verificacion en laboratorio (2026-08-21)

Se levanto una instancia real de Uptime Kuma en un equipo de laboratorio accesible por la red interna (`http://172.31.251.113:3001`, HTTP plano dentro de la LAN).

Resultados confirmados:

| Aspecto | Resultado |
| --- | --- |
| Version exacta | `1.23.17` (metrica `app_version`) |
| Autenticacion `/metrics` | usuario/contrasena via Basic Auth; API Keys deshabilitadas |
| Sin credenciales | `401` con `WWW-Authenticate: Basic` |
| Raiz del servidor | `302` (redireccion al dashboard) |
| Content-Type | `text/plain; version=0.0.4; charset=utf-8` |
| `monitor_id` | Ausente; identidad derivada obligatoria |
| Familias presentes | solo base: status, response_time, cert_days_remaining, cert_is_valid |
| Metricas agregadas | Ausentes; sin ventanas `1d/30d/365d` |
| Escala | 10 monitores, 28 series |
| Tipos | http x4, keyword x1, dns x1, port x1, ping x2, push x1 |
| Estados observados | up x9, down x1 (push) |

Hallazgos adicionales:

- Labels vacios llegan como literal `"null"`: hostname 6/10, port 8/10, url 5/10. El parser normaliza a ausencia y hay pruebas de regresion.
- Los monitores tipo `ping` reportan latencia decimal (`98.1` ms).
- El tipo `push` reporta latencia `-1` y estaba en estado down; valida la politica de omision.
- La metrica `app_version` permite detectar version sin API adicional.
- Cliente V2 validado en vivo: contrasena incorrecta produce error bloqueante clasificado; credenciales validas producen snapshot parsable en ~130 ms.
- Fixture anonimizado con la forma real agregado en `tests/fixtures/connectors/uptime_kuma/metrics-real-1.23.17-anonymized.txt`.

Riesgo elevado confirmado: si se configuran monitores `push`, su token vive en `monitor_url`; la redaccion de URLs deja de ser teorica y es requisito antes de habilitar ese tipo.

## Compatibilidad entre versiones

El entorno de laboratorio confirmo el perfil 1.23.x descrito abajo. El sondeo de capacidades se conserva para entornos futuros que puedan estar en 2.x.

| Version revisada | `monitor_id` | Metricas base | Metricas agregadas y tags |
| --- | --- | --- | --- |
| 1.23.x | No | Estado, respuesta y certificado | No observadas en el archivo revisado |
| 2.0.0 | Si | Estado, respuesta y certificado | No observadas en el archivo revisado |
| 2.5.0 / `master` revisado | Si | Estado, respuesta y certificado | Uptime, respuesta promedio y tags |

### Sondeo de capacidades propuesto

El primer scrape valido debe construir un perfil de capacidades:

- presencia de `monitor_id`;
- familias de metricas disponibles;
- ventanas agregadas disponibles;
- labels base y labels adicionales;
- modo de autenticacion exitoso;
- cantidad y tamano aproximado del snapshot.

El perfil se almacenara con la configuracion efectiva redactada y se comparara en ciclos posteriores. Un cambio incompatible de contrato debe degradar el conector y producir un diagnostico; no debe interpretarse como un snapshot vacio valido.

## Autenticacion

### API key

Las API keys para Prometheus estan disponibles desde Uptime Kuma 1.21.0. Se envian mediante HTTP Basic Auth:

```text
username: vacio o cualquier valor; Uptime Kuma lo ignora
password: API key completa
```

Cuando API Keys se habilita, el endpoint deja de aceptar las credenciales normales del usuario. La clave debe tratarse como contrasena aunque solo permita acceder a metricas potencialmente sensibles.

### Usuario y contrasena

Si API Keys no esta habilitado y la autenticacion general esta activa, `/metrics` utiliza usuario y contrasena de Uptime Kuma mediante Basic Auth.

### Autenticacion deshabilitada

Si Uptime Kuma tiene autenticacion deshabilitada, `/metrics` puede ser publico. V2 solo admitira este modo cuando se configure de forma explicita para evitar ocultar una configuracion insegura.

### Rate limiting

El codigo 2.5 revisado aplica rate limiting a intentos con API key y documenta internamente un limite actual de 60 solicitudes por minuto. La frecuencia propuesta de 30 segundos queda muy por debajo, pero V2 tratara `429` como error recuperable y respetara `Retry-After` cuando exista.

### Correccion necesaria respecto de V1

V1 exige conjuntamente `UPTIME_KUMA_API_KEY_ID` y `UPTIME_KUMA_API_KEY`. El ID separado no es necesario para autenticar `/metrics`: forma parte de la clave completa y el username se ignora. V2 debe exponer una unica propiedad secreta para la API key y evitar instrucciones confusas.

## Evaluacion del webhook

El proveedor webhook envia normalmente un objeto con esta forma:

```json
{
  "heartbeat": {},
  "monitor": {},
  "msg": ""
}
```

Tambien admite `GET`, `form-data`, cuerpo personalizado y headers adicionales. Para V2 solo se consideraria `POST` JSON con HTTPS y un header de autenticacion.

Ventajas:

- incluye heartbeat y mensaje;
- incluye la hora registrada por Uptime Kuma;
- reduce la latencia frente al polling;
- informa transiciones importantes y recuperaciones segun las reglas de notificacion.

Limitaciones confirmadas:

- no existe outbox durable para webhooks;
- los errores se capturan y registran, pero no se observa retry durable automatico;
- los proveedores se invocan secuencialmente;
- no existe firma criptografica nativa del payload;
- no existe identificador idempotente nativo;
- el primer estado saludable puede no generar notificacion;
- mantenimiento, reenvios y configuracion por monitor afectan que mensajes se emiten;
- un webhook mal configurado o no asociado a un monitor no entrega datos;
- una respuesta decodificada guardada en el heartbeat podria contener evidencia sensible y debe filtrarse.

Decision: el webhook sera una mejora opcional de baja latencia. El receptor solo respondera `2xx` despues de hacer durable el evento. `/metrics` continuara siendo obligatorio para reconciliar eventos perdidos, estado inicial, monitores nuevos y cambios durante indisponibilidad del receptor.

## Evaluacion de la API interna

La documentacion oficial advierte que la API interna:

- esta disenada para la aplicacion web;
- no esta soportada oficialmente para integraciones de terceros;
- puede cambiar entre versiones sin aviso;
- utiliza principalmente Socket.io despues del login;
- requiere manejar sesion, callbacks, eventos y potencialmente 2FA.

Aunque Socket.io puede entregar `heartbeat`, `monitorList`, `uptime`, `avgPing` y `certInfo`, su costo de compatibilidad y riesgo de ruptura son mayores. No se utilizara en la primera implementacion V2. Solo se reconsiderara si las pruebas demuestran que `/metrics` mas webhook no cumple una necesidad de negocio medible.

## Evaluacion de SQLite de Uptime Kuma

V1 puede consultar directamente tablas como `monitor`, `heartbeat`, `monitor_tag`, `monitor_tls_info`, `stat_hourly` y `stat_daily`.

Ventajas:

- aporta mensajes, timestamps, configuracion, tags y heartbeats recientes;
- permite recuperar historia que `/metrics` no expone;
- puede mejorar diagnosticos locales.

Riesgos:

- acoplamiento al esquema interno y a migraciones de Uptime Kuma;
- necesidad de montar el volumen de otra aplicacion;
- diferencias entre SQLite, MariaDB y versiones futuras;
- concurrencia con la aplicacion propietaria de la base;
- mayor impacto de permisos y aislamiento del contenedor;
- posibilidad de exponer configuracion o datos sensibles.

Decision: no sera la fuente principal ni un requisito de despliegue. Si se habilita, se usara una conexion SQLite URI con `mode=ro`, `busy_timeout`, consultas breves, allowlist de columnas y adaptador por version. No se usara `immutable=1` sobre una base activa y nunca se escribira en la base de Uptime Kuma.

## Diseno de extraccion propuesto

### Frecuencia inicial

| Parametro | Valor inicial propuesto |
| --- | ---: |
| Intervalo de scrape | 30 segundos |
| Timeout total | 15 segundos |
| Refresh sin cambios | 5 minutos |
| Confirmacion de monitor ausente | 3 scrapes exitosos |
| Ciclos simultaneos por tenant y fuente | 1 |

Los valores son configurables y deben medirse localmente. El scheduler evitara solapamientos: si un ciclo continua activo, no se iniciara otro para el mismo `(tenant_id, source_instance_id)`.

### Limites

El cliente aplicara:

- limite de bytes de respuesta;
- limite de lineas o series;
- limite de monitores;
- timeout de conexion, lectura, escritura y pool;
- allowlist de familias de metricas;
- longitud maxima por label;
- cola acotada entre extraccion y normalizacion.

Una respuesta que exceda un limite sera un fallo de extraccion, no un snapshot parcial valido. No se avanzara el checkpoint ni se declararan monitores eliminados.

### Parser

El parser V1 contiene conocimiento reutilizable, pero requiere adaptacion:

- debe aceptar contratos 1.x sin `monitor_id`;
- debe manejar de forma segura escapes y valores validos del formato Prometheus;
- debe rechazar duplicados contradictorios para la misma serie;
- debe ignorar metricas ajenas mediante allowlist;
- debe distinguir metrica ausente de valor cero;
- debe controlar `NaN`, infinitos, timestamps opcionales y lineas desconocidas;
- debe producir errores tipados y contadores, no omitir silenciosamente todos los datos invalidos.

Se evaluara usar el parser oficial de `prometheus_client` sobre una respuesta previamente acotada. Si se conserva un parser propio, se construiran pruebas de contrato equivalentes antes de usarlo en produccion.

## Identidad del monitor

### Uptime Kuma 2.x

Identidad recomendada:

```text
tenant_id + source_instance_id + monitor_id
```

`source_instance_id` representa una instalacion configurada de Uptime Kuma y evita colisiones cuando dos instancias usan el mismo ID numerico.

### Uptime Kuma 1.x

Al no existir `monitor_id` en `/metrics`, se propone una clave fuente sintetica mediante hash determinista de:

```text
monitor_type + monitor_url + monitor_hostname + monitor_port + monitor_name
```

Consecuencia conocida: renombrar un monitor o cambiar su destino puede verse como desaparicion del registro anterior y aparicion de uno nuevo. Esta limitacion debe quedar visible en `identity_quality=derived` y en la documentacion operativa.

No se usaran tags como identidad porque se sanitizan, pueden colisionar y pueden cambiar sin representar un monitor nuevo.

## Estado y deteccion de cambios

Por cada monitor se conservara de forma durable:

- identidad fuente y calidad de identidad;
- ultimo estado observado;
- primer y ultimo `observed_at`;
- ultimo hash de campos relevantes;
- numero de scrapes exitosos en los que estuvo ausente;
- ultima fecha de refresh emitido;
- capacidades de metricas observadas;
- identidad del ultimo registro emitido.

Se emitira una observacion cuando ocurra uno de estos casos:

- primer descubrimiento del monitor;
- cambio de estado;
- cambio relevante de certificado;
- cambio de metadata que afecte identidad o contexto;
- refresh periodico configurable;
- desaparicion confirmada despues de varios scrapes exitosos.

Reglas importantes:

- un scrape fallido no incrementa ausencias;
- un snapshot vacio inesperado no se acepta automaticamente como exito;
- `PENDING` y `MAINTENANCE` se conservan como estados distintos;
- la ausencia de una metrica opcional no se convierte en cero;
- el checkpoint solo avanza cuando registros y outbox son durables.

## Normalizacion canonica provisional

La forma definitiva depende de la Fase 2. La propuesta actual es mapear cada estado a `Observation`.

| Campo canonico propuesto | Origen o calculo |
| --- | --- |
| `tenant_id` | Configuracion validada |
| `source` | `uptime_kuma` |
| `source_instance_id` | Configuracion de la instancia |
| `source_monitor_id` | `monitor_id` o clave sintetica |
| `record_id` | Hash determinista del tipo de observacion y hechos fuente |
| `asset_id` | Resolver posterior basado en target y contexto |
| `observation_type` | disponibilidad, latencia, uptime o certificado |
| `status` | Mapeo sin perdida de `UP`, `DOWN`, `PENDING`, `MAINTENANCE` |
| `observed_at` | Hora UTC del scrape |
| `source_event_time` | Nulo para snapshot; disponible si viene de webhook |
| `response_time_ms` | `monitor_response_time` |
| `uptime_ratio` | Valor y ventana de `monitor_uptime_ratio` |
| `certificate` | Validez y dias restantes cuando existan |
| `target` | URL, hostname y puerto saneados |
| `provenance` | Versiones de schema, conector, mapping y politica |

No se enviara Uptime Kuma como `vuln_scan_report`. La salida no se mezclara con metadata de Zabbix ni con findings de scanners. Una futura correlacion utilizara `tenant_id`, `asset_id`, `record_id` y tiempos canonicos para relacionar registros separados.

## Identidad de registros e idempotencia

El snapshot completo no sera la unidad primaria de deduplicacion. Cada observacion tendra una identidad determinista.

Ejemplos conceptuales:

```text
estado inferido:
hash(tenant + instancia + monitor + tipo + estado + observed_window)

webhook:
hash(tenant + instancia + monitor + tipo + estado + source_event_time)

refresh:
hash(tenant + instancia + monitor + tipo + estado + refresh_bucket)
```

La definicion exacta de ventanas y buckets se cerrara en Fase 2. El mismo retry conservara `record_id`, `delivery_id`, nombre de objeto e `Idempotency-Key`.

## Filtrado y severidad provisional

El filtrado debe conservar primero los hechos fuente y aplicar despues una politica versionada. Propuesta inicial sujeta a validacion:

| Condicion | Tratamiento inicial |
| --- | --- |
| Transicion a `DOWN` en activo critico o expuesto | Aceptar con prioridad alta |
| Transicion a `DOWN` sin contexto critico | Aceptar; severidad contextual por definir |
| `PENDING` persistente o repetido | Aceptar como media contextual |
| `MAINTENANCE` | Conservar como estado; no alertar por defecto |
| Recuperacion `DOWN` a `UP` | Aceptar para cerrar el estado operativo |
| Estado `UP` sin cambios | Agregar o emitir solo por refresh |
| Certificado invalido o proximo a vencer | Aceptar segun umbral versionado |
| Metricas informativas sin cambio | Agregar o descartar con razon auditable |

Cada decision producira `accepted`, `rejected` o `quarantined`, codigo de razon y `policy_version`. La criticidad del activo no se inferira unicamente del nombre o URL; provendra de configuracion, tags confiables o inventario canonico.

## Seguridad y privacidad

- TLS se verifica por defecto; una CA privada sera configurable.
- API keys, usuarios y contrasenas nunca se incluiran en registros, logs, spool o diagnosticos.
- `monitor_url` puede contener usuario, contrasena, query parameters o tokens y debe pasar por redaccion.
- Se conservaran esquema, host y puerto cuando sean necesarios; query y fragment se eliminaran por defecto.
- Los labels derivados de tags tendran allowlist, longitud maxima y redaccion.
- El webhook opcional usara HTTPS, secreto en header, limite de cuerpo y comparacion segura del secreto.
- El receptor no confiara en IP origen como unico mecanismo de autenticacion.
- Los logs utilizaran IDs, resultados, duraciones y contadores en lugar de targets completos.
- El acceso SQLite opcional tendra permisos de solo lectura y no ampliara automaticamente el payload.

## Errores y recuperacion

| Situacion | Clasificacion propuesta | Accion |
| --- | --- | --- |
| DNS, conexion, timeout, `408`, `429`, `5xx` | Recuperable | Backoff exponencial con jitter |
| `401`, `403` | Configuracion bloqueada | No reintentar indefinidamente; health degradado |
| Respuesta demasiado grande | Limite operativo | Fallar ciclo sin checkpoint |
| Formato Prometheus invalido | Contrato o dato | Fallar o poner series puntuales en cuarentena segun alcance |
| No existe `monitor_status` | Contrato incompatible | Fallar ciclo; no aceptar vacio |
| Snapshot vacio inesperado | Ambiguo | No confirmar eliminaciones |
| Backend no disponible | Entrega recuperable | Conservar outbox y aplicar backpressure |
| Payload permanentemente invalido | Permanente | Dead-letter con razon redactada |

## Observabilidad del conector

Metricas minimas propuestas:

- duracion y resultado de scrape;
- bytes y series recibidas;
- monitores descubiertos, presentes y ausentes;
- transiciones por estado;
- series ignoradas, invalidas y en cuarentena;
- modo de identidad `native` o `derived`;
- edad del ultimo scrape exitoso;
- errores por clase y codigo HTTP;
- profundidad y bytes de outbox;
- retraso hasta entrega y cantidad de retries;
- eventos webhook recibidos, duplicados y reconciliados.

El healthcheck local no consultara Uptime Kuma en cada invocacion. Readiness dependera de configuracion valida, almacenamiento disponible y ausencia de bloqueos permanentes; la antiguedad del ultimo exito determinara estado saludable o degradado.

## Diferencias detectadas en V1

| Comportamiento V1 | Cambio requerido en V2 |
| --- | --- |
| Parser exige `monitor_id` | Detectar capacidades y soportar 1.x de forma explicita |
| API key requiere un ID separado | Usar la API key completa como unico secreto |
| Snapshot firma solo estados agregados | Deduplicar observaciones individuales |
| Estado guardado en JSON | Usar transaccion SQLite con outbox y checkpoint |
| Se presenta como agente en tiempo real | Documentar que polling es snapshot periodico |
| Disponibilidad se transforma en findings/reporte de vulnerabilidad | Mapear a `Observation` |
| Respuesta completa se carga como texto | Acotar bytes y series antes de procesar |
| Lineas no reconocidas se omiten silenciosamente | Medir y clasificar errores de parsing |
| Enriquecimiento abre la base local directamente | Hacerlo opcional, solo lectura y versionado |
| URL y labels pasan al modelo sin politica central | Redactar y aplicar allowlist |
| Estado se actualiza alrededor de una entrega propia | Confirmar datos, outbox y checkpoint atomicamente |

Las pruebas V1 del parser son una base de regresion, pero actualmente representan principalmente el formato 2.x y no cubren autenticacion, limites, 1.23.x, desapariciones o cambios de contrato.

## Plan de implementacion

1. Cerrar en Fase 2 los campos de `Observation`, identidad, validacion, proveniencia y decisiones de filtrado.
2. Crear fixtures anonimizados de Uptime Kuma 1.23.x, 2.0 y la version desplegada.
3. Implementar configuracion tipada y redactada para instancia, autenticacion, TLS, intervalos y limites.
4. Implementar cliente HTTPX con clasificacion de errores y sondeo de capacidades.
5. Implementar parser acotado y mapper a `Observation`.
6. Implementar estado por monitor, deteccion de transiciones y desaparicion confirmada.
7. Integrar deduplicacion, transaccion de checkpoint/outbox y spool compartidos.
8. Implementar politicas provisionales y registrar razones auditables.
9. Probar localmente `/metrics` contra una instancia controlada y comparar V1/V2.
10. Implementar y probar webhook solo despues de estabilizar reconciliacion por snapshot.
11. Medir CPU, memoria, bytes, latencia, ruido, duplicados y recuperacion en el appliance objetivo.
12. Documentar operacion, diagnostico, rotacion de credenciales y compatibilidad validada.

## Estrategia de pruebas

### Contrato y parser

- snapshots anonimizados 1.23.x, 2.0 y 2.5;
- labels vacios, escapados, sanitizados, duplicados y desconocidos;
- valores cero, `-1`, `NaN`, infinitos y metricas opcionales ausentes;
- respuesta truncada, demasiado grande o sin `monitor_status`;
- dos monitores con nombres iguales y distintos IDs;
- identidad derivada para 1.x.

### Autenticacion y transporte

- API key valida, invalida, deshabilitada y expirada;
- usuario y contrasena validos e invalidos;
- autenticacion deshabilitada solo con permiso explicito;
- TLS valido, CA privada y certificado rechazado;
- timeout, DNS, `401`, `403`, `429` y `5xx`.

### Estado y resiliencia

- primera observacion;
- `UP -> DOWN -> UP`;
- `UP -> PENDING -> DOWN`;
- entrada y salida de mantenimiento;
- monitor nuevo, renombrado y eliminado;
- scrape fallido entre dos exitosos;
- proceso detenido antes y despues del commit;
- reinicio con outbox pendiente;
- backend caido y recuperacion sin duplicados.

### Webhook opcional

- autenticacion y limites del receptor;
- evento antes y despues del snapshot equivalente;
- entrega repetida;
- evento perdido y reconciliado por `/metrics`;
- payload sin monitor o heartbeat;
- evidencia sensible dentro del heartbeat.

## Criterios de salida de esta investigacion

Esta parte de la Fase 3 podra considerarse completa cuando:

- se identifique la version desplegada de Uptime Kuma; (cumplido: 1.23.17 en laboratorio)
- se capture un fixture real anonimizado de su `/metrics`; (cumplido)
- se confirme el modo de autenticacion disponible; (cumplido: usuario/contrasena Basic, API Keys deshabilitadas)
- Fase 2 cierre el contrato minimo de `Observation`; (schemas y validacion implementados; aprobacion pendiente)
- se aprueben identidad, frecuencia, limites y politica de desaparicion;
- se decida si el webhook entra en la demostracion inicial o queda como mejora;
- las decisiones confirmadas se conviertan en pruebas de contrato ejecutables.

## Implementacion actual del conector

- `src/txdx_etl/connectors/uptime_kuma/parser.py`: parser de exposicion Prometheus con sondeo de capacidades y rechazo estricto de contratos desconocidos.
- `src/txdx_etl/connectors/uptime_kuma/mapper.py`: mapper fuente-canonico que produce assets y observations con identidad determinista.
- `src/txdx_etl/connectors/uptime_kuma/detector.py`: motor de cambios entre snapshots; clasifica cada monitor como `initial`, `refresh`, `change`, `discovered` o `disappeared` segun las reglas de la seccion de estado, con umbral configurable de scrapes consecutivos antes de confirmar desaparicion. Implementa ademas la politica de emision: ciclos sin cambios no generan registros, el refresh actua como latido periodico (una emision por ventana configurable) y un cambio de certificado se emite de inmediato.
- `src/txdx_etl/connectors/uptime_kuma/client.py`: cliente HTTP de `/metrics` sobre HTTPX con Basic Auth (API key como contrasena), TLS verificado por defecto, limite de bytes en streaming, redireccionamiento desactivado y clasificacion de errores segun la tabla de autenticacion y rate limiting de este documento.
- Pruebas offline con fixtures 1.23.x/2.x y transporte simulado en `tests/unit/test_kuma_client.py` y `tests/contract/test_kuma_mapping.py`.

## Preguntas pendientes

- Que version exacta de Uptime Kuma esta desplegada? (respondido: 1.23.17 en laboratorio)
- Cuantos monitores existen y cual es el crecimiento esperado? (parcial: 10 hoy en laboratorio)
- Cual es el intervalo minimo configurado en los monitores?
- Que tags o inventario definen un activo critico? (nota: 1.23.x no expone tags como labels; confirmado en laboratorio)
- Cual es la latencia maxima aceptable para detectar una caida?
- Se puede configurar un webhook en todos los monitores del entorno de prueba?
- Uptime Kuma y el ETL comparten host o volumen, o solo conectividad de red?
- Que campos del target puede recibir el backend actual sin exponer secretos?
- Que umbrales de certificado y persistencia de `PENDING` se aprobaran?

Mientras estas respuestas no existan, V2 utilizara deteccion de capacidades, configuracion conservadora y valores iniciales medibles en lugar de asumir una version o escala.

## Fuentes oficiales

- Prometheus Integration: https://github.com/louislam/uptime-kuma/wiki/Prometheus-Integration
- Prometheus API Keys: https://github.com/louislam/uptime-kuma/wiki/Prometheus-API-Keys
- Internal API: https://github.com/louislam/uptime-kuma/wiki/Internal-API
- Notification Methods: https://github.com/louislam/uptime-kuma/wiki/Notification-Methods
- Metricas actuales: https://github.com/louislam/uptime-kuma/blob/master/server/prometheus.js
- Ruta `/metrics`: https://github.com/louislam/uptime-kuma/blob/master/server/server.js
- Autenticacion: https://github.com/louislam/uptime-kuma/blob/master/server/auth.js
- Webhook: https://github.com/louislam/uptime-kuma/blob/master/server/notification-providers/webhook.js
- Semantica de notificaciones: https://github.com/louislam/uptime-kuma/blob/master/server/model/monitor.js
- Rutas HTTP: https://github.com/louislam/uptime-kuma/blob/master/server/routers/api-router.js
