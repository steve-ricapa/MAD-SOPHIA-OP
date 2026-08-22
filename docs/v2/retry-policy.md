# Politica de reintentos y entrega durable

## Proposito

Este documento define como el ETL V2 maneja los envios que fallan por cortes de energia, perdida de red, backend apagado o credenciales incorrectas. Tambien registra la investigacion de practicas de la industria en la que se basa el diseno, para trazabilidad academica del proyecto.

## Contexto del problema

El pipeline entrega envelopes hacia un backend mediante HTTP. Entre la deteccion de un evento y su entrega pueden ocurrir fallas:

- corte de energia antes, durante o despues de un envio;
- perdida temporal de conectividad de red;
- backend detenido por mantenimiento;
- credenciales invalidas o rechazo permanente del receptor;
- respuestas lentas que cuelgan el proceso.

La garantia objetivo es at-least-once con deduplicacion exacta: un aviso nunca se pierde y nunca se aplica dos veces.

## Practicas observadas en proyectos de referencia

Se revisaron cuatro sistemas de telemetria ampliamente adoptados:

| Proyecto | Buffer local | Reintentos | Limite / descarte |
| --- | --- | --- | --- |
| Prometheus remote write | WAL en disco; cola por destino | Sin limite ("retries are endless"); backoff exponencial `min_backoff` a `max_backoff` duplicando cada fallo | Pierde datos solo si el destino esta caido mas de 2 horas (compactacion del WAL); expone contadores de reintentos y muestras descartadas |
| Telegraf (InfluxData) | Buffer por salida en memoria o disco (`buffer_strategy`), tamano `metric_buffer_limit` | Reintento automatico del lote fallido; intervalo de flush con jitter | Al llenarse el buffer, sobrescribe los mas viejos; ajuste reciente evita martillar salidas caidas |
| Vector (Datadog) | Buffer en disco tipo diario, sobrevive reinicios; garantia at-least-once requiere buffer en disco | Solo reintentable ante 408, 429 y 5xx (salvo 501); rechazos permanentes no se reintentan; backoff tipo Fibonacci con techo `retry_max_duration_secs` | `when_full`: bloquear (backpressure) o descartar nuevos |
| Fluent Bit | Almacenamiento filesystem hibrido con backlog al reiniciar | Programador con backoff exponencial y jitter (algoritmo AWS), base 5 s por defecto, techo `scheduler.cap` 2000 s; `Retry_Limit` configurable por salida | Tras agotar reintentos descarta, salvo DLQ activada (`storage.keep.rejected`); con `storage.total_limit_size` llena descarta el chunk mas viejo |

## Principios comunes identificados

1. **Guardar primero en disco, enviar despues.** Todos usan una cola duradera local antes del transporte.
2. **Dos relojes separados.** La ingesta sigue corriendo aunque el envio este en espera; el backoff afecta solo al enviador, jamas a la lectura de datos.
3. **Clasificacion de errores.** Transitorios (red, timeout, 408/429/5xx) se reintentan; permanentes (autenticacion, rechazo de contrato) no se reintentan y quedan visibles.
4. **Backoff exponencial siempre con techo** corto en redes locales, tipicamente con jitter para evitar tormentas sincronizadas.
5. **Ningun descarte silencioso:** todo lo que se pierde o estaciona queda contado y visible.

## Diseno adoptado en el ETL V2

### Guardar primero

Cada envelope se persiste en SQLite (`pipeline/outbox.py`) con `synchronous=FULL` y WAL antes de intentar enviarlo. El estado `delivered` se escribe solo tras confirmacion del sink. Los `record_id` entregados se registran en una tabla de deduplicacion exacta: el mismo hecho nunca se envia dos veces, ni siquiera tras reinicios.

### Dos relojes separados

El ciclo de lectura-deteccion-encolado corre en cada intervalo sin excepcion. El drenaje del outbox corre dentro del mismo ciclo pero se auto-regula: si el ultimo intento fallo de forma transitoria, el enviador omite sus intentos hasta cumplir la espera calculada. La lectura nunca se pausa.

### Clasificacion de errores de entrega

| Clase | Ejemplos | Tratamiento |
| --- | --- | --- |
| Exito | 2xx | Marcar `delivered`, registrar record_id, reiniciar backoff |
| Transitorio (`TransientDeliveryError`) | red caida, timeout, 503 del backend | Contar intento, pausar el drenaje el tiempo del backoff actual y duplicarlo hasta el techo |
| Permanente (`PermanentDeliveryError`) | rechazo de contrato, credencial de backend invalida | Estacionar el envelope en estado `failed` con su razon (analogia DLQ) y continuar con los siguientes; nunca se borra |

Los errores de scrape hacia Uptime Kuma ya clasificados por el cliente HTTP (`AuthenticationError`, `RateLimitedError`, `TransientMetricsError`, `SourceContractError`) siguen la misma filosofia: un ciclo fallido no hace avanzar el estado del detector ni cuenta como ausencia del monitor.

### Backoff con techo corto para LAN

Secuencia inicial 15 s, luego 30 s, luego 60 s y se mantiene en 60 s (techo). Es el patron Prometheus (`min_backoff`/`max_backoff`) y Fluent Bit (`base`/`cap`) dimensionado a un appliance donde el backend vive en la misma red local: reacciona rapido tras un susto y evita martillar un servidor caido.

### Auto-vigilancia

Siguiendo el principio de metricas internas de los cuatro proyectos, el runtime reporta en cada ciclo cuantos sobres quedaron pendientes, cuantos estacionados y el resultado del scrape. La integracion prevista es un monitor push de Uptime Kuma que vigila al propio ETL: cola creciente o scrape fallido sostenido disparan alerta automatica, sin depender de revision manual de logs.

## Parametros iniciales

| Parametro | Valor | Justificacion |
| --- | --- | --- |
| Intervalo de scrape | 30 s | Suficiente frente al intervalo minimo realista de chequeo de Kuma (~20 s) |
| Backoff inicial de envio | 15 s | Reaccion rapida ante fallos breves |
| Techo de backoff | 60 s | Red local; evita esperas largas innecesarias |
| Lote maximo por drenaje | 100 envelopes | Acotar trabajo por ciclo |
| Umbral de desaparicion | 3 scrapes consecutivos | Evita falsos positivos por un scrape irregular |
| Latido por monitor | 300 s | Ventana de refresh acordada en Fase 3 |

## Escenarios de falla y comportamiento esperado

| Escenario | Comportamiento |
| --- | --- |
| Corte de luz antes de enviar | El sobre ya estaba en SQLite; al arrancar de nuevo el ciclo lo encuentra pendiente y lo entrega |
| Corte de energia a mitad del envio | No hay confirmacion; el sobre permanece pendiente y se reenvia completo; el receptor deduplica por `record_id` e ignora el repetido |
| WiFi caido varios minutos | La lectura de Kuma puede fallar (el ciclo no avanza estado) y el envio reintenta 15/30/60 s; al volver la red la cola se drena completa |
| Backend apagado horas | Igual al anterior; los sobres acumulan kilobytes en SQLite, sin presion de memoria |
| Credencial de backend incorrecta | Primer intento produce error permanente: el sobre queda estacionado visible, el resto de la fila sigue drenandose y la alerta sale por el ping de auto-vigilancia |
| Envelope corrupto o rechazado por contrato | Estacionado con razon; no bloquea ni contamina a los demas |

## Referencias

1. Prometheus - Remote write tuning: https://prometheus.io/docs/practices/remote_write/
2. Prometheus - `storage/remote/queue_manager.go` (implementacion del backoff): https://github.com/prometheus/prometheus/blob/main/storage/remote/queue_manager.go
3. Prometheus - Discusion "When do retries stop in Remote Write?" (#16943): https://github.com/prometheus/prometheus/discussions/16943
4. InfluxData - Configure Telegraf (buffers y flush): https://docs.influxdata.com/telegraf/v1/configuration/
5. Telegraf - `docs/OUTPUTS.md` (semantica de reintento por lote): https://github.com/influxdata/telegraf/blob/master/docs/OUTPUTS.md
6. Vector - Buffering model (buffer en disco tipo diario): https://vector.dev/docs/architecture/buffering-model/
7. Vector - Guarantees (at-least-once con buffer en disco): https://vector.dev/docs/architecture/guarantees/
8. Vector - Referencia del sink Datadog metrics (politica de reintentos por codigo HTTP): https://vector.dev/docs/reference/configuration/sinks/datadog_metrics/
9. Fluent Bit - Scheduling and retries (backoff, jitter, Retry_Limit, DLQ): https://docs.fluentbit.io/manual/administration/scheduling-and-retries
10. Fluent Bit - Backpressure (limites de almacenamiento por salida): https://docs.fluentbit.io/manual/administration/backpressure
11. AWS - Exponential Backoff And Jitter: https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
