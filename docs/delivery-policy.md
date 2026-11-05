# Política de envío de metadata

## Perfiles

Las seis integraciones usan la misma política `change_or_backup`, resuelta por `mad_common.delivery`:

| Integración | Perfil predeterminado | Motivo |
| --- | --- | --- |
| Nessus | `change_or_backup`, 6 ciclos | Inventario y hallazgos. |
| OpenVAS | `change_or_backup`, 6 ciclos | Contenido y contador por reporte; un cambio en el mismo ID genera un evento nuevo. |
| InsightVM | `change_or_backup`, 6 ciclos | Activos y hallazgos normalizados. |
| Wazuh | `change_or_backup`, 6 ciclos | Eventos y agentes identificados por su contenido. |
| Uptime Kuma | `change_or_backup`, 6 ciclos | Monitores y métricas, incluidos los cambios de latencia. |
| Zabbix | `change_or_backup`, 6 ciclos | Problemas, eventos, hosts y triggers. |

Primero se envía un snapshot; después se envía inmediatamente si cambia el contenido. Si sigue igual, se omiten cinco consultas exitosas y se envía un respaldo en la sexta. El contador queda en disco y solo se reinicia tras una entrega confirmada. Un error de consulta no cuenta; mientras hay un envío pendiente, no se incrementa el contador ni se crean respaldos duplicados. Un reintento confirmado y una consulta sin cambios en la misma ejecución dejan el contador en cero. Un nuevo cambio sí puede generar un evento nuevo durante una caída de red.

La configuración común es `MAD_DELIVERY_MODE=change_or_backup` y `MAD_DELIVERY_BACKUP_CYCLES=6`. Sin variables también son los valores predeterminados de las seis. Se admiten overrides `<PREFIJO>_DELIVERY_MODE` y `<PREFIJO>_DELIVERY_BACKUP_CYCLES` (Kuma usa `UPTIME`), que prevalecen sobre los globales; el ejemplo no usa overrides. `on_change`, `periodic` y `always` permanecen como opciones explícitas para usos especiales. Solo `periodic` usa `*_DELIVERY_INTERVAL_SECONDS`.

Se cuentan consultas exitosas, incluidas las ejecuciones manuales. Seis ciclos no garantizan seis horas. Un error de detección de cambios no se corrige con el respaldo; se vuelve a construir y enviar un snapshot cuando corresponde. En monitoreo, las variaciones reales de métricas pueden provocar un envío en cada ejecución.

## Observación, envío y confirmación

La firma observada y la firma confirmada como enviada son estados separados. El colector guarda cada payload y su clave idempotente en `queue/delivery-v2/` antes de contactar el destino. Solo una respuesta de transporte explícitamente confirmada permite actualizar el estado entregado. Un falso, una excepción, un modo de consola o un payload meramente guardado dejan el evento pendiente.

En cada ciclo, los pendientes se reintentan antes de consultar la fuente. Se conserva exactamente el payload y la misma clave durante el reintento. La clave es distinta para cada transición real, incluso si el contenido vuelve de A a B y luego a A. Un backlog que no se pueda drenar hace que la ejecución termine con error y lo deja persistido para el próximo ciclo.

La cola JSON antigua de transporte no se importa ni se borra automáticamente: si hay archivos pendientes allí, el colector se detiene con un error para que se haga una migración explícita preservando los datos. Los controles de preflight validan la política y los recibos locales; no demuestran por sí mismos que AWS haya procesado la metadata.

## Migración y operación

Las opciones heredadas `FORCE_SEND_EVERY_CYCLES` y `SNAPSHOT_ALWAYS_SEND` se rechazan intencionalmente, incluso si están en `false`. Hay que quitarlas, retirar overrides anteriores de modo periódico o solo cambios y declarar la política común del ejemplo. Los estados previos solo se usan como línea base si registran que hubo un envío confirmado. Las firmas nuevas incluyen el contenido completo, por lo que en el primer ciclo tras migrar puede haber un envío inicial de sincronización. El contador nuevo empieza en cero; no se importan contadores antiguos con reglas distintas.

Conservar `delivery-v2` junto al estado de cada integración y protegerlo como dato sensible: contiene payloads que todavía no se han confirmado. En POSIX el journal aplica permisos privados al directorio y a los archivos. En Windows hereda ACL del directorio padre; el despliegue debe garantizar que solo la cuenta del servicio y administradores autorizados puedan leerlo.

Esta política y el código de este checkout son una implementación local candidata. No se han instalado en Nexus ni activado en producción. Antes de desplegar, revisar el inventario real de colas heredadas y estados, respaldarlos y acordar el primer envío de sincronización.
