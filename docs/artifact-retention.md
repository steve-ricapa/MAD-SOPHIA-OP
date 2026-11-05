# Archivos de diagnóstico y retención

Las seis integraciones separan la información necesaria para operar de las copias opcionales para investigar una recolección. Los controles de almacenamiento no cambian la consulta al sensor, los límites de extracción, la política de envío ni las credenciales.

## Qué se conserva

| Tipo | Comportamiento |
| --- | --- |
| Estado, firmas, contador de ciclos y bases SQLite | Permanecen en sus rutas configuradas. La limpieza de diagnósticos no los recorre ni elimina. |
| Journal `delivery-v2` y payloads pendientes | Permanecen hasta que el mecanismo de entrega confirma el envío. No caducan por la política de archivos opcionales. |
| Último snapshot, último payload y último recibo | Se conserva la copia más reciente y se sobrescribe al producir una nueva. Un archivo llamado `last_payload_sent.json` puede contener el último intento: la confirmación debe comprobarse en el recibo/journal. |
| Históricos completos | Desactivados por defecto. Con la opción explícita se guardan bundles administrados con límites de antigüedad, espacio y cantidad. |
| Logs | Rotan por tamaño y sus archivos rotados se limitan por cantidad y antigüedad. |
| `dead-letter`, respaldos y archivos históricos anteriores | No se eliminan automáticamente por esta mejora. Su disposición requiere un inventario y revisión independiente. |

## Variables comunes

Cada asignación activa de `.env.example` tiene un comentario que explica su función. Los controles nuevos son:

| Variable | Valor de ejemplo | Efecto |
| --- | --- | --- |
| `MAD_ARCHIVE_ENABLED` | `false` | Deshabilita los históricos completos opcionales. No deshabilita últimas copias, estados ni pendientes. |
| `MAD_ARCHIVE_RETENTION_DAYS` | `7` | Días máximos de conservación de los bundles administrados. |
| `MAD_ARCHIVE_MAX_MB` | `100` | Presupuesto en MiB por raíz administrada e integración. No es un presupuesto global para Nexus. |
| `MAD_ARCHIVE_MAX_ENTRIES` | `100` | Cantidad máxima de bundles por raíz administrada e integración; un bundle puede contener varios archivos. |
| `MAD_LOG_MAX_MB` | `5` | Umbral de rotación en MiB. |
| `MAD_LOG_BACKUP_COUNT` | `5` | Número máximo de archivos rotados por flujo de log; no incluye el activo. |
| `MAD_LOG_RETENTION_DAYS` | `14` | Antigüedad máxima de los logs rotados. |
| `LOG_LEVEL` | `INFO` | Nivel del logger de Wazuh. `DEBUG` añade detalle a ese log, no habilita el histórico completo. |

Los límites deben ser positivos. El gestor retira los bundles administrados más antiguos cuando vencen o cuando es necesario liberar presupuesto/cantidad. Un bundle mayor que todo el presupuesto se omite y se registra una advertencia; un problema de escritura de un diagnóstico opcional no debe bloquear el transporte de metadata. Reducir el presupuesto no afecta los payloads de entrega pendientes.

Los seis transportes conservan opciones de diagnóstico específico: `NESSUS_PAYLOAD_DEBUG`, `UPTIME_PAYLOAD_DEBUG`, `ZABBIX_PAYLOAD_DEBUG`, `OPENVAS_PAYLOAD_DEBUG`, `WAZUH_PAYLOAD_DEBUG` e `INSIGHTVM_PAYLOAD_DEBUG`. Por defecto están en `false`. Si una se activa, fuerza un bundle de diagnóstico de ese transporte aun con `MAD_ARCHIVE_ENABLED=false`, pero se aplican los mismos límites de retención, espacio y cantidad. El comentario `*_PAYLOAD_DEBUG_DIR` muestra cómo elegir su raíz; configurar una ruta no activa la captura.

Las raíces de histórico general y de debug pueden ser distintas, por lo que sus presupuestos se contabilizan por separado. Habilitar muchos históricos y rutas de debug aumenta el espacio máximo total. No es necesario activar debug para consultar el último snapshot y el último recibo.

## Directorios administrados y protección de datos

Los bundles nuevos usan la estructura:

```text
<raíz>/.mad-archive-v1/<integración>/
    .owner.json
    .lock
    entry-<uuid>/
        .entry.json
        raw.json / snapshot.json / normalized.json / report.xml / payload.json / metadata.json ...
```

El marcador identifica el gestor y la integración. Cada manifest de entrada identifica los archivos permitidos y la fecha de creación. Solo se limpian entradas reconocidas de esa estructura. Un marcador incompatible, nombres inesperados o enlaces simbólicos detienen esa limpieza para revisión; no autorizan borrar otros archivos.

Los directorios antiguos `raw_batches/`, `payloads/`, `reports/<report_id>/` y las carpetas antiguas de payload debug permanecen intactos. Desactivar el histórico detiene la creación de nuevas copias opcionales, pero no borra retrospectivamente esos archivos. El mantenimiento del formato nuevo puede retirar sus propios bundles vencidos aunque ya no se estén generando otros.

Los payloads y XML pueden contener información sensible del entorno. En POSIX se crean archivos privados y directorios administrados privados; en Windows hay que proteger también las ACL heredadas del directorio padre.

## Logs y alcance de los límites

Cada integración conserva `delivery_receipts.jsonl`: un historial pequeño de identificadores, fechas y resultados, sin el payload completo ni claves API. Usa los mismos límites `MAD_LOG_*`. Es evidencia de transporte, no una confirmación del procesamiento posterior en AWS. Los recibos completos más recientes siguen en sus rutas habituales.

Wazuh utiliza rotación y retención del logger. El orquestador revisa sus logs antes de iniciar cada integración. El umbral no es un límite estricto del archivo activo durante una ejecución: un ciclo muy verboso puede superarlo y se rotará en la siguiente revisión. La cantidad y la antigüedad se aplican a archivos rotados reconocidos; las bases, colas y respaldos quedan fuera.

La retención se ejecuta durante los ciclos/archivado y la rotación; no es un servicio de limpieza independiente. Si MAD queda detenido, no se promete borrar archivos exactamente al vencer el plazo.

## Revisión de lo acumulado antes de esta política

El inventario se obtiene sin ejecutar colectores ni enviar datos:

```bash
python scripts/audit_storage.py --repo . --older-than-days 30
```

`scripts/audit_storage.py` es una herramienta de inventario de solo lectura. No tiene una operación `--apply` para eliminar el legado. La antigüedad o el nombre de un archivo no demuestran que se pueda eliminar: primero hay que separar evidencias históricas, fallos sin resolver, respaldos necesarios y dependencias operativas. La limpieza de lo acumulado requiere una lista verificada y una decisión de conservación.

Para desplegar, respaldar primero el `.env`, el estado, los journals y las bases; aplicar el código probado y modificar únicamente los controles de almacenamiento acordados. No cambiar credenciales, rutas de estado, paginación, límites de hallazgos o la programación del temporizador para resolver el crecimiento de diagnósticos.
