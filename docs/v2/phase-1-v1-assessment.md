# Fase 1: Evaluacion tecnica de V1

## Conclusion

V1 contiene seis aplicaciones independientes. Comparte una idea de entrega, pero no un nucleo ETL. La estrategia V2 sera conservar conocimiento de proveedor y reemplazar la infraestructura duplicada.

## Criterio de migracion

| Decision | Significado |
| --- | --- |
| Reutilizar | Logica aislada, determinista y comprobable que puede trasladarse con cambios menores. |
| Adaptar | Logica util que requiere interfaces, paginacion, errores tipados o inyeccion de dependencias. |
| Reemplazar | Componente acoplado, duplicado, inseguro o incompatible con el modelo V2. |

## Componentes comunes

| Componente V1 | Decision V2 | Motivo |
| --- | --- | --- |
| Clientes y parsers de proveedor | Adaptar | Contienen el conocimiento mas costoso de reconstruir. |
| Normalizadores por integracion | Adaptar | Deben producir entidades canonicas y separar filtrado de transformacion. |
| `agent.py` y `main.py` | Reemplazar | Mezclan scheduler, extraccion, estado, transformacion y entrega. |
| Seis `snapshot.py` | Reemplazar | Una firma agregada no deduplica registros individuales de forma segura. |
| Variantes de `deliver.py` | Reemplazar | Repiten protocolo, retry, cola y tratamiento de errores. |
| Estados JSON | Reemplazar | No permiten transacciones entre cursor, deduplicacion y outbox. |
| Contratos construidos manualmente | Reemplazar | Conviven versiones y semanticas diferentes. |
| Pruebas de parsers y clientes | Reutilizar | Son una base para pruebas de regresion del conector. |
| Pruebas de delivery duplicadas | Consolidar | Deben validar una sola implementacion compartida. |

## Uptime Kuma

| V1 | Decision |
| --- | --- |
| `collector.py::parse_metrics` y parser de labels | Reutilizar. |
| Cliente HTTP de metricas | Adaptar a cliente inyectable, timeouts y errores tipados. |
| Enriquecimiento SQLite | Adaptar como capacidad opcional del conector. |
| Mapeo `STATUS_META` | Reutilizar como semantica fuente. |
| `build_findings` | Adaptar; disponibilidad no debe forzarse a vulnerabilidad. |
| Reporte, agente, configuracion, snapshot y delivery | Reemplazar por el nucleo V2. |

## Zabbix

| V1 | Decision |
| --- | --- |
| JSON-RPC, login y llamadas API | Adaptar a sesion inyectable y errores tipados. |
| Consultas de hosts, problemas, eventos y triggers | Adaptar con paginacion y frontera temporal. |
| Mapeo de severidades | Reutilizar como dato fuente, no como riesgo final. |
| Asociacion trigger-host-interface | Adaptar como mapper del conector. |
| `summarize` | Separar en normalizacion, politica de relevancia y agregacion. |
| Idempotencia actual | Reemplazar; incorpora un UUID aleatorio. |
| Reporte, agente, configuracion, snapshot y delivery | Reemplazar por el nucleo V2. |

## Migraciones posteriores

| Fuente | Reutilizar o adaptar | Reemplazar |
| --- | --- | --- |
| Nessus | Cliente, filtros de scans y mapeos de plugins. | Agente, estado, snapshot, reporte y delivery. |
| OpenVAS | Transporte GMP, cliente y parsers XML. | Monolito principal, estado y delivery. |
| InsightVM | Cliente paginado y conceptos `Asset`/`Finding`. | Orquestador, manejo de error-vacio, estado y backend duplicado. |
| Wazuh | Paginacion OpenSearch, normalizacion MITRE y parte del estado SQLite. | Loop, firma temporal y sender propio. |

## Riesgos V1 que V2 no debe heredar

- Credenciales dentro del payload de negocio o archivos de cola.
- Imports ambiguos como `from config import ...` dependientes del directorio actual.
- Respuestas vacias indistinguibles de errores de extraccion.
- Snapshots completos acumulados en memoria.
- Claves idempotentes aleatorias.
- Colas sin cuota, retencion o aislamiento por tenant.
- Configuracion TLS insegura por defecto.
- Escritura de artefactos y estado dentro del codigo fuente.
- Efectos de red o loops al importar modulos.

## Orden de migracion

1. Construir el nucleo V2 sin mover V1.
2. Crear contrato canonico, identidad y validacion.
3. Implementar estado SQLite, outbox, spool y delivery.
4. Migrar Uptime Kuma y comparar resultados con V1.
5. Migrar Zabbix con paginacion e idempotencia por registro.
6. Validar fallos, recursos y compatibilidad con el backend.
7. Retirar V1 solo despues de cumplir los criterios de Fase 0.
