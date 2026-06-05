# Resumen de Integraciones y Agentes (Presentación)

## 1. ¿Qué es este sistema?
`MAD-SOPHIA-OP` es una plataforma que reúne varias herramientas de seguridad y monitoreo en un solo servicio.

Cada agente se conecta a una herramienta distinta, recoge datos, los ordena y los envía al sistema web central para que todo se vea en un mismo lugar.

## 2. ¿Qué hace cada integración?

1. **Wazuh**
- Trae alertas de seguridad (eventos sospechosos).
- Filtra ruido y envía lo importante.
- Ayuda a detectar incidentes de forma más clara.

2. **Zabbix**
- Trae problemas de infraestructura (hosts, triggers, eventos).
- Muestra salud y estado operativo de los equipos.
- Ayuda a identificar caídas o fallas técnicas.

3. **Uptime Kuma**
- Monitorea disponibilidad de servicios (arriba/abajo).
- Registra tiempos de respuesta.
- Ayuda a controlar continuidad del servicio al cliente.

4. **Nessus**
- Toma resultados de escaneos de vulnerabilidades.
- Resume hallazgos por severidad.
- Ayuda a priorizar qué corregir primero.

5. **OpenVAS**
- Procesa reportes de vulnerabilidades.
- En este proyecto está orientado a laboratorio/pruebas.
- Sirve para validar flujo de recolección y envío de hallazgos.

6. **InsightVM**
- Consolida activos y vulnerabilidades (Rapid7).
- Genera visión de riesgo por activo.
- Ayuda a enfocar esfuerzos de remediación.

## 3. ¿Cómo están desarrolladas? (Explicación simple)

Todos los agentes siguen un flujo parecido:

1. Revisan su herramienta cada cierto tiempo.
2. Detectan información nueva.
3. Evitan duplicados para no repetir alertas.
4. Guardan estado local para continuidad.
5. Envían datos al backend web.
6. Si hay fallos de red/backend, reintentan y guardan evidencia.

Además, existe un **orquestador central** que:

1. Inicia todos los agentes.
2. Ejecuta pruebas de conectividad al arranque.
3. Reinicia agentes si alguno se cae.
4. Permite ejecutar todos o solo una integración.

## 4. Funcionalidades fáciles de explicar

1. **Vista unificada**: varias herramientas, una sola salida.
2. **Menos ruido**: filtros + deduplicación.
3. **Continuidad**: estado local para no perder contexto.
4. **Resiliencia**: reintentos automáticos ante fallos.
5. **Trazabilidad**: logs y artefactos para auditoría.
6. **Escalabilidad por cliente**: configuración por entorno e intervalos.

## 5. ¿Cómo benefician estos agentes a muchos clientes?

1. **Ahorro de tiempo**: evita revisar múltiples consolas por separado.
2. **Mejor decisión**: datos normalizados y comparables.
3. **Respuesta más rápida**: alertas centralizadas.
4. **Menor costo operativo**: más automatización, menos trabajo manual.
5. **Base de crecimiento**: se pueden agregar nuevas integraciones sin rehacer todo.

## 6. Mensaje de cierre para la presentación

“Este sistema convierte múltiples fuentes técnicas en información clara y accionable para el negocio: detecta, organiza, evita ruido y entrega una visión única de seguridad y disponibilidad para muchos clientes.”
