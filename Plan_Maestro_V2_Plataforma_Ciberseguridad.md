# PLAN MAESTRO V2
# Plataforma Cloud Multi‑Tenant para Procesamiento de Eventos de Ciberseguridad

## Estado del documento
Versión: 2.0
Enfoque: Arquitectura Cloud + Agente MAD

---

# 1. Visión Estratégica

El proyecto no será un ETL tradicional.

El objetivo es construir una plataforma centralizada capaz de recibir información de múltiples herramientas de ciberseguridad instaladas en diferentes clientes y procesarla de forma inteligente dentro de AWS.

La plataforma deberá:

- Soportar múltiples clientes.
- Procesar información en tiempo real o de forma programada.
- Reducir ruido mediante deduplicación.
- Agregar contexto mediante enriquecimiento.
- Correlacionar eventos relacionados.
- Enviar información al dashboard central.
- Escalar sin rediseñar la arquitectura.

La idea fundamental es separar:

## MAD (On Premise)

Responsable únicamente de recolección.

## AWS (Cloud)

Responsable de toda la inteligencia.

---

# 2. Principio Arquitectónico Fundamental

## Lo que NO queremos

Cada cliente con:

- RabbitMQ
- Redis
- Grafana
- Prometheus
- Correlación
- Deduplicación

Esto genera:

- Complejidad.
- Mayor consumo.
- Dificultad de mantenimiento.
- Actualizaciones distribuidas.

---

## Lo que SÍ queremos

Cliente:

OpenVAS
Nessus
InsightVM
Wazuh
Zabbix
Uptime Kuma
        ↓
      MAD
        ↓
      AWS

La inteligencia vive en AWS.

Esto permite:

- Multi tenancy real.
- Escalamiento centralizado.
- Menor consumo en cliente.
- Menor mantenimiento.

---

# 3. Arquitectura Objetivo

OpenVAS
Nessus
InsightVM
Wazuh
Zabbix
Uptime Kuma
      ↓
      MAD
      ↓
 AWS API Gateway
      ↓
   RabbitMQ
      ↓
 Normalización
      ↓
 Redis
      ↓
 Enriquecimiento
      ↓
 Deduplicación
      ↓
 Correlación
      ↓
 DynamoDB
      ↓
 Dashboard

Fase 2
      ↓
 Prometheus
 Grafana

Fase 3
      ↓
 OpenSearch

---

# 4. Componentes del MAD

## Python

Lenguaje principal.

Motivos:

- Amplio soporte para APIs.
- Amplio uso en ciberseguridad.
- Fácil mantenimiento.
- Excelente ecosistema.

## FastAPI

Responsable de:

- API local.
- Configuración.
- Gestión del MAD.
- Webhooks.

## Connectors

Conectores para:

- OpenVAS
- Nessus
- InsightVM
- Wazuh
- Zabbix
- Uptime Kuma

## Scheduler

Responsable de ejecutar sincronizaciones.

Ejemplos:

- Cada 5 minutos.
- Cada hora.
- Bajo demanda.

## Retry Engine

Responsable de reintentos.

Evita pérdida de datos.

## Compresión

Reduce tráfico de red.

## Firma y autenticación

Garantiza confianza en los datos.

---

# 5. Componentes Cloud

## RabbitMQ

Decisión tomada frente a SQS.

Motivos:

- Open Source.
- Sin costo por transacción.
- Sin dependencia directa de pricing AWS.
- Control total.
- Dead Letter Queue.
- Retries.
- Prioridades.

Responsabilidades:

- Buffer de eventos.
- Desacoplamiento.
- Escalabilidad.

---

## Normalización

Primer motor de inteligencia.

Problema:

Cada herramienta usa formatos distintos.

Solución:

Convertir todo a un modelo canónico único.

Beneficios:

- Procesamiento uniforme.
- Menor complejidad.
- Facilita correlación.

---

## Redis

Su función no es persistencia.

Será utilizado para:

- Cache.
- Locks.
- Deduplicación rápida.
- Control de frecuencia.

Beneficios:

- Muy bajo consumo.
- Muy alta velocidad.

---

## Enriquecimiento

Añade contexto.

Ejemplos:

- CVSS.
- Scores internos.
- Clasificaciones.
- Metadatos adicionales.

Objetivo:

Convertir eventos en información útil.

---

## Deduplicación

Uno de los componentes con más valor.

Ejemplo:

OpenVAS detecta una vulnerabilidad.

Nessus detecta la misma.

InsightVM detecta la misma.

Resultado esperado:

Una vulnerabilidad.

Tres evidencias.

Beneficios:

- Menos ruido.
- Menos almacenamiento.
- Mejor experiencia.

---

## Correlación

Segundo gran diferenciador.

Objetivo:

Relacionar eventos.

Ejemplo:

- Vulnerabilidad crítica.
- Alerta Wazuh.
- Problema operativo.

Resultado:

Incidente contextualizado.

---

## DynamoDB

Persistencia principal.

Responsabilidades:

- Almacenar resultados.
- Servir dashboard.
- Mantener snapshots.

---

# 6. Fase 1 (Producto Completo)

La Fase 1 ya es un producto totalmente funcional.

Incluye:

- MAD.
- RabbitMQ.
- Normalización.
- Redis.
- Enriquecimiento.
- Deduplicación.
- Correlación.
- DynamoDB.
- Dashboard.

Beneficios:

- Completa.
- Escalable.
- Multi tenant.
- Lista para producción.

No depende de Grafana.

No depende de OpenSearch.

Puede operar sola.

---

# 7. Fase 2 (Observabilidad Empresarial)

## Prometheus

Recolectará métricas:

- Eventos procesados.
- Errores.
- Retries.
- Latencias.
- Eventos por tenant.
- Rendimiento.

## Grafana

Visualizará:

- Salud del sistema.
- Uso de recursos.
- Estado de RabbitMQ.
- Estado de conectores.
- Rendimiento del pipeline.

### ¿Por qué implementarlo?

No agrega funcionalidad para el cliente.

Pero agrega muchísimo valor operacional.

Permite:

- Diagnóstico rápido.
- Monitoreo.
- Capacity Planning.
- Demostrar madurez técnica.

Conclusión:

La plataforma funciona sin ellos.

Pero con ellos se vuelve más profesional.

---

# 8. Fase 3 (Búsqueda y Analítica Avanzada)

## OpenSearch

Implementar únicamente cuando exista necesidad real.

Casos:

- Millones de registros.
- Búsquedas complejas.
- Tendencias históricas.
- Filtros avanzados.

Beneficio:

Gran capacidad analítica.

Costo:

Mayor complejidad.

Por ello no es prioridad inicial.

---

# 9. Plan de Ejecución

Paso 1:

Modelo canónico.

Paso 2:

Conectores.

Paso 3:

MAD.

Paso 4:

RabbitMQ.

Paso 5:

Normalización.

Paso 6:

Redis.

Paso 7:

Enriquecimiento.

Paso 8:

Deduplicación.

Paso 9:

Correlación.

Paso 10:

Persistencia AWS.

Paso 11:

Dashboard.

Paso 12:

Prometheus.

Paso 13:

Grafana.

Paso 14:

OpenSearch.

---

# 10. Conclusión Final

La arquitectura recomendada es:

MAD:
- Python
- FastAPI
- Connectors
- Scheduler
- Retry Engine
- Compresión
- Firma y autenticación

Cloud:
- RabbitMQ
- Normalización
- Redis
- Enriquecimiento
- Deduplicación
- Correlación
- DynamoDB
- Dashboard

Fase avanzada:
- Prometheus
- Grafana

Fase futura:
- OpenSearch

La Fase 1 proporciona el 80-90% del valor del sistema y ya constituye una plataforma profesional de procesamiento de eventos de ciberseguridad.

La Fase 2 aporta observabilidad empresarial.

La Fase 3 aporta capacidades avanzadas de búsqueda y análisis histórico.
