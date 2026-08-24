# PLAN MAESTRO
# Plataforma Multi‑Tenant de Procesamiento, Correlación y Distribución de Eventos de Ciberseguridad

## 1. Resumen Ejecutivo

Este proyecto no será un ETL tradicional. Su propósito no es únicamente extraer, transformar y cargar información, sino construir una plataforma de procesamiento inteligente de eventos de ciberseguridad capaz de integrar múltiples herramientas, procesar información en tiempo real o por lotes, enriquecer datos, eliminar ruido, correlacionar eventos y proporcionar capacidades avanzadas de búsqueda, análisis y observabilidad.

La plataforma estará orientada a entornos multi‑tenant y será capaz de recibir información desde OpenVAS, Nessus, InsightVM, Wazuh, Zabbix y Uptime Kuma, entre otras posibles fuentes futuras.

---

## 2. Objetivos Estratégicos

### Objetivo General

Diseñar e implementar una plataforma escalable basada en arquitectura orientada a eventos (Event‑Driven Architecture) para el procesamiento y distribución de eventos de ciberseguridad.

### Objetivos Específicos

- Centralizar eventos provenientes de distintas herramientas.
- Normalizar formatos heterogéneos.
- Enriquecer información de seguridad.
- Eliminar hallazgos duplicados.
- Correlacionar eventos relacionados.
- Implementar búsquedas avanzadas.
- Incorporar observabilidad completa.
- Permitir procesamiento configurable y casi en tiempo real.
- Integrarse con infraestructura AWS Serverless.

---

# 3. Arquitectura General

Fuentes → Conectores → RabbitMQ → Normalización → Redis → Enriquecimiento → Deduplicación → Correlación → Routing → AWS → OpenSearch → Dashboard

## Principios Arquitectónicos

### Event-Driven Architecture

Todos los eventos serán tratados como mensajes independientes.

Beneficios:

- Escalabilidad horizontal.
- Tolerancia a fallos.
- Procesamiento desacoplado.
- Reintentos automáticos.
- Facilidad para agregar nuevas integraciones.

### Microservicios Especializados

Cada responsabilidad estará separada.

- Connector Service
- Normalization Service
- Enrichment Service
- Deduplication Service
- Correlation Service
- Routing Service

---

# 4. Stack Tecnológico Oficial

## Python

Lenguaje principal del proyecto.

Razones:

- Amplio uso en ciberseguridad.
- Amplio uso en Data Engineering.
- Excelente integración con APIs.
- Excelente soporte AWS.
- Amplio ecosistema de librerías.

## FastAPI

Responsable de:

- Exponer APIs.
- Gestionar Webhooks.
- Administración de conectores.
- Control del pipeline.

## RabbitMQ

Se utilizará como Message Broker.

Responsabilidades:

- Work Queues.
- Retries.
- Dead Letter Queue.
- Balanceo de carga.
- Aislamiento de productores y consumidores.

## Redis

Responsabilidades:

- Caché.
- Deduplicación temporal.
- Locks distribuidos.
- Rate limiting.
- Almacenamiento temporal de estado.

## OpenSearch

Responsabilidades:

- Indexación.
- Búsqueda avanzada.
- Filtros complejos.
- Agregaciones.
- Análisis histórico.

## AWS

Persistencia principal.

Componentes:

- API Gateway.
- Lambda.
- DynamoDB.
- Aurora (si aplica).

## Prometheus

Responsable de recolectar métricas.

## Grafana

Responsable de visualizar métricas y generar observabilidad operacional.

---

# 5. Justificación de RabbitMQ

Sin RabbitMQ:

Fuente → Procesamiento → AWS

Problemas:

- Pérdida de eventos.
- Acoplamiento.
- Escalabilidad limitada.
- Difícil gestión de errores.

Con RabbitMQ:

Fuente → RabbitMQ → Procesamiento → AWS

Ventajas:

- Buffer de eventos.
- Escalado horizontal.
- Retries automáticos.
- Dead Letter Queue.
- Mayor resiliencia.

---

# 6. Justificación de Redis

Redis permitirá resolver problemas de rendimiento.

## Cache de enriquecimiento

Evitar consultas repetidas.

## Deduplicación rápida

Detección inmediata de eventos previamente procesados.

## Locks distribuidos

Evitar procesamiento simultáneo de un mismo recurso.

## Control de frecuencia

Protección frente a límites de APIs externas.

---

# 7. Justificación de OpenSearch

La plataforma manejará grandes cantidades de eventos.

OpenSearch permitirá:

- Buscar CVEs.
- Buscar activos.
- Buscar IPs.
- Buscar vulnerabilidades.
- Realizar filtros avanzados.
- Construir dashboards analíticos.

## Análisis histórico

Ejemplo:

Snapshot día 1:

- 100 vulnerabilidades críticas.

Snapshot día 30:

- 60 vulnerabilidades críticas.

La plataforma podrá mostrar tendencias y evolución del riesgo.

---

# 8. Justificación de Prometheus y Grafana

## Problema

No basta con que el sistema funcione.

También debe poder monitorearse.

## Prometheus

Recolectará:

- Eventos procesados.
- Errores.
- Latencia.
- Retries.
- Mensajes pendientes.

## Grafana

Visualizará:

- Salud del pipeline.
- Rendimiento.
- Métricas por tenant.
- Saturación de colas.
- Tiempo de procesamiento.

Beneficio académico:

Permite demostrar observabilidad, monitoreo y operación empresarial.

---

# 9. Fases del Proyecto

## Fase 1 - Modelo Canónico

La fase más importante.

Objetivo:

Diseñar un formato universal de eventos.

Razón:

Todo el resto del sistema dependerá de este modelo.

Entregable:

Especificación oficial del esquema de eventos.

---

## Fase 2 - Desarrollo de Conectores

Integraciones:

- OpenVAS
- Nessus
- InsightVM
- Wazuh
- Zabbix
- Uptime Kuma

Características:

- Autenticación.
- Paginación.
- Snapshots.
- Ejecución programada.
- Procesamiento incremental.

---

## Fase 3 - Incorporación de RabbitMQ

Construcción de colas.

- ingestion.queue
- normalization.queue
- enrichment.queue
- deduplication.queue
- correlation.queue
- routing.queue

---

## Fase 4 - Normalización

Conversión de todos los formatos al modelo canónico.

Resultado:

Todas las herramientas producirán el mismo esquema lógico.

---

## Fase 5 - Redis

Implementación de:

- Cache.
- Locks.
- Deduplicación temporal.
- Estado temporal.

---

## Fase 6 - Enriquecimiento

Agregar contexto adicional.

Ejemplos:

- CVSS.
- EPSS.
- Risk Score.

---

## Fase 7 - Deduplicación

Consolidar hallazgos repetidos.

Ejemplo:

Misma vulnerabilidad detectada por múltiples scanners.

Resultado:

Una vulnerabilidad consolidada con múltiples evidencias.

---

## Fase 8 - Correlación

Relacionar eventos.

Ejemplo:

- Vulnerabilidad.
- Alerta.
- Problema de disponibilidad.

Resultado:

Incidente contextualizado.

---

## Fase 9 - Routing

Decidir el destino del evento.

Según:

- Severidad.
- Tipo de evento.
- Configuración.
- Reglas futuras.

---

## Fase 10 - Integración AWS

Envío de eventos procesados.

Destino:

- API Gateway.
- Lambda.
- DynamoDB.

---

## Fase 11 - OpenSearch

Indexación.

Búsquedas.

Dashboards analíticos.

Histórico.

---

## Fase 12 - Prometheus

Implementación de métricas.

---

## Fase 13 - Grafana

Construcción de dashboards operacionales.

---

# 10. Características de Rendimiento

La plataforma deberá soportar:

- Tiempo real.
- Procesamiento configurable.
- Procesamiento por snapshots.
- Reintentos automáticos.
- Escalabilidad horizontal.
- Procesamiento asíncrono.

---

# 11. Resultado Final Esperado

Una plataforma empresarial moderna capaz de operar como núcleo de integración de eventos de ciberseguridad.

Capacidades finales:

- Ingestión multi-fuente.
- Arquitectura orientada a eventos.
- Normalización.
- Enriquecimiento.
- Deduplicación.
- Correlación.
- Routing inteligente.
- Integración AWS.
- Observabilidad completa.
- Análisis histórico.
- Escalabilidad.
- Operación en tiempo real.

Esta solución se posiciona más cerca de una plataforma tipo SIEM o Security Data Platform que de un ETL tradicional.
