# Propuesta de Tesis: Extensión Analítica y de Machine Learning para XOC

## 1. Contexto

XOC ya cuenta con una arquitectura productiva serverless, multi-tenant y event-driven en AWS, con Amazon API Gateway, AWS Lambda, EventBridge, S3, RDS, DynamoDB y JWT Authorizer.

La plataforma adquiere datos por tenant desde seis integraciones principales:

- Zabbix
- Uptime Kuma
- Wazuh
- OpenVAS
- Nessus
- InsightVM

Los datos se almacenan actualmente como resúmenes estructurados en RDS y como snapshots completos en Amazon S3.

La propuesta no consiste en crear una plataforma analítica paralela, sino en extender la arquitectura existente de XOC con un nuevo dominio de analítica y Machine Learning.

## 2. Problema

Actualmente parte del procesamiento para indicadores, estadísticas y gráficas ocurre en el frontend.

```text
Integraciones
    ↓
Ingesta XOC
    ↓
S3 snapshots + RDS
    ↓
API actual
    ↓
Frontend
    ↓
Transformación + análisis + gráficas
```

A medida que crezcan tenants, activos, histórico, frecuencia de adquisición y tamaño de snapshots, esto puede aumentar transferencia de datos, memoria del navegador, tiempos de carga y complejidad del frontend.

## 3. Objetivo

Incorporar dentro de XOC un nuevo dominio:

**XOC Analytics & ML Service**

Responsabilidades:

- Normalización de datos.
- ETL.
- Agregación de KPIs.
- Histórico analítico.
- Feature Engineering.
- Machine Learning.
- Priorización inteligente de vulnerabilidades.
- Exposición de resultados mediante la API existente.

## 4. Integración con la arquitectura existente

```text
                    ARQUITECTURA XOC

Integraciones
      ↓
Ingesta actual
      ↓
S3 / RDS / DynamoDB
      ↓
EventBridge
      ↓
┌──────────────────────────────┐
│ NUEVO DOMINIO ANALYTICS & ML │
│                              │
│ Normalización                │
│ Agregación                   │
│ Feature Engineering          │
│ Machine Learning             │
└──────────────┬───────────────┘
               ↓
       Analytics Storage
               ↓
         analyticsApi
               ↓
       API Gateway actual
               ↓
          Frontend XOC
```

Se reutilizan API Gateway, JWT Authorizer, multi-tenancy, EventBridge, S3, RDS, DynamoDB, seguridad y observabilidad existentes.

## 5. Flujo event-driven

La adquisición actual no necesita reemplazarse. La mejora comienza cuando el snapshot ya fue almacenado.

```text
Nuevo snapshot en S3
      ↓
EventBridge
      ↓
Evento Analytics
      ↓
SQS
      ↓
Procesamiento Analytics
      ↓
Normalización
      ↓
Validación
      ↓
Enriquecimiento
      ↓
Agregación
      ↓
Feature Engineering
      ↓
ML Scoring
      ↓
Persistencia
```

SQS permitiría desacoplar el procesamiento y absorber picos.

## 6. RAW y Analytics

Los snapshots originales permanecen como fuente RAW.

```text
s3://xoc-data/

raw/
    tenant-123/
        zabbix/
        uptime-kuma/
        wazuh/
        openvas/
        nessus/
        insightvm/

analytics/
    tenant-123/
        network/
        infrastructure/
        vulnerabilities/
        events/
        applications/
```

La zona Analytics contendría información normalizada, validada y optimizada para consulta.

Ejemplo:

```text
analytics/vulnerabilities/
tenant_id=tenant-123/
year=2026/
month=08/
day=25/
data.parquet
```

Se propone evaluar Apache Parquet y particionamiento para el histórico analítico.

## 7. Normalización

Cada herramienta posee estructuras distintas. La capa ETL las transforma hacia modelos analíticos comunes de XOC.

```json
{
  "tenantId": "tenant-123",
  "source": "openvas",
  "category": "vulnerability",
  "assetId": "server-01",
  "timestamp": "2026-08-25T14:00:00Z",
  "severity": "critical",
  "cvss": 9.8,
  "metric": "vulnerability",
  "value": 1
}
```

Así el frontend deja de necesitar lógica específica para cada integración.

## 8. Capa analítica

Para histórico:

```text
S3 Analytics
      ↓
AWS Glue Data Catalog
      ↓
Amazon Athena
```

Athena podría utilizarse para tendencias, comparaciones temporales, reportes y análisis histórico.

Para KPIs frecuentes se utilizarían resultados precomputados:

```text
S3 Analytics
      ↓
Aggregation Lambda
      ↓
DynamoDB
      ↓
analyticsApi
      ↓
Frontend
```

Esto evita lanzar múltiples consultas analíticas cada vez que se abre el dashboard.

## 9. analyticsApi

Se agregaría un módulo dentro del backend actual, no un API Gateway nuevo.

```text
Frontend XOC
      ↓
API Gateway existente
      ↓
JWT Authorizer existente
      ↓
analyticsApi
      ↓
DynamoDB / Athena / Analytics Storage
```

Endpoints conceptuales:

```http
GET /analytics/overview
GET /analytics/vulnerabilities
GET /analytics/vulnerabilities/trend
GET /analytics/vulnerabilities/prioritized
GET /analytics/assets/risk
GET /analytics/network/availability
GET /analytics/incidents/timeline
```

El aislamiento por tenant reutilizaría el mecanismo multi-tenant actual de XOC.

## 10. Machine Learning

La capa analítica serviría también como dataset para Machine Learning.

Primer caso de uso:

**Priorización inteligente de vulnerabilidades.**

CVSS por sí solo expresa severidad técnica, pero no necesariamente qué vulnerabilidad debe remediarse primero dentro del contexto operacional del cliente.

## 11. XOC Priority Score

El modelo produciría un score de 0 a 100.

```text
Vulnerabilidad       CVSS       XOC Priority

CVE-A                 9.8            63
CVE-B                 9.7            96
CVE-C                 9.4            81
```

Una vulnerabilidad con CVSS ligeramente menor podría recibir mayor prioridad si afecta un activo crítico, está expuesta a Internet, tiene exploit conocido o afecta múltiples activos.

## 12. Features

Variables potenciales:

- CVSS Base Score.
- Severidad.
- Criticidad del activo.
- Exposición a Internet.
- Exploit conocido.
- Madurez del exploit.
- Número de activos afectados.
- Tipo de activo.
- Antigüedad de vulnerabilidad.
- Tiempo sin remediar.
- Recurrencia.
- Historial de incidentes.
- Historial de vulnerabilidades del activo.
- Disponibilidad requerida.
- Fuente de detección.
- Número de herramientas que detectan el problema.
- Impacto en disponibilidad.
- Impacto en confidencialidad.
- Impacto en integridad.
- Contexto operacional del tenant.

## 13. Feature Engineering

```text
S3 Analytics
      ↓
Feature Engineering
      ↓
ML Dataset
      ↓
Modelo
      ↓
XOC Priority Score
```

Ejemplo de dataset:

```text
CVE
CVSS
AssetCriticality
InternetExposed
KnownExploit
AffectedAssets
Age
Recurrence
IncidentHistory
AvailabilityImpact
RemediationPriority
```

## 14. Formulación ML

En lugar de limitarse a:

```text
¿Es crítica?
Sí / No
```

se plantea:

> Dado un conjunto de vulnerabilidades detectadas en la infraestructura de un tenant, determinar el orden recomendado de remediación considerando severidad técnica y contexto operacional.

La formulación puede estudiarse como:

- Scoring.
- Clasificación ordinal.
- Ranking.
- Learning-to-Rank.

La formulación definitiva dependerá de la calidad y cantidad de datos disponibles.

## 15. Modelos candidatos

Para datos tabulares:

- XGBoost.
- LightGBM.
- Random Forest como baseline.
- Algoritmos Learning-to-Rank si el dataset lo permite.

No es necesario comenzar con redes neuronales.

## 16. Explicabilidad

El score debería acompañarse de razones.

```json
{
  "cve": "CVE-XXXX",
  "priorityScore": 94,
  "priority": "IMMEDIATE",
  "factors": {
    "cvss": 9.1,
    "internetExposed": true,
    "criticalAsset": true,
    "knownExploit": true,
    "affectedAssets": 17
  }
}
```

Se pueden evaluar Feature Importance y SHAP para explicar las decisiones.

## 17. Arquitectura consolidada

```text
                  FUENTES DE DATOS XOC

 Zabbix   Kuma   Wazuh   OpenVAS   Nessus   InsightVM
    │       │      │        │         │         │
    └───────┴──────┴────────┴─────────┴─────────┘
                           │
                           ▼
                  INGESTA XOC ACTUAL
                           │
                  ┌────────┴─────────┐
                  ▼                  ▼
                RDS              S3 RAW
                                    │
                              EventBridge
                                    │
                                    ▼
                                   SQS
                                    │
                  ┌─────────────────▼─────────────────┐
                  │        ANALYTICS & ML DOMAIN      │
                  │                                   │
                  │ Normalize                         │
                  │    ↓                              │
                  │ Validate                          │
                  │    ↓                              │
                  │ Enrich                            │
                  │    ↓                              │
                  │ Aggregate                         │
                  │    ↓                              │
                  │ Feature Engineering               │
                  │    ↓                              │
                  │ ML Scoring                        │
                  └─────────────────┬─────────────────┘
                                    │
                     ┌──────────────┴──────────────┐
                     ▼                             ▼
              S3 Analytics                    DynamoDB
               / Parquet                    KPIs / Scores
                     │                             │
                     ▼                             │
              Glue + Athena                        │
                     │                             │
                     └──────────────┬──────────────┘
                                    ▼
                              analyticsApi
                                    │
                         API Gateway existente
                                    │
                         JWT Authorizer existente
                                    │
                                    ▼
                              FRONTEND XOC
```

## 18. Qué se reutiliza y qué se agrega

### Se reutiliza

- API Gateway.
- JWT Authorizer.
- Multi-tenancy.
- Lambdas.
- EventBridge.
- S3.
- RDS.
- DynamoDB.
- Arquitectura serverless.
- Arquitectura event-driven.
- Seguridad y observabilidad existentes.

### Se agrega

- Analytics Pipeline.
- Normalización analítica.
- Analytics Storage.
- KPIs precomputados.
- analyticsApi.
- Feature Engineering.
- Modelo ML.
- XOC Priority Score.

## 19. Evaluación técnica

La tesis puede comparar la arquitectura actual contra la propuesta mediante:

- Tiempo de carga del dashboard.
- Latencia.
- MB transferidos al navegador.
- Uso de memoria.
- Procesamiento frontend.
- Procesamiento backend.
- Escalabilidad.
- Snapshots procesados.
- Comportamiento multi-tenant.
- Costo AWS.
- Tasa de errores.
- Tiempo del pipeline.

## 20. Evaluación ML

Baseline:

```text
CVSS
  ↓
Orden por severidad
  ↓
Prioridad
```

Propuesta:

```text
CVSS
+
Criticidad
+
Exposición
+
Amenaza
+
Histórico
+
Recurrencia
+
Contexto operacional
      ↓
Machine Learning
      ↓
XOC Priority Score
      ↓
Ranking de remediación
```

Dependiendo de la formulación se pueden evaluar Precision, Recall, F1, ROC-AUC, NDCG o MAP.

## 21. Evolución futura

```text
Analítica descriptiva
        ↓
Priorización inteligente
        ↓
Detección de anomalías
        ↓
Correlación entre fuentes
        ↓
Root Cause Analysis
        ↓
Predicción de incidentes
        ↓
Forecasting
        ↓
Recomendaciones
        ↓
Remediación automatizada
```

## 22. Título propuesto

**Diseño e implementación de un servicio serverless de analítica y aprendizaje automático para la priorización inteligente de vulnerabilidades en una arquitectura multi-tenant orientada a eventos.**

Alternativa:

**Implementación de un servicio de analítica y Machine Learning sobre la arquitectura serverless event-driven de XOC para optimizar el procesamiento y priorización de vulnerabilidades.**

## 23. Objetivo general preliminar

Diseñar e implementar una extensión serverless de analítica y aprendizaje automático integrada a la arquitectura event-driven existente de XOC, que permita optimizar el procesamiento de datos provenientes de múltiples herramientas de monitoreo y priorizar vulnerabilidades considerando tanto su severidad técnica como el contexto operacional de los activos afectados.

## 24. Idea central

La tesis no crea otra plataforma. Evoluciona XOC:

```text
XOC ACTUAL

Adquisición → almacenamiento → API → frontend
```

Hacia:

```text
XOC EVOLUCIONADO

Adquisición
     ↓
Almacenamiento
     ↓
Eventos
     ↓
Analytics Pipeline
     ↓
Modelo analítico
     ↓
Machine Learning
     ↓
XOC Priority Score
     ↓
API existente
     ↓
Dashboard
```

La contribución combina arquitectura cloud, serverless computing, sistemas event-driven, ingeniería de datos, ETL, analítica, Machine Learning, ciberseguridad y multi-tenancy dentro de una arquitectura real ya existente.
