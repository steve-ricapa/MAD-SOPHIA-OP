# WazuhC Agent 🚀

El **WazuhC Agent** es un conector de alto rendimiento diseñado para extraer, normalizar y sincronizar alertas de seguridad desde un entorno Wazuh hacia un backend centralizado en tiempo real.

## 🌟 Características Principales

- **Sincronización Incremental**: Utiliza un sistema de checkpoints (`state/agent_state.db`) para asegurar que no se envíen datos duplicados y que no se pierda ninguna alerta tras un reinicio.
- **Reducción Inteligente de Datos**: Filtra el ruido (alertas de nivel bajo) mediante el parámetro `MIN_RULE_LEVEL`, enviando solo lo que es crítico para tu SOC.
- **Enriquecimiento MITRE ATT&CK**: Mapea automáticamente las alertas a tácticas y técnicas de MITRE, permitiendo visualizaciones avanzadas en el dashboard.
- **Agregación Real-time**: Envía reportes que incluyen "Top Agents" y "Top Rules", optimizando la carga de procesamiento del backend.
- **Logs Profesionales en JSON**: Toda la telemetría del agente se guarda en `debug_output/agent_console.json` para auditoría y debug.
- **Resiliencia**: Sistema de reintentos automático con backoff exponencial para comunicaciones con el backend.

## 🏗️ Arquitectura del Agente

El agente está dividido en componentes modulares:

1.  **Poller (Alert Feed)**: Consulta el Wazuh Indexer (OpenSearch) cada 2-10 segundos buscando deltas.
2.  **Inventory Poller**: Monitorea el estado de salud y conexión de los agentes de Wazuh.
3.  **Aggregator**: Transforma la data cruda en el formato unificado `finding` y calcula métricas.
4.  **Sender**: Comprime (gzip) y envía los reportes al backend mediante HTTPS.
5.  **State Store**: Gestiona la persistencia de los cursores de sincronización en SQLite.

## 🛠️ Configuración

Crea un archivo `.env` en la raíz del proyecto basado en `.env.example`:

```env
# Conexión Wazuh API
WAZUH_API_HOST=https://192.168.50.83:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=tu_password

# Conexión Wazuh Indexer
WAZUH_INDEXER_HOST=https://192.168.50.83:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=tu_password

# Configuración del Agente
POLL_INTERVAL_ALERTS=10
POLL_INTERVAL_AGENTS=60
MIN_RULE_LEVEL=7  # Solo alertas High/Critical
DRY_RUN=true      # Cambiar a false para enviar al backend

# Backend Ingest
TXDXAI_INGEST_URL=https://api.tu-backend.com/ingest
TXDXAI_COMPANY_ID=9
TXDXAI_API_KEY=tu_token_de_seguridad
```

## 🚀 Inicio Rápido

1.  **Instalar dependencias**:
    ```powershell
    pip install -r requirements.txt
    ```

2.  **Ejecutar el agente**:
    ```powershell
    python main.py
    ```

## 📂 Salidas y Reportes

- **Consola**: Muestra el flujo de sincronización, detecciones y salud del inventario.
- **Reportes Locales**: Si `DRY_RUN=true`, los JSON se guardan en `debug_output/report_*.json`.
- **Telemetría**: El historial completo se guarda en `debug_output/agent_console.json`.

---
*Desarrollado para la integración avanzada de SIEM y Dashboards de Seguridad.*