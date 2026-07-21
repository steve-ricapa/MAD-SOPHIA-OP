# InsightVM / Rapid7 Agent

Agente Python para recolectar snapshots de InsightVM/Rapid7 y enviarlos al backend AWS de TxDxAI.

## Backend AWS

- `TXDXAI_INGEST_URL` debe apuntar a `/scans/upload-url`.
- `TXDXAI_TENANT_ID` identifica el tenant en AWS. Si no se define, se usa `TXDXAI_COMPANY_ID` como fallback.
- `TXDXAI_API_KEY_INSIGHTVM` debe ser una Agent API key activa para `insightvm`.

Flujo de envio:

1. El agente solicita una URL de subida al backend AWS.
2. El snapshot completo se sube con `PUT` a la URL prefirmada de S3.
3. AWS procesa el objeto desde S3 y crea summaries/findings.
