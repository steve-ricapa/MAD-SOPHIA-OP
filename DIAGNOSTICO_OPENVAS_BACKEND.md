# Diagnóstico de alternancia OpenVAS vs Backend (`201` / `timeout` / `500`)

Este checklist sirve para aislar si la falla viene del backend TXDXAI, de la red/TLS, o del flujo del cliente OpenVAS.

## 0. Preparación

Ejecutar desde la raíz del proyecto:

```bash
cd /root/MAD-SOPHIA-OP
```

Crear carpeta temporal para salidas:

```bash
mkdir -p /tmp/mad_diag
```

## 1. Probar backend con payload mínimo (sin OpenVAS)

Comando:

```bash
curl -k -sS -o /tmp/mad_diag/ingest_probe_body.txt -w "HTTP:%{http_code}\n" \
  -X POST "https://txdxai-flask.replit.app/api/scans/ingest" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Ver body de respuesta:

```bash
cat /tmp/mad_diag/ingest_probe_body.txt
```

Interpretación rápida:
- `HTTP:500`: probable problema del backend o validación interna del servidor.
- `HTTP:4xx`: backend alcanzable y validando contrato de entrada.
- `timeout` / error TLS: problema de red/TLS/intermitencia de conectividad.

## 2. Reenviar un payload real fallido (replay)

1. Ubicar un payload fallido reciente:

```bash
ls -lt openVAS_integration/artifacts/failed_payloads/payloads/
```

2. Reenviar ese payload (reemplaza `<archivo>.json`):

```bash
curl -k -sS -o /tmp/mad_diag/replay_body.txt -w "HTTP:%{http_code}\n" \
  -X POST "https://txdxai-flask.replit.app/api/scans/ingest" \
  -H "Content-Type: application/json" \
  --data-binary "@/root/MAD-SOPHIA-OP/openVAS_integration/artifacts/failed_payloads/payloads/<archivo>.json"
```

3. Ver body de respuesta:

```bash
cat /tmp/mad_diag/replay_body.txt
```

Interpretación rápida:
- Mismo payload siempre da `500`: problema backend o shape de ese payload.
- Mismo payload a veces `201` y a veces falla: intermitencia de red/TLS/backend.
- Siempre `201`: incidente previo transitorio.

## 3. Ejecutar OpenVAS en `--once` múltiples veces

Comando:

```bash
for i in 1 2 3 4 5; do
  echo "===== RUN $i ====="
  python3 /root/MAD-SOPHIA-OP/openVAS_integration/main.py --once
  sleep 2
done
```

Interpretación rápida:
- Todas `201`: flujo estable.
- Mezcla `201` + `500/timeout`: problema intermitente (normalmente externo al parser OpenVAS).
- Todas `500`: backend rechaza consistentemente.

## 4. Correlación por timestamp (clave para causa raíz)

Revisar en paralelo:

```bash
ls -lt runtime/diagnostics/
ls -lt openVAS_integration/artifacts/failed_payloads/logs/
ls -lt openVAS_integration/artifacts/failed_payloads/payloads/
```

Buscar errores relevantes:

```bash
rg -n "http_500|http_timeout|SSLEOFError|UNEXPECTED_EOF|status=201|Report sent" runtime/diagnostics -S
rg -n "http_500|http_timeout|SSLEOFError|UNEXPECTED_EOF|status=201|Report sent" openVAS_integration/artifacts -S
```

Qué confirmar:
- Si el `timestamp` del `500` coincide con un payload específico.
- Si el mismo payload luego entra con `201`.
- Si hay `SSLEOFError` cerca de los `timeout/500`.

## 5. Matriz de decisión final

- Caso A: `probe` y `replay` también fallan (`500`)
  - Diagnóstico: backend/contrato.
- Caso B: `probe` OK pero `replay` falla solo con ciertos payloads
  - Diagnóstico: contenido/estructura de payload puntual.
- Caso C: resultados alternan sin patrón (`201` unas veces, `500/timeout` otras)
  - Diagnóstico: intermitencia de red/TLS o inestabilidad del servicio backend.
- Caso D: todo estable en manual, pero falla solo en corrida orquestada
  - Diagnóstico: condición de concurrencia/carga al iniciar múltiples agentes.

## 6. Recomendaciones operativas

- Para pruebas aisladas usar opción `5` del menú (prueba una integración y salir).
- Evitar mezclar validación de OpenVAS con errores de Wazuh/Zabbix durante diagnóstico.
- Conservar evidencias por corrida (diagnostic report + payload + log con timestamp).

## 7. Seguridad

- No compartir `api_key` en texto plano.
- Si una key quedó expuesta en archivos compartidos, rotarla.
