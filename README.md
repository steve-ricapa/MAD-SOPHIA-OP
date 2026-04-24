# MAD-SOPHIA-OP

Stack de integraciones de seguridad/monitoreo ejecutadas con Docker Compose usando una sola imagen compartida.

## Resumen rapido

- Una imagen: `mad-sophia-op:latest`
- Seis servicios:
  - `wazuh`
  - `zabbix`
  - `openvas`
  - `insightvm`
  - `uptimekuma`
  - `nessus`
- Cada servicio corre en su propio contenedor con logs separados.
- Si un servicio falla, los demas siguen funcionando.

## Estructura de ejecucion

- `Dockerfile`: construye la imagen base con todas las dependencias.
- `docker-compose.yml`: levanta los 6 servicios con esa misma imagen.
- `.env`: configuracion real (secretos y tiempos).
- `.env.example`: plantilla documentada sin secretos.

## Requisitos

- Docker Engine + Docker Compose plugin (`docker compose`)
- Conectividad de red desde el host hacia tus fuentes:
  - Wazuh API/Indexer
  - Zabbix API
  - OpenVAS/GVMD
  - InsightVM API
  - Uptime Kuma
  - Nessus
  - Backend `TXDXAI_INGEST_URL`

## Configuracion de entorno

1. Copia la plantilla:

```bash
cp .env.example .env
```

2. Completa en `.env`:
- URLs/credenciales de cada integracion
- API keys de backend por integracion (`TXDXAI_API_KEY_*`)
- lapsos prefijados para Compose (`WAZUH_*`, `ZABBIX_*`, `OPENVAS_*`, `UPTIME_*`, `NESSUS_*`, `INSIGHTVM_*`)

3. Punto importante:
- En Compose ya se usan variables prefijadas para evitar colisiones.
- Si corres un agente manualmente (sin Compose), entonces usa sus variables locales (`POLL_INTERVAL_SECONDS`, `SCANNER_TYPE`, etc.).

## Modo real vs simulado (OpenVAS)

OpenVAS soporta dos modos en Compose:

- Real: `OPENVAS_COLLECTOR=gmp`
- Simulado: `OPENVAS_COLLECTOR=simulated`

Cambio rapido:

```bash
# en .env
OPENVAS_COLLECTOR=simulated

# aplicar
docker compose up -d openvas
```

## SCANNER_TYPE en Uptime y Nessus

En Compose no depende del `SCANNER_TYPE` global repetido:

- Uptime usa `UPTIME_SCANNER_TYPE` (default `uptimekuma`)
- Nessus usa `NESSUS_SCANNER_TYPE` (default `nessus`)

## Archivos runtime (state/debug) que vas a ver

Por diseno, los agentes generan archivos JSON locales.

- Utiles/operativos:
  - `state.json` o `state/agent_state.db`: deduplicacion/checkpoint.
  - `queue/*.json` o `failed_*.json`: reintentos cuando el backend falla.
- De debug/auditoria:
  - `debug_report.json`
  - `last_payload_sent.json`
  - `raw_*snapshot.json` / `artifacts/raw_batches/*.json`

Recomendacion:
- Mantener `state.*` y colas de retry.
- No versionar en Git snapshots/debug runtime.

## Despliegue

### Build + up (todo)

```bash
docker compose up -d --build
```

### Ver estado

```bash
docker compose ps
docker compose top
```

### Validar compose renderizado

```bash
docker compose config
```

## Operacion diaria (logs y control)

### Logs de todo

```bash
docker compose logs -f -t
```

### Logs por integracion

```bash
docker compose logs -f wazuh
docker compose logs -f zabbix
docker compose logs -f openvas
docker compose logs -f insightvm
docker compose logs -f uptimekuma
docker compose logs -f nessus
```

### Logs recientes

```bash
docker compose logs --since=10m wazuh
docker compose logs --tail=200 nessus
```

### Reiniciar un servicio

```bash
docker compose restart wazuh
```

### Recrear un servicio

```bash
docker compose up -d --force-recreate wazuh
```

### Levantar solo un servicio

```bash
docker compose up -d openvas
```

### Detener todo

```bash
docker compose down
```

## Troubleshooting rapido

### Un servicio no levanta

```bash
docker compose ps
docker compose logs --tail=300 <servicio>
docker compose restart <servicio>
```

### Ver variables activas dentro del contenedor

```bash
docker compose exec <servicio> sh -lc 'env | sort'
```

### Verificar API key cargada (sin mostrar valor)

```bash
docker compose exec wazuh sh -lc 'echo "LEN=${#TXDXAI_API_KEY_WAZUH}"'
```

### Wazuh: validar auth API

```bash
docker compose exec wazuh sh -lc 'curl -sk -u "$WAZUH_API_USER:$WAZUH_API_PASSWORD" "$WAZUH_API_HOST/security/user/authenticate?raw=true"'
```

### Si cambias dependencias/codigo base

```bash
docker compose build --no-cache
docker compose up -d
```

## Archivos de referencia

- [docker-compose.yml](./docker-compose.yml)
- [Dockerfile](./Dockerfile)
- [.env.example](./.env.example)
- [GUIA_DOCKER_COMPOSE.md](./GUIA_DOCKER_COMPOSE.md)
- [GUIA_LAPSOS_AGENTES.md](./GUIA_LAPSOS_AGENTES.md)
