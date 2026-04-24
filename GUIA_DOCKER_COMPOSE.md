# Guia Docker Compose (operacion)

Esta guia cubre comandos operativos para el stack completo.

## Modelo

- Una sola imagen compartida: `mad-sophia-op:latest` (o `AGENT_IMAGE`).
- Seis servicios:
  - `wazuh`
  - `zabbix`
  - `openvas`
  - `insightvm`
  - `uptimekuma`
  - `nessus`

## Comandos base

### Validar compose

```bash
docker compose config
```

### Build + levantar todo

```bash
docker compose up -d --build
```

### Ver estado

```bash
docker compose ps
docker compose top
```

### Bajar todo

```bash
docker compose down
```

## Logs

### Todo el stack

```bash
docker compose logs -f -t
```

### Por integracion

```bash
docker compose logs -f wazuh
docker compose logs -f zabbix
docker compose logs -f openvas
docker compose logs -f insightvm
docker compose logs -f uptimekuma
docker compose logs -f nessus
```

### Recientes / acotados

```bash
docker compose logs --since=10m wazuh
docker compose logs --tail=200 openvas
```

## Control de servicios

### Reiniciar uno

```bash
docker compose restart wazuh
```

### Levantar uno puntual

```bash
docker compose up -d openvas
```

### Recrear uno puntual

```bash
docker compose up -d --force-recreate openvas
```

## Debug rapido cuando uno falla

### 1) Estado + error del servicio

```bash
docker compose ps
docker compose logs --tail=300 <servicio>
```

### 2) Ver variables activas dentro del contenedor

```bash
docker compose exec <servicio> sh -lc 'env | sort'
```

### 3) Verificar largo de API key sin exponer valor

```bash
docker compose exec wazuh sh -lc 'echo ${#TXDXAI_API_KEY_WAZUH}'
docker compose exec nessus sh -lc 'echo ${#TXDXAI_API_KEY_NESSUS}'
docker compose exec uptimekuma sh -lc 'echo ${#TXDXAI_API_KEY_UPTIMEKUMA}'
```

### 4) Rebuild limpio cuando sospechas imagen/cache roto

```bash
docker compose build --no-cache
docker compose up -d
```

## Cambios frecuentes en `.env`

### OpenVAS real vs simulado

```env
OPENVAS_COLLECTOR=gmp        # real
# OPENVAS_COLLECTOR=simulated  # demo/lab
```

Aplicar:

```bash
docker compose up -d openvas
```

### Cambiar lapsos

```env
WAZUH_POLL_INTERVAL_ALERTS=60
ZABBIX_INTERVAL=180
OPENVAS_POLL_SECONDS=600
UPTIME_POLL_INTERVAL_SECONDS=120
NESSUS_POLL_INTERVAL_SECONDS=600
INSIGHTVM_INTERVAL_SECONDS=600
```

Aplicar:

```bash
docker compose up -d
```

### Uptime scanner_type

```env
UPTIME_SCANNER_TYPE=uptimekuma
```

## Healthcheck

Wazuh expone healthcheck:

```bash
curl -s http://localhost:18080/health
```

Si cambias puerto host:

```env
WAZUH_HEALTH_HOST_PORT=28080
```
