# MAD-SOPHIA-OP

Plataforma de integraciones de seguridad/monitoreo con una sola imagen compartida.

Soporta dos modos:
- `docker compose`: un contenedor por integracion.
- `app.py` orquestador: un solo contenedor/proceso padre que levanta todas las integraciones internamente.

## Indice

1. [Arquitectura](#arquitectura)
2. [Servicios](#servicios)
3. [Requisitos](#requisitos)
4. [Estructura del repositorio](#estructura-del-repositorio)
5. [Modelo de entorno-env](#modelo-de-entorno-env)
6. [Configuracion inicial](#configuracion-inicial)
7. [Despliegue](#despliegue)
8. [Arranque Interno 1 Comando](#arranque-interno-1-comando)
9. [Operacion diaria](#operacion-diaria)
10. [Lapsos de ejecucion](#lapsos-de-ejecucion)
11. [Modos y variables sensibles](#modos-y-variables-sensibles)
12. [Troubleshooting](#troubleshooting)
13. [Buenas practicas](#buenas-practicas)
14. [Documentacion relacionada](#documentacion-relacionada)

## Arquitectura

- Una sola imagen Docker: `mad-sophia-op:latest`.
- Modo A: seis contenedores (un proceso por integracion) con Compose.
- Modo B: un contenedor con `app.py` levantando todos los agentes internamente.
- Un `.env` general en raiz.
- Variables prefijadas en Compose para evitar colisiones.

## Servicios

- `wazuh`
- `zabbix`
- `openvas`
- `insightvm`
- `uptimekuma`
- `nessus`

Si un servicio falla en runtime, los demas siguen activos.

## Requisitos

- Docker Engine + Docker Compose plugin (`docker compose`).
- Conectividad de red hacia:
  - Wazuh API e Indexer.
  - Zabbix API.
  - OpenVAS/GVMD.
  - InsightVM API.
  - Uptime Kuma.
  - Nessus.
  - Backend `TXDXAI_INGEST_URL`.

## Estructura del repositorio

- `Dockerfile`: construye la imagen unica.
- `docker-compose.yml`: orquesta los 6 servicios.
- `.env`: configuracion real (no versionada).
- `.env.example`: plantilla oficial documentada (sin secretos).
- `GUIA_DOCKER_COMPOSE.md`: operacion y comandos Compose.
- `GUIA_LAPSOS_AGENTES.md`: defaults y ubicacion de lapsos en codigo.

## Modelo de entorno (.env)

Hay dos capas de variables:

1. Variables prefijadas para Docker Compose (recomendado):
- `WAZUH_*`, `ZABBIX_*`, `OPENVAS_*`, `INSIGHTVM_*`, `UPTIME_*`, `NESSUS_*`.
- Evitan que una variable global pise otra.

2. Variables locales por integracion (modo manual):
- Ejemplos: `POLL_INTERVAL_SECONDS`, `SCANNER_TYPE`, `OUTPUT_MODE`.
- Se usan cuando ejecutas un agente sin Compose.

Plantilla base:

```bash
cp .env.example .env
```

## Configuracion inicial

1. Copia `.env.example` a `.env`.
2. Completa hosts, usuarios, passwords y `TXDXAI_API_KEY_*`.
3. Ajusta company ID (`TXDXAI_COMPANY_ID`) segun tu tenant.
4. Define lapsos prefijados para Compose si quieres sobreescribir defaults.

## Despliegue

Validar config renderizada:

```bash
docker compose config
```

Build + levantar todo:

```bash
docker compose up -d --build
```

## Arranque Interno 1 Comando

Si quieres que todo MAD se levante desde un solo comando y dentro de un solo contenedor:

```bash
docker build -t mad-sophia-op:latest .
docker run -d --name mad_all --env-file .env mad-sophia-op:latest
```

Notas:
- El `Dockerfile` ahora usa `AGENT_PATH=app.py` por defecto.
- `app.py` inicia internamente: `wazuh`, `zabbix`, `openvas`, `insightvm`, `uptimekuma`, `nessus`.
- Si quieres correr solo algunos agentes en modo interno:

```bash
docker run -d --name mad_partial --env-file .env -e MAD_AGENTS=wazuh,zabbix,openvas mad-sophia-op:latest
```

- Si necesitas volver al modo de un solo agente:

```bash
docker run -d --name mad_wazuh_only --env-file .env -e AGENT_PATH=wazuh_integration/main.py mad-sophia-op:latest
```

Estado:

```bash
docker compose ps
docker compose top
```

Detener stack:

```bash
docker compose down
```

## Operacion diaria

Logs de todo el stack:

```bash
docker compose logs -f -t
```

Logs por servicio:

```bash
docker compose logs -f wazuh
docker compose logs -f zabbix
docker compose logs -f openvas
docker compose logs -f insightvm
docker compose logs -f uptimekuma
docker compose logs -f nessus
```

Reiniciar un servicio:

```bash
docker compose restart <servicio>
```

Recrear un servicio:

```bash
docker compose up -d --force-recreate <servicio>
```

Levantar un subconjunto:

```bash
docker compose up -d wazuh zabbix insightvm uptimekuma nessus
```

## Lapsos de ejecucion

Perfil recomendado (balanceado):

- Wazuh: `WAZUH_POLL_INTERVAL_ALERTS=60`, `WAZUH_POLL_INTERVAL_AGENTS=600`
- Zabbix: `ZABBIX_INTERVAL=180`
- OpenVAS: `OPENVAS_POLL_SECONDS=600`
- InsightVM: `INSIGHTVM_INTERVAL_SECONDS=600`
- Uptime Kuma: `UPTIME_POLL_INTERVAL_SECONDS=120`, `UPTIME_FORCE_SEND_EVERY_CYCLES=15`
- Nessus: `NESSUS_POLL_INTERVAL_SECONDS=600`, `NESSUS_FORCE_SEND_EVERY_CYCLES=6`

Detalle tecnico completo de defaults y uso en loops:
- Ver `GUIA_LAPSOS_AGENTES.md`.

## Modos y variables sensibles

OpenVAS:

- Real: `OPENVAS_COLLECTOR=gmp`
- Simulado: `OPENVAS_COLLECTOR=simulated`

Uptime y Nessus (scanner type):

- Compose: usar `UPTIME_SCANNER_TYPE` y `NESSUS_SCANNER_TYPE`.
- Manual: usar `SCANNER_TYPE` en cada integracion.

Uptime Kuma auth:

- API Keys habilitadas: usar `UPTIME_KUMA_API_KEY_ID` + `UPTIME_KUMA_API_KEY`.
- Sin API Keys: usar `UPTIME_KUMA_USERNAME` + `UPTIME_KUMA_PASSWORD`.

## Troubleshooting

Servicio caido:

```bash
docker compose ps
docker compose logs --tail=300 <servicio>
docker compose restart <servicio>
```

Ver env dentro de contenedor:

```bash
docker compose exec <servicio> sh -lc 'env | sort'
```

Validar que API key cargo (sin exponer valor):

```bash
docker compose exec wazuh sh -lc 'echo "LEN=${#TXDXAI_API_KEY_WAZUH}"'
docker compose exec nessus sh -lc 'echo "LEN=${#TXDXAI_API_KEY_NESSUS}"'
docker compose exec uptimekuma sh -lc 'echo "LEN=${#TXDXAI_API_KEY_UPTIMEKUMA}"'
```

Wazuh auth 401:

```bash
docker compose exec wazuh sh -lc 'curl -sk -u "$WAZUH_API_USER:$WAZUH_API_PASSWORD" "$WAZUH_API_HOST/security/user/authenticate?raw=true"'
```

Rebuild limpio:

```bash
docker compose build --no-cache
docker compose up -d
```

## Buenas practicas

- No subir secretos reales al repo.
- Mantener `.env` en local y versionar solo `.env.example`.
- No versionar archivos runtime (`state`, `queue`, `debug_report`, `raw_snapshot`).
- Rotar credenciales si se exponen accidentalmente.

## Documentacion relacionada

- [Guia Docker Compose](./GUIA_DOCKER_COMPOSE.md)
- [Guia de Lapsos](./GUIA_LAPSOS_AGENTES.md)
- [Plantilla de entorno](./.env.example)
- [Compose](./docker-compose.yml)
- [Dockerfile](./Dockerfile)
