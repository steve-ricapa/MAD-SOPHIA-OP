# MAD-SOPHIA-OP

Plataforma de integraciones de seguridad y monitoreo empaquetada en una sola imagen Docker.

## Estrategia de ejecucion

- Unico servicio.
- Sin orquestador adicional.
- Configuracion por entorno en runtime con `--env-file .env`.
- Imagen agnostica: no contiene secretos ni `.env`.

## Integraciones incluidas

- `wazuh`
- `zabbix`
- `openvas`
- `insightvm`
- `uptimekuma`
- `nessus`

## Requisitos

- Docker Engine.
- Conectividad de red hacia los endpoints de cada integracion.

## Archivos clave

- `Dockerfile`: imagen base para todas las integraciones.
- `.env`: variables locales (no versionado).
- `.env.example`: plantilla de variables sin secretos.
- `app.py`: orquestador interno para ejecutar multiples integraciones.
- `GUIA_LAPSOS_AGENTES.md`: referencia de lapsos/defaults.

## Build

```bash
docker build -t app .
```

## Run (orquestador completo)

```bash
docker run -d --name mad_all --env-file .env -p 8000:8000 app
```

## Run (una integracion)

Ejemplo Wazuh:

```bash
docker run -d --name mad_wazuh --env-file .env -p 8000:8000 -e AGENT_PATH=wazuh_integration/main.py app
```

Ejemplo Zabbix:

```bash
docker run -d --name mad_zabbix --env-file .env -e AGENT_PATH=zabix_integration/agent.py app
```

## Logs y estado

```bash
docker logs -f mad_all
docker ps
```

## Buenas practicas

- No subir secretos reales al repo.
- Versionar solo `.env.example`.
- Rotar credenciales si alguna se expuso.
- Mantener runtime artifacts fuera de git.
