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

## Enviar Data Real Al Backend

Para enviar data real al backend debes validar estas variables en tu `.env`:

- `TXDXAI_INGEST_URL`
- `TXDXAI_COMPANY_ID`
- `TXDXAI_API_KEY_<INTEGRACION>`

Ademas, cada integracion debe tener configurado su origen real:

- `openvas`: `COLLECTOR=gmp` y variables `GVM_*`
- `nessus`: `NESSUS_BASE_URL`, `NESSUS_ACCESS_KEY`, `NESSUS_SECRET_KEY`
- `uptimekuma`: `UPTIME_KUMA_URL`
- `zabbix`: `ZABBIX_API_URL`, `ZABBIX_USER`, `ZABBIX_PASS`
- `wazuh`: `WAZUH_API_*`, `WAZUH_INDEXER_*`
- `insightvm`: `INSIGHTVM_BASE_URL`, `INSIGHTVM_USER`, `INSIGHTVM_PASSWORD`

## Flujo Recomendado Desde El Menu

Si quieres probar una integracion y ver toda la data que consulta y arma antes de revisar el backend, usa el orquestador con modo diagnostico one-shot.

Ejecucion local:

```bash
py -3 app.py --agents openvas --diagnostic-single-run true
```

Ejecucion en Docker:

```bash
docker run -it --rm --name mad_diag --env-file .env app python app.py --agents openvas --diagnostic-single-run true
```

Opciones del menu global:

- `4`: Ejecutar pruebas de una integracion e iniciar luego los agentes seleccionados.
- `5`: Ejecutar pruebas de una integracion y salir.

Para inspeccionar una sola integracion, la opcion recomendada es `5`.

Luego el menu te pedira la integracion a probar, por ejemplo:

- `openvas`
- `nessus`
- `uptimekuma`
- `zabbix`
- `wazuh`
- `insightvm`

Con `--diagnostic-single-run true`, el orquestador ejecuta la integracion seleccionada en modo one-shot y deja artifacts para revisar lo que bajo del origen y lo que se preparo para enviar.

## Donde Ver La Data Generada

Artifacts globales del diagnostico del orquestador:

- `runtime/diagnostics/<timestamp>/diagnostic_report.json`
- `runtime/diagnostics/<timestamp>/`

Artifacts por integracion:

- `openvas`: `runtime/openvas/artifacts/`
- `nessus`: `runtime/nessus/`
- `uptimekuma`: `runtime/uptimekuma/`
- `zabbix`: `runtime/zabbix/`
- `wazuh`: `runtime/wazuh/artifacts/`
- `insightvm`: `runtime/insightvm/`

Archivos principales a revisar:

- raw del origen
- `debug_report.json` o `last_report_built.json`
- `last_payload_sent.json`
- `last_delivery_meta.json`

## OpenVAS Y Estados

OpenVAS ahora normaliza estados terminales antes del envio al backend:

- `Done` -> `completed`
- `Completed` -> `completed`
- `Running` -> `running`
- `Pending` -> `pending`

Ademas, OpenVAS ya no marca como enviado un reporte que siga `running` o `pending`. Eso evita que se registre una sola vez con estado incorrecto y nunca vuelva a reenviarse cuando termine.

## Guia Detallada De Artifacts

Para comandos por integracion y ubicaciones exactas de archivos, revisa tambien:

- `INTEGRATION_ARTIFACTS_GUIDE.md`

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
