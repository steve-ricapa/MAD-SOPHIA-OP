# Guia de lapsos (intervalos) por agente

Este documento deja claro que variable cambia el tiempo de ejecucion de cada integracion, donde esta el valor default en codigo y donde se usa en el loop.

## Wazuh

- Variable: `POLL_INTERVAL_ALERTS` (default `30`)
  - Default en codigo: `wazuh_integration/main.py:276`
  - Uso en loop: `wazuh_integration/main.py:203`
- Variable: `POLL_INTERVAL_AGENTS` (default `60`)
  - Default en codigo/uso: `wazuh_integration/main.py:236`
- Variable: `RETRY_FAILED_INTERVAL_SECONDS` (default `30`)
  - Default en codigo: `wazuh_integration/main.py:279`
  - Uso en loop: `wazuh_integration/main.py:78`
- Variable: `HEARTBEAT_EMPTY_CYCLES` (default `6`)
  - Default en codigo: `wazuh_integration/main.py:282`
  - Impacto: heartbeat cada `POLL_INTERVAL_ALERTS * HEARTBEAT_EMPTY_CYCLES` cuando no hay eventos.

## Zabbix

- Variable: `INTERVAL` (default `60`)
  - Default en codigo: `zabix_integration/config.py:66`
  - Uso en loop: `zabix_integration/agent.py:125`

## Uptime Kuma

- Variable: `POLL_INTERVAL_SECONDS` (default `15`)
  - Default en codigo: `uptimekuma_integration/config.py:80`
  - Uso en loop: `uptimekuma_integration/agent.py:143`
- Variable: `FORCE_SEND_EVERY_CYCLES` (default `6`)
  - Default en codigo: `uptimekuma_integration/config.py:85`
  - Impacto: envio forzado cada `POLL_INTERVAL_SECONDS * FORCE_SEND_EVERY_CYCLES` aunque no haya cambios.

## Nessus

- Variable: `POLL_INTERVAL_SECONDS` (default `60`)
  - Default en codigo: `nessus_integration/config.py:92`
  - Uso en loop: `nessus_integration/agent.py:156`
- Variable: `FORCE_SEND_EVERY_CYCLES` (default `10`)
  - Default en codigo: `nessus_integration/config.py:97`
  - Impacto: envio forzado cada `POLL_INTERVAL_SECONDS * FORCE_SEND_EVERY_CYCLES`.

## OpenVAS

- Variable: `POLL_SECONDS` (default `10`)
  - Default en codigo: `openVAS_integration/config.py:34`
  - Uso en loop: `openVAS_integration/main.py:490`

## InsightVM

- Variable CLI: `--interval` (default `0`)
  - Default en codigo: `insightVM_integration/main.py:65`
  - Uso en loop: `insightVM_integration/main.py:80`
- Nota: con `--interval 0` corre una sola vez y termina.

## Perfil recomendado (balanceado)

Estos valores bajan consumo sin perder visibilidad:

- Wazuh: `POLL_INTERVAL_ALERTS=60`, `POLL_INTERVAL_AGENTS=600`, `RETRY_FAILED_INTERVAL_SECONDS=60`, `HEARTBEAT_EMPTY_CYCLES=10`
- Zabbix: `INTERVAL=180`
- Uptime Kuma: `POLL_INTERVAL_SECONDS=120`, `FORCE_SEND_EVERY_CYCLES=15`
- Nessus: `POLL_INTERVAL_SECONDS=600`, `FORCE_SEND_EVERY_CYCLES=6`
- OpenVAS: `POLL_SECONDS=600`
- InsightVM: ejecutar con `--interval 600`

## Si usas un .env general unico

- Evita repetir nombres globales como `POLL_INTERVAL_SECONDS` para distintos agentes.
- Recomendado: prefijos por agente en el `.env` general (`WAZUH_*`, `NESSUS_*`, etc.) y usarlos directamente en cada integracion.

