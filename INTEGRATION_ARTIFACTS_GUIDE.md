# Guia De Artifacts De Integraciones

Esta guia explica como correr cada integracion una sola vez y donde revisar la data cruda consultada, el payload armado para el backend y la metadata del envio.

## Regla General

- La evidencia persistente queda por defecto bajo `runtime/<integracion>/`.
- El archivo principal para validar lo que se enviara al backend es `last_payload_sent.json`.
- El archivo principal para validar el resultado del envio es `last_delivery_meta.json`.
- La data cruda del origen se guarda como snapshots JSON, lotes archivados o XML crudo segun la integracion.

## OpenVAS

Comando:

```powershell
$env:OPENVAS_OUTPUT_MODE='console'; $env:OPENVAS_COLLECTOR='simulated'; py -3 "openVAS_integration\main.py" --once
```

Para una corrida real, cambia `OPENVAS_COLLECTOR='gmp'` y usa las credenciales GMP de `openVAS_integration/.env`.

Archivos:

- `runtime/openvas/artifacts/last_tasks.xml`
- `runtime/openvas/artifacts/last_report.xml`
- `runtime/openvas/artifacts/last_report_built.json`
- `runtime/openvas/artifacts/last_payload_sent.json`
- `runtime/openvas/artifacts/last_delivery_meta.json`

Opcional para historico HTTP:

```powershell
$env:OPENVAS_PAYLOAD_DEBUG='true'
```

Eso crea archivos bajo `runtime/payload_debug/openvas/`.

## Nessus

Comando:

```powershell
py -3 "nessus_integration\main.py" --once
```

Archivos:

- `runtime/nessus/raw_scans_snapshot.json`
- `runtime/nessus/debug_report.json`
- `runtime/nessus/last_payload_sent.json`
- `runtime/nessus/last_delivery_meta.json`
- `runtime/nessus/state.json`
- `runtime/nessus/queue/`

Opcional para historico HTTP:

```powershell
$env:NESSUS_PAYLOAD_DEBUG='true'
```

## Uptime Kuma

Comando:

```powershell
py -3 "uptimekuma_integration\agent.py" --once
```

Archivos:

- `runtime/uptimekuma/raw_monitors_snapshot.json`
- `runtime/uptimekuma/debug_report.json`
- `runtime/uptimekuma/last_payload_sent.json`
- `runtime/uptimekuma/last_delivery_meta.json`
- `runtime/uptimekuma/state.json`
- `runtime/uptimekuma/queue/`

Opcional para historico HTTP:

```powershell
$env:UPTIME_PAYLOAD_DEBUG='true'
```

## Zabbix

Comando:

```powershell
py -3 "zabix_integration\agent.py" --once
```

Archivos:

- `runtime/zabbix/raw_snapshot.json`
- `runtime/zabbix/debug_report.json`
- `runtime/zabbix/last_payload_sent.json`
- `runtime/zabbix/last_delivery_meta.json`
- `runtime/zabbix/state.json`

Opcional para historico HTTP:

```powershell
$env:ZABBIX_PAYLOAD_DEBUG='true'
```

## Wazuh

Comando:

```powershell
$env:STARTUP_MENU_ENABLED='false'; py -3 "wazuh_integration\main.py" --once
```

Archivos:

- `runtime/wazuh/artifacts/last_raw_snapshot.json`
- `runtime/wazuh/artifacts/last_payload_sent.json`
- `runtime/wazuh/artifacts/last_delivery_meta.json`
- `runtime/wazuh/artifacts/raw_batches/`
- `runtime/wazuh/artifacts/payloads/`
- `runtime/wazuh/artifacts/failed_payloads/`
- `runtime/wazuh/artifacts/logs/`

Opcional para historico HTTP:

```powershell
$env:WAZUH_PAYLOAD_DEBUG='true'
```

## InsightVM

Comando:

```powershell
py -3 "insightVM_integration\main.py"
```

Archivos:

- `runtime/insightvm/security_data.json`
- `runtime/insightvm/security_data_normalized.json`
- `runtime/insightvm/last_payload_sent.json`
- `runtime/insightvm/last_delivery_meta.json`
- `runtime/insightvm/assets_table.csv`
- `runtime/insightvm/assets_table.json`
- `runtime/insightvm/state.json`

## Flujo Rapido De Validacion

Cuando quieras validar una corrida, revisa los archivos en este orden:

1. Archivo raw del origen.
2. `debug_report.json` o `last_report_built.json`.
3. `last_payload_sent.json`.
4. `last_delivery_meta.json`.

Si el payload esta bien pero el backend guarda algo distinto, entonces el problema ya no esta en la integracion. Esta en la transformacion o persistencia del backend.

## Manejo De Estados En OpenVAS

OpenVAS ahora normaliza estados terminales antes del envio:

- `Done` -> `completed`
- `Completed` -> `completed`
- `Running` -> `running`
- `Pending` -> `pending`

OpenVAS ademas ya no marca un reporte como enviado mientras sigue en estado no terminal (`running` o `pending`). Eso evita que un scan quede registrado una sola vez con el estado incorrecto y nunca vuelva a enviarse al completar.
