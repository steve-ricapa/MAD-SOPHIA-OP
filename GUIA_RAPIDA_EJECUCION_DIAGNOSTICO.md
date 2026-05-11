# Guia Rapida: Ejecucion y Diagnostico MAD

## Comando base (menu)
Windows (PowerShell):
```powershell
py app.py
```
Linux:
```bash
python3 app.py
```

## Comando recomendado para pruebas
(Ejecuta tests + single-run, sin bloquear por fallos requeridos)

Windows:
```powershell
py app.py --startup-menu-enabled true --diagnostic-single-run true --startup-require-all-tests false
```
Linux:
```bash
python3 app.py --startup-menu-enabled true --diagnostic-single-run true --startup-require-all-tests false
```

## Que hace cada opcion del menu
1. `1`: tests de integraciones seleccionadas + inicia todos los agentes.
2. `2`: tests de integraciones seleccionadas y salir.
3. `3`: omite tests + inicia todos los agentes.
4. `4`: test de una integracion + single-run (si esta activo) + inicia todos.
5. `5`: test de una integracion + single-run (si esta activo) + salir.

## Flujo recomendado para diagnosticar una integracion
1. Ejecuta el comando recomendado.
2. Elige opcion `5`.
3. Escribe la integracion (ej: `openvas`).
4. Revisa consola + artifacts.

## Activar guardado de payloads (debug)
Activalo solo para pruebas.

Windows (OpenVAS):
```powershell
$env:OPENVAS_PAYLOAD_DEBUG="true"
```
Linux (OpenVAS):
```bash
export OPENVAS_PAYLOAD_DEBUG=true
```

Tambien disponible para: `WAZUH_PAYLOAD_DEBUG`, `ZABBIX_PAYLOAD_DEBUG`, `NESSUS_PAYLOAD_DEBUG`, `UPTIME_PAYLOAD_DEBUG`.

## Rutas de logs y artifacts
Diagnostico orquestador (opcion 5 con single-run):
- `C:\Users\diego\PROYECTOS\MAD-SOPHIA-OP\runtime\diagnostics\<timestamp>\`
- Archivos: `diagnostic_report.json`, `<integracion>.log`

Payload debug (si esta activado):
- OpenVAS: `runtime\payload_debug\openvas\`
- Wazuh: `runtime\payload_debug\wazuh\`
- Zabbix: `runtime\payload_debug\zabbix\`
- Nessus: `runtime\payload_debug\nessus\`
- UptimeKuma: `runtime\payload_debug\uptimekuma\`

Cada intento guarda:
- `payload_*.json`
- `meta_*.json` (status, response, longitudes, campos >255)
