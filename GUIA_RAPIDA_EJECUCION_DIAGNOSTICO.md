# Mini Guia Rapida: Ejecucion y Diagnostico MAD

## Comando recomendado (diagnostico completo)
```powershell
py -3.13 app.py --startup-menu-enabled true --diagnostic-single-run true --startup-require-all-tests false
```

## Flujo recomendado
1. Ejecuta el comando anterior.
2. En el menu, elige `4` (probar una integracion + continuar).
3. Escribe la integracion: `wazuh`, `zabbix`, `openvas`, `insightvm`, `uptimekuma`, `nessus` (o Enter para default que seria wazuh).
4. Revisa resultados en consola y en archivos.

## Que hace cada opcion del menu
1. `1`: Ejecuta pruebas de integraciones seleccionadas + inicia todos los agentes seleccionados.
2. `2`: Ejecuta pruebas de integraciones seleccionadas y termina el proceso.
3. `3`: Omite pruebas e inicia todos los agentes seleccionados.
4. `4`: Ejecuta pruebas de una sola integracion y luego continua (permite diagnostico single-run + arranque).
5. `5`: Ejecuta pruebas de una sola integracion y termina el proceso.

## Comandos utiles

### Ejecutar normal con menu
```powershell
py -3.13 app.py --startup-menu-enabled true
```

### Ejecutar diagnostico single-run
```powershell
py -3.13 app.py --startup-menu-enabled true --diagnostic-single-run true
```

### Forzar continuar aunque fallen pruebas (ideal para recolectar evidencia)
```powershell
py -3.13 app.py --startup-menu-enabled true --diagnostic-single-run true --startup-require-all-tests false
```

## Donde ver logs y reportes

### Diagnostico consolidado del orquestador
`C:\Users\diego\PROYECTOS\MAD-SOPHIA-OP\runtime\diagnostics\<timestamp>\`

Contenido esperado:
- `diagnostic_report.json`
- `<integracion>.log` (ej. `wazuh.log`, `openvas.log`)

### Artefactos internos por agente
- Wazuh: `C:\Users\diego\PROYECTOS\MAD-SOPHIA-OP\runtime\wazuh\artifacts\...`
- Otras integraciones: subcarpetas en `runtime\...` segun agente.

## Nota importante
Si eliges opcion `5`, el proceso termina despues de la prueba unica y no llega al bloque que genera el diagnostico single-run.
