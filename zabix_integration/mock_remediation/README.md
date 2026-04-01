# Mock remediation flow

Este directorio permite probar el flujo `finding -> ticket mock -> ejecucion de Victor` sin depender aun del backend.

## Archivos

- `build_mock_tickets.py`: transforma `debug_report.json` en tickets mock accionables.
- `test_remediation_flow.py`: ejecuta una simulacion `dry-run` de Victor sobre esos tickets.
- `run_mcp_read_only.py`: consulta el MCP real de Zabbix en modo solo lectura y resuelve IDs/contexto runtime.
- `execute_ack_remediation.py`: ejecuta la primera remediacion real segura usando `event_acknowledge`.
- `mock_tickets.json`: salida generada con tickets pendientes.
- `mock_execution_results.json`: resultado de la simulacion.
- `mcp_read_only_results.json`: resultado de validacion real contra el MCP.
- `mcp_write_results.json`: evidencia de la primera accion write segura.

## Uso

```bash
python mock_remediation/build_mock_tickets.py
python mock_remediation/test_remediation_flow.py
python mock_remediation/run_mcp_read_only.py
python mock_remediation/execute_ack_remediation.py
```

## Criterio actual

- `active_trigger` -> ticket `PENDING` con aprobacion requerida.
- `informational_trigger` -> ticket `PENDING` para validacion/documentacion.
- `health_summary` -> no genera ticket por ahora.

La idea es reemplazar luego el `dry-run` por llamadas reales al MCP de Zabbix.

## Modo read-only

`run_mcp_read_only.py` usa el modulo real del MCP ubicado en `ZABIXMCPAG/zabbix-mcp-server/src`, configura `READ_ONLY=true` y ejecuta consultas reales como `host_get`, `trigger_get`, `problem_get`, `event_get` e `item_get`.
