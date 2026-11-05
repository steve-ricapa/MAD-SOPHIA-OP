# Pendientes de operación MAD

**Actualizado:** 2026-11-05
**Estado de referencia:** `main` en `c75dffe` (local, `origin/main` y Nexus alineados).
**Operación actual:** `mad-6x.timer` activo cada hora; 5 integraciones (Nessus, Uptime Kuma, Zabbix, OpenVAS, Wazuh). InsightVM desactivado del ciclo horario.

## Prioridad alta

- [ ] **Validar el ciclo automático de las 19:00 y los siguientes.**
  Criterio: `systemctl is-active mad-6x.service` termina en `inactive`, `runtime/logs/last_run.status` con `global_failed=0` y `NRestarts=0`.
  Comandos sugeridos:
  ```bash
  systemctl list-timers mad-6x.timer
  journalctl -b -u mad-6x.service --since "2 hours ago"
  cat runtime/logs/last_run.status
  ```

- [ ] **Hacer durable la lectura del journal para `diego.ramos`.**
  Hoy funciona por ACL aplicada manualmente con `systemd-tmpfiles`. Confirmar persistencia tras reinicio; si no, agregar el usuario al grupo `systemd-journal`.
  ```bash
  getfacl /var/log/journal
  journalctl -b -u mad-6x.service   # como diego.ramos
  ```

- [ ] **Revisar restos de InsightVM.**
  El código y credenciales siguen instalados. Revisar si quedan payloads pendientes en `runtime/insightvm/queue` y decidir si se documentan o se limpian. `scripts/check_integrations.py` seguirá reportando 401 si se ejecuta manualmente.

## Prioridad media

- [ ] **Actualizar documentación desactualizada.**
  `docs/delivery-policy.md`, `docs/artifact-retention.md` y `README.md` aún describen 6 integraciones y un estado "no desplegado". Ajustar a 5 integraciones y al despliegue real.

- [ ] **Revisar `/var/backups`.**
  Hay un tar de aproximadamente 1,99 GB en `mad-policy-20261105-1320/runtime-queues-state.before.tar` y `myenv.backup` de 107 MB. Definir qué se conserva y qué se puede retirar.

- [ ] **Eliminar logs basura del 27 de agosto.**
  `runtime/logs/--log-level.log`, `runtime/logs/--once.log`, `runtime/logs/INFO.log`.

- [ ] **Evaluar alertas de fallo.**
  Hoy un fallo solo queda en journal. Opciones: `OnFailure=` en systemd o un chequeo periódico de `runtime/logs/last_run.status`.

## Prioridad baja

- [ ] **Ejecutar la suite de pruebas tras los cambios.**
  ```bash
  python -m pytest tests scripts/tests
  ```

## Reactivación de InsightVM

Rapid7 ya no permite trials mensuales. Si se recupera una licencia válida:

1. Re-agregar la línea `insightvm|insightVM_integration/main.py --once --log-level INFO` en `scripts/run_hourly.sh`.
2. Commit y `git pull` en el servidor.
3. No hace falta cambiar la unidad systemd: `Restart=no` se mantiene.

## Notas

- No guardar credenciales ni secretos en este archivo.
- Los manifiestos de limpieza están en `/var/backups/mad-cleanup-20261105-01/` y `/var/backups/mad-openvas-cleanup-20261105-01/`.
- Respaldo de configuración de journald: `/var/backups/mad-journald-20261105-01/`.
- Respaldo de la unidad systemd: `/var/backups/mad-unit-fix-20261105-01/`.
