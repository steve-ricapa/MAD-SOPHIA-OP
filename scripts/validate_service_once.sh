#!/usr/bin/env bash
# Prueba real con la identidad y los overrides de la unidad instalada.
# No habilita el timer. --send-once autoriza envios y reenvios configurados.
set -euo pipefail

if [ "${1:-}" = "--help" ]; then
  echo "Uso: sudo bash scripts/validate_service_once.sh --send-once"
  echo "Valida accesos y ejecuta un ciclo real; puede vaciar colas configuradas."
  echo "El timer debe estar detenido y no se habilita al finalizar."
  exit 0
fi
if [ "$#" -ne 1 ] || [ "$1" != "--send-once" ]; then
  echo "Se requiere --send-once. Usa --help para consultar el alcance." >&2
  exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "Ejecutar como administrador para validar la unidad instalada." >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVICE=mad-6x.service
TIMER=mad-6x.timer
cd "$REPO"

if [ "$(git -c safe.directory="$REPO" branch --show-current)" != "main" ]; then
  echo "El despliegue debe estar en main antes de validar." >&2
  exit 2
fi
# Los estados, comprobantes y otros datos operativos pueden cambiar en cada ciclo.
# La validacion exige integridad del codigo y sus plantillas de configuracion.
SOURCE_PATHS=(
  ':(glob)**/*.py'
  ':(glob)**/*.sh'
  ':(glob)**/*.service'
  ':(glob)**/*.timer'
  ':(glob)**/.env.example'
  ':(glob)**/.env.template'
  ':(glob)**/requirements*.txt'
  ':(glob)**/Dockerfile*'
  ':(glob)**/Makefile'
  ':(glob)**/*.toml'
  ':(glob)**/*.ini'
  ':(glob)**/*.cfg'
  ':(glob)**/*.conf'
  ':(glob)**/*.yaml'
  ':(glob)**/*.yml'
  ':(top).gitignore'
  ':(top).dockerignore'
  ':(glob)wazuh_integration/config_profiles/*.env'
)
if ! git -c safe.directory="$REPO" -c core.filemode=false diff --quiet -- "${SOURCE_PATHS[@]}" || \
   ! git -c safe.directory="$REPO" -c core.filemode=false diff --cached --quiet -- "${SOURCE_PATHS[@]}"; then
  echo "Hay cambios de codigo o plantillas locales o preparados para commit; reconciliarlos antes de validar." >&2
  exit 2
fi
if [ "$(systemctl show "$SERVICE" -p LoadState --value)" != "loaded" ]; then
  echo "La unidad mad-6x.service no esta instalada." >&2
  exit 2
fi
if [ "$(systemctl show "$TIMER" -p ActiveState --value)" != "inactive" ]; then
  echo "Detener mad-6x.timer antes de la prueba." >&2
  exit 2
fi
case "$(systemctl show "$SERVICE" -p ActiveState --value)" in
  inactive|failed) ;;
  *) echo "Detener el servicio antes de la prueba." >&2; exit 2 ;;
esac
if [ "$(systemctl show "$SERVICE" -p WorkingDirectory --value)" != "$REPO" ]; then
  echo "WorkingDirectory no coincide con este despliegue." >&2
  exit 2
fi
case "$(systemctl show "$SERVICE" -p ExecStart --value)" in
  *"$REPO/scripts/run_hourly.sh"*) ;;
  *) echo "ExecStart no apunta al orquestador de este despliegue." >&2; exit 2 ;;
esac
case "$(systemctl show "$SERVICE" -p Requires -p Wants -p BindsTo --value)" in
  *"$TIMER"*) echo "Quitar la dependencia del servicio al timer antes de probar." >&2; exit 2 ;;
esac

SERVICE_USER="$(systemctl show "$SERVICE" -p User --value)"
SERVICE_USER="${SERVICE_USER:-root}"
SERVICE_GROUP="$(systemctl show "$SERVICE" -p Group --value)"
SERVICE_GROUP="${SERVICE_GROUP:-$(id -gn "$SERVICE_USER")}"
PY="$REPO/myenv/bin/python3"
if [ ! -x "$PY" ]; then
  echo "No se encontro myenv/bin/python3; preparar el venv antes de validar." >&2
  exit 2
fi

runuser -u "$SERVICE_USER" -g "$SERVICE_GROUP" -- "$PY" -B \
  "$SCRIPT_DIR/check_integrations.py" --env "$REPO/.env" --service-user "$SERVICE_USER"

OVERRIDE_DIR="/run/systemd/system/$SERVICE.d"
OVERRIDE_FILE=""
override_created=0
cycle_started=0
cleanup() {
  local code=$?
  trap - EXIT INT TERM
  if [ "$cycle_started" -eq 1 ]; then
    if ! systemctl stop "$SERVICE"; then code=1; fi
  fi
  if [ "$override_created" -eq 1 ]; then
    if ! rm -f -- "$OVERRIDE_FILE"; then code=1; fi
    if ! systemctl daemon-reload; then code=1; fi
  fi
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

install -d -m 0755 "$OVERRIDE_DIR"
OVERRIDE_FILE="$(mktemp "$OVERRIDE_DIR/zz-recovery-once-XXXXXX.conf")"
override_created=1
printf '[Service]\nRestart=no\n' > "$OVERRIDE_FILE"
chmod 0644 "$OVERRIDE_FILE"
systemctl daemon-reload
if [ "$(systemctl show "$SERVICE" -p Restart --value)" != "no" ]; then
  echo "No se pudo desactivar el reintento automatico durante la prueba." >&2
  exit 2
fi
# Volver a comprobar el timer tras las validaciones de red y permisos.
if [ "$(systemctl show "$TIMER" -p ActiveState --value)" != "inactive" ]; then
  echo "El timer cambio de estado durante la validacion; no se ejecutara el ciclo." >&2
  exit 2
fi

STARTED_AT="$("$PY" -B -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat())')"
echo "Inicio de validacion real: $STARTED_AT"
cycle_started=1
cycle_code=0
systemctl start "$SERVICE" || cycle_code=$?
delivery_code=0
runuser -u "$SERVICE_USER" -g "$SERVICE_GROUP" -- "$PY" -B \
  "$SCRIPT_DIR/check_deliveries.py" --env "$REPO/.env" --since "$STARTED_AT" || delivery_code=$?

if [ "$cycle_code" -ne 0 ] || [ "$delivery_code" -ne 0 ]; then
  echo "FAIL: revisar runtime/logs y journalctl -u $SERVICE --since '$STARTED_AT'." >&2
  echo "El timer permanece detenido. No se ha confirmado la recuperacion." >&2
  exit 1
fi
echo "PASS: ciclo y seis comprobantes recientes validados. Confirmar procesamiento en AWS/SOPHIA."
echo "El timer sigue detenido; su activacion queda a cargo del administrador."
