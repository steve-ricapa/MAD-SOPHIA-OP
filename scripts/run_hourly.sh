#!/usr/bin/env bash
#
# run_hourly.sh
# ------------
# Orquestador horario de las 6 integraciones MAD-SOPHIA-OP.
#
# - Detecta automaticamente un Python valido (venv del repo o python3 global).
# - Corre cada integracion con --once (un solo ciclo) usando el smart-cache
#   existente (state.json + decide_snapshot_send): si el snapshot no cambio,
#   el agente no envia nada (excepto heartbeat forzado por FORCE_SEND_EVERY_CYCLES).
# - Protege contra solapamientos con flock por integracion.
# - Escalona ligeramente los lanzamientos para no golpear todos los sistemas
#   y el backend al mismo tiempo.
# - Devuelve codigo de salida GLOBAL != 0 si alguna integracion fallo, para que
#   un systemd unit Type=oneshot se marque como failed de forma fiable.
#
# Uso:
#   bash scripts/run_hourly.sh            # corre todo
#   bash scripts/run_hourly.sh --dry-run  # solo imprime que lanzaria, sin ejecutar
#   INV_ONLY=nessus bash scripts/run_hourly.sh   # solo nessus (debug)

set -u

# --- Argumento opcional --dry-run -------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    --dry-run|-n) export MAD_DRY_RUN=1 ;;
    *) echo "[run_hourly] Argumento desconocido ignorado: $arg" >&2 ;;
  esac
done
# --- fin dry-run ----------------------------------------------------------------
# ---------------------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------------------
# Directorio raiz del repo: carpeta padre de scripts/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$REPO_DIR/runtime/logs"
LOCK_DIR="${MAD_LOCK_DIR:-/var/lock}/mad"
STATUS_FILE="$LOG_DIR/last_run.status"

mkdir -p "$LOG_DIR"
mkdir -p "$LOCK_DIR"

# ---------------------------------------------------------------------------
# Deteccion de Python (venv del repo o python3 global)
# ---------------------------------------------------------------------------
detect_python() {
  local p
  for p in \
    "$REPO_DIR/myenv/bin/python3" \
    "$REPO_DIR/venv/bin/python3" \
    "$REPO_DIR/.venv/bin/python3"; do
    if [ -x "$p" ]; then
      echo "$p"
      return 0
    fi
  done
  if command -v python3 >/dev/null 2>&1; then
    echo "$(command -v python3)"
    return 0
  fi
  return 1
}

PY="$(detect_python)" || {
  echo "[run_hourly] ERROR: no se encontro un Python valido (venv del repo o python3)." >&2
  exit 1
}
echo "[run_hourly] Python: $PY"
echo "[run_hourly] Repo:   $REPO_DIR"

# ---------------------------------------------------------------------------
# LOGS: rotacion interna basica (mantener ~5 archivos por integracion)
# ---------------------------------------------------------------------------
rotate_log() {
  local log="$1"
  local max=5
  [ -f "$log" ] || return 0
  # rotar solo si supera ~5MB
  local size=0
  size="$(wc -c < "$log" 2>/dev/null || echo 0)"
  if [ "${size:-0}" -ge 5242880 ]; then
    local i
    for i in $(seq "$max" -1 1); do
      if [ -f "$log.$i" ]; then
        if [ "$i" -eq "$max" ]; then rm -f "$log.$i"; else mv "$log.$i" "$log.$((i+1))"; fi
      fi
    done
    mv "$log" "$log.1"
  fi
}

# ---------------------------------------------------------------------------
# Ejecutar una integracion con lock + log + deteccion de fallo
# ---------------------------------------------------------------------------
global_failed=0

# Comprobacion temprana: flock (util-linux) es requisito para el sistema de locks.
HAVE_FLOCK=1
command -v flock >/dev/null 2>&1 || HAVE_FLOCK=0
if [ "$HAVE_FLOCK" -eq 0 ]; then
  echo "[run_hourly] AVISO: 'flock' no disponible; locks desactivados (recomendado: instalar util-linux)." >&2
fi

# Wazuh aborta por prechecks no criticos a menos que se fuerce lo contrario.
# Es inofensivo para las demas integraciones (solo Wazuh lo lee); exportar
# globalmente evita anteponer 'env' al binario python en la invocacion.
export STARTUP_REQUIRE_ALL_TESTS=false

# Nota: el lock (flock) se abre sobre un archivo por nombre en LOCK_DIR.
run_one() {
  local name="$1"; shift
  local lock="$LOCK_DIR/$name.lock"
  local log="$LOG_DIR/$name.log"

  rotate_log "$log"

  (
    if [ "$HAVE_FLOCK" -eq 1 ]; then
      if ! flock -n 200; then
        echo "[$(date -Is)] SKIP $name: lock ocupado (otra ejecucion en curso)." >> "$log"
        return 0
      fi
    fi
    echo "[$(date -Is)] INICIO $name" >> "$log"
    local start end code
    start="$(date +%s)"
    # shellcheck disable=SC2068
    ( cd "$REPO_DIR" && "$PY" $@ ) >> "$log" 2>&1
    code=$?
    end="$(date +%s)"
    if [ "$code" -eq 0 ]; then
      echo "[$(date -Is)] FIN $name OK (${code}, $((end-start))s)" >> "$log"
      echo "[run_hourly] OK   $name (${code}, $((end-start))s)"
      return 0
    else
      echo "[$(date -Is)] FIN $name ERROR (${code}, $((end-start))s)" >> "$log"
      echo "[run_hourly] FAIL $name (${code}, $((end-start))s)" >&2
      return "$code"
    fi
  ) 200>>"$lock"
  return $?
}

# ---------------------------------------------------------------------------
# Definir las 6 integraciones
# ---------------------------------------------------------------------------
# Formato: nombre|comando...
run_list() {
  printf '%s\n' \
    "nessus|nessus_integration/agent.py --once" \
    "uptimekuma|uptimekuma_integration/agent.py --once" \
    "zabbix|zabix_integration/agent.py --once" \
    "openvas|openVAS_integration/main.py --once" \
    "wazuh|wazuh_integration/main.py --once" \
    "insightvm|insightVM_integration/main.py --once --log-level INFO"
}

# ---------------------------------------------------------------------------
# Ejecutar
# ---------------------------------------------------------------------------
# Escalonado entre integraciones (segundos) para no saturar sistemas/backend.
STAGGER="${MAD_STAGGER_SECONDS:-25}"
ITEMS="$(run_list)"

# Modo dry-run: solo imprime que lanzaria, sin ejecutar nada.
DRY_RUN="${MAD_DRY_RUN:-}"

invoke() {
  local item n c i=0 total pids=()
  total="$(printf '%s\n' "$ITEMS" | wc -l)"
  # Parte SOLO por saltos de linea; cada item conserva espacios internos del comando.
  while IFS= read -r item; do
    [ -z "$item" ] && continue
    n="${item%%|*}"
    c="${item#*|}"
    if [ -n "${INV_ONLY:-}" ] && [ "$INV_ONLY" != "$n" ]; then
      continue
    fi
    if [ -n "$DRY_RUN" ]; then
      echo "[run_hourly] DRY-RUN $n -> $PY $c"
      i=$((i+1))
      continue
    fi
    run_one "$n" $c &
    pids+=("$!")
    i=$((i+1))
    # Escalonar la puesta en marcha salvo en la ultima integracion.
    if [ "$i" -lt "$total" ]; then
      sleep "$STAGGER"
    fi
  done <<< "$ITEMS"
  # Agregar codigos de salida: global_failed=1 si alguna fallo.
  local pid rc
  for pid in "${pids[@]}"; do
    wait "$pid"
    rc=$?
    if [ "$rc" -ne 0 ]; then
      global_failed=1
    fi
  done
}

invoke

# ---------------------------------------------------------------------------
# Estado del ultimo run
# ---------------------------------------------------------------------------
printf 'ts=%s global_failed=%d python=%s repo=%s\n' \
  "$(date -Is)" "$global_failed" "$PY" "$REPO_DIR" > "$STATUS_FILE"

echo "[run_hourly] global_failed=$global_failed"
exit "$global_failed"
