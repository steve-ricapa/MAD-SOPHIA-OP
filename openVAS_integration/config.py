import os
from dotenv import load_dotenv

load_dotenv()

def _env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    return v if v is not None and v != "" else default

def _env_int(name: str, default: int) -> int:
    v = _env(name)
    if v is None:
        return default
    try:
        return int(v)
    except ValueError:
        return default

def _env_bool(name: str, default: bool) -> bool:
    v = _env(name)
    if v is None:
        return default
    v = v.strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    return default


OUTPUT_MODE = (_env("OUTPUT_MODE", "console") or "console").strip().lower()
COLLECTOR   = (_env("COLLECTOR", "simulated") or "simulated").strip().lower()

POLL_SECONDS = _env_int("POLL_SECONDS", 10)
STATE_PATH   = _env("STATE_PATH", "./state.json") or "./state.json"
META_MAX_KB  = _env_int("META_MAX_KB", 256)

TXDXAI_INGEST_URL = _env("TXDXAI_INGEST_URL", "console://stdout") or "console://stdout"
TXDXAI_COMPANY_ID = _env_int("TXDXAI_COMPANY_ID", 0)
TXDXAI_API_KEY    = _env("TXDXAI_API_KEY_OPENVAS", _env("TXDXAI_API_KEY", _env("API_KEY", ""))) or ""

GVM_HOST = _env("GVM_HOST", "127.0.0.1") or "127.0.0.1"
GVM_PORT = _env_int("GVM_PORT", 9390)
GVM_USERNAME = _env("GVM_USERNAME", _env("GVM_USER", "admin")) or "admin"
GVM_PASSWORD = _env("GVM_PASSWORD", _env("GVM_PASS", "")) or ""
GVM_SOCKET = _env("GVM_SOCKET", "") or ""

# TLS opcional para GMP remoto (si usas TLSConnection)
GVM_TLS_CAFILE  = _env("GVM_TLS_CAFILE", "") or ""
GVM_TLS_CERTFILE = _env("GVM_TLS_CERTFILE", "") or ""
GVM_TLS_KEYFILE  = _env("GVM_TLS_KEYFILE", "") or ""
GVM_TIMEOUT = _env_int("GVM_TIMEOUT", 30)

DETAIL_LEVEL = (_env("DETAIL_LEVEL", "findings") or "findings").strip().lower()
TOP_N = _env_int("TOP_N", 50)
REPORT_MAX_KB = _env_int("REPORT_MAX_KB", 4096)
FINDING_TEXT_MAX = _env_int("FINDING_TEXT_MAX", 300)

DEBUG = _env_bool("DEBUG", False)
MAX_ERROR_REPEAT = _env_int("MAX_ERROR_REPEAT", 3)

# Estado (para evitar crecimiento infinito)
STATE_TTL_DAYS = _env_int("STATE_TTL_DAYS", 30)
STATE_MAX_ITEMS = _env_int("STATE_MAX_ITEMS", 5000)


ALLOWED_OUTPUT_MODES = {"console", "http"}
ALLOWED_COLLECTORS = {"simulated", "gmp"}
ALLOWED_DETAIL_LEVELS = {"summary", "stats", "findings", "full", "all"}

def validate_config() -> None:
    if OUTPUT_MODE not in ALLOWED_OUTPUT_MODES:
        raise ValueError(f"OUTPUT_MODE inválido: {OUTPUT_MODE} (usa {sorted(ALLOWED_OUTPUT_MODES)})")

    if COLLECTOR not in ALLOWED_COLLECTORS:
        raise ValueError(f"COLLECTOR inválido: {COLLECTOR} (usa {sorted(ALLOWED_COLLECTORS)})")

    if DETAIL_LEVEL not in ALLOWED_DETAIL_LEVELS:
        raise ValueError(f"DETAIL_LEVEL inválido: {DETAIL_LEVEL} (usa {sorted(ALLOWED_DETAIL_LEVELS)})")

    if POLL_SECONDS <= 0:
        raise ValueError("POLL_SECONDS debe ser > 0")

    if not (1 <= GVM_PORT <= 65535):
        raise ValueError("GVM_PORT fuera de rango 1..65535")

    if COLLECTOR == "gmp":
        if not GVM_SOCKET and not GVM_HOST:
            raise ValueError("COLLECTOR=gmp requiere GVM_HOST o GVM_SOCKET")
        if not GVM_PASSWORD:
            raise ValueError("COLLECTOR=gmp requiere GVM_PASSWORD no vacío")

    if OUTPUT_MODE == "http" and TXDXAI_COMPANY_ID <= 0:
        raise ValueError("OUTPUT_MODE=http requiere TXDXAI_COMPANY_ID > 0")
