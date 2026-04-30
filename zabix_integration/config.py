import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from dotenv import load_dotenv

@dataclass(frozen=True)
class Config:
    base_dir: Path
    api_url: str
    user: str
    password: str
    hours: int
    output_mode: str  # stdout | webhook | all
    webhook_url: Optional[str]
    state_path: str
    company_id: int
    api_key: str
    interval: int # Segundos entre escaneos
    verify_ssl: bool
    request_timeout: int
    http_retries: int
    backoff_seconds: int
    problems_limit: int
    triggers_limit: int
    events_limit: int
    debug_report_path: Path
    last_payload_path: Path
    include_events: bool


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _resolve_path(base_dir: Path, raw_path: str, fallback_name: str) -> Path:
    candidate = Path((raw_path or fallback_name).strip())
    if not candidate.is_absolute():
        candidate = base_dir / candidate
    return candidate

def load_config() -> Config:
    load_dotenv()
    base_dir = Path(__file__).resolve().parent

    # Zabbix Source
    api_url = os.getenv("ZABBIX_API_URL", "").strip()
    user = os.getenv("ZABBIX_USER", "").strip()
    password = os.getenv("ZABBIX_PASS", "").strip()
    hours = int(os.getenv("ZABBIX_HOURS") or os.getenv("HOURS", "24"))
    
    # Backend TxDxAI (Prioridad a TXDXAI_*)
    output_mode = (os.getenv("ZABBIX_OUTPUT_MODE") or os.getenv("OUTPUT_MODE") or "stdout").strip().lower()
    webhook_url = os.getenv("TXDXAI_INGEST_URL") or os.getenv("WEBHOOK_URL")
    company_id = int(os.getenv("TXDXAI_COMPANY_ID") or os.getenv("COMPANY_ID", "1"))
    api_key = (
        os.getenv("TXDXAI_API_KEY_ZABBIX")
        or os.getenv("TXDXAI_API_KEY")
        or os.getenv("API_KEY", "local_test_key")
    )
    
    state_raw = os.getenv("ZABBIX_STATE_FILE") or os.getenv("STATE_FILE") or os.getenv("STATE_PATH", "state.json")
    interval = int(os.getenv("ZABBIX_INTERVAL") or os.getenv("INTERVAL", "60"))
    verify_ssl = _env_bool("ZABBIX_VERIFY_SSL", _env_bool("VERIFY_SSL", True))
    request_timeout = int(os.getenv("ZABBIX_REQUEST_TIMEOUT") or os.getenv("REQUEST_TIMEOUT", "30"))
    http_retries = int(os.getenv("ZABBIX_HTTP_RETRIES") or os.getenv("HTTP_RETRIES", "3"))
    backoff_seconds = int(os.getenv("ZABBIX_BACKOFF_SECONDS") or os.getenv("BACKOFF_SECONDS", "5"))
    problems_limit = int(os.getenv("ZABBIX_PROBLEMS_LIMIT") or os.getenv("PROBLEMS_LIMIT", "2000"))
    triggers_limit = int(os.getenv("ZABBIX_TRIGGERS_LIMIT") or os.getenv("TRIGGERS_LIMIT", "5000"))
    events_limit = int(os.getenv("ZABBIX_EVENTS_LIMIT") or os.getenv("EVENTS_LIMIT", "2000"))
    debug_report_raw = os.getenv("ZABBIX_DEBUG_REPORT_PATH") or os.getenv("DEBUG_REPORT_PATH", "debug_report.json")
    last_payload_raw = os.getenv("ZABBIX_LAST_PAYLOAD_PATH") or os.getenv("LAST_PAYLOAD_PATH", "last_payload_sent.json")
    include_events = _env_bool("ZABBIX_INCLUDE_EVENTS", _env_bool("INCLUDE_EVENTS", False))

    state_path = _resolve_path(base_dir, state_raw, "state.json")
    debug_report_path = _resolve_path(base_dir, debug_report_raw, "debug_report.json")
    last_payload_path = _resolve_path(base_dir, last_payload_raw, "last_payload_sent.json")

    if not api_url:
        raise SystemExit("Falta ZABBIX_API_URL.")
    if not user or not password:
        raise SystemExit("Faltan ZABBIX_USER o ZABBIX_PASS.")
    if output_mode not in {"stdout", "webhook", "all"}:
        raise SystemExit("ZABBIX_OUTPUT_MODE/OUTPUT_MODE debe ser stdout, webhook o all.")
    
    return Config(
        base_dir=base_dir,
        api_url=api_url,
        user=user,
        password=password,
        hours=hours,
        output_mode=output_mode,
        webhook_url=webhook_url.strip() if webhook_url else None,
        state_path=str(state_path),
        company_id=company_id,
        api_key=api_key.strip(),
        interval=interval,
        verify_ssl=verify_ssl,
        request_timeout=request_timeout,
        http_retries=http_retries,
        backoff_seconds=backoff_seconds,
        problems_limit=problems_limit,
        triggers_limit=triggers_limit,
        events_limit=events_limit,
        debug_report_path=debug_report_path,
        last_payload_path=last_payload_path,
        include_events=include_events,
    )
