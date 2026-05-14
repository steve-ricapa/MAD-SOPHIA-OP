import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


@dataclass(frozen=True)
class Config:
    base_dir: Path
    uptime_kuma_url: str
    metrics_path: str
    output_mode: str
    webhook_url: Optional[str]
    company_id: int
    api_key: str
    scanner_type: str
    event_type: str
    poll_interval: int
    request_timeout: int
    verify_ssl: bool
    http_retries: int
    backoff_seconds: int
    force_send_every_cycles: int
    snapshot_always_send: bool
    include_all_monitors: bool
    include_extended_fields: bool
    queue_enabled: bool
    queue_dir: Path
    queue_flush_max: int
    state_path: Path
    debug_report_path: Path
    last_payload_path: Path
    raw_snapshot_path: Path
    mad_version: str
    integration_version: str
    source: str
    kuma_user: Optional[str]
    kuma_password: Optional[str]
    kuma_api_key_id: Optional[str]
    kuma_api_key: Optional[str]
    kuma_db_path: Optional[Path]

    @property
    def metrics_url(self) -> str:
        base = self.uptime_kuma_url.rstrip("/")
        path = self.metrics_path if self.metrics_path.startswith("/") else f"/{self.metrics_path}"
        return f"{base}{path}"


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

    uptime_kuma_url = os.getenv("UPTIME_KUMA_URL", "").strip()
    metrics_path = os.getenv("UPTIME_KUMA_METRICS_PATH", "/metrics").strip()

    output_mode = (os.getenv("UPTIME_OUTPUT_MODE") or os.getenv("OUTPUT_MODE") or "stdout").strip().lower()
    webhook_url = os.getenv("TXDXAI_INGEST_URL") or os.getenv("WEBHOOK_URL")
    company_id = int(os.getenv("TXDXAI_COMPANY_ID") or os.getenv("COMPANY_ID", "1"))
    api_key = (
        os.getenv("TXDXAI_API_KEY_UPTIMEKUMA")
        or os.getenv("TXDXAI_API_KEY")
        or os.getenv("API_KEY", "local_test_key")
    ).strip()
    scanner_type = (os.getenv("UPTIME_SCANNER_TYPE") or os.getenv("SCANNER_TYPE", "uptimekuma")).strip().lower()
    event_type = (os.getenv("UPTIME_EVENT_TYPE") or os.getenv("EVENT_TYPE", "vuln_scan_report")).strip()

    poll_interval = int(os.getenv("UPTIME_POLL_INTERVAL_SECONDS") or os.getenv("POLL_INTERVAL_SECONDS", "15"))
    request_timeout = int(os.getenv("UPTIME_REQUEST_TIMEOUT") or os.getenv("REQUEST_TIMEOUT", "30"))
    verify_ssl = _env_bool("UPTIME_VERIFY_SSL", _env_bool("VERIFY_SSL", True))
    http_retries = int(os.getenv("UPTIME_HTTP_RETRIES") or os.getenv("HTTP_RETRIES", "3"))
    backoff_seconds = int(os.getenv("UPTIME_BACKOFF_SECONDS") or os.getenv("BACKOFF_SECONDS", "5"))
    force_send_every_cycles = int(os.getenv("UPTIME_FORCE_SEND_EVERY_CYCLES") or os.getenv("FORCE_SEND_EVERY_CYCLES", "6"))
    snapshot_always_send = _env_bool("UPTIME_SNAPSHOT_ALWAYS_SEND", _env_bool("SNAPSHOT_ALWAYS_SEND", False))
    include_all_monitors = _env_bool("UPTIME_INCLUDE_ALL_MONITORS", _env_bool("INCLUDE_ALL_MONITORS", False))
    include_extended_fields = _env_bool("UPTIME_INCLUDE_EXTENDED_FIELDS", _env_bool("INCLUDE_EXTENDED_FIELDS", False))
    queue_enabled = _env_bool("UPTIME_QUEUE_ENABLED", _env_bool("QUEUE_ENABLED", True))
    queue_flush_max = int(os.getenv("UPTIME_QUEUE_FLUSH_MAX") or os.getenv("QUEUE_FLUSH_MAX", "20"))

    state_raw = os.getenv("STATE_FILE", "state.json")
    debug_report_raw = os.getenv("DEBUG_REPORT_PATH", "debug_report.json")
    last_payload_raw = os.getenv("LAST_PAYLOAD_PATH", "last_payload_sent.json")
    raw_snapshot_raw = os.getenv("UPTIME_RAW_SNAPSHOT_PATH") or os.getenv("RAW_SNAPSHOT_PATH", "raw_monitors_snapshot.json")
    queue_dir_raw = os.getenv("UPTIME_QUEUE_DIR") or os.getenv("QUEUE_DIR", "queue")

    mad_version = (os.getenv("MAD_VERSION") or "2.3.0").strip()
    integration_version = (os.getenv("UPTIMEKUMA_INTEGRATION_VERSION") or os.getenv("INTEGRATION_VERSION", "1.0.0")).strip()
    source = (os.getenv("SOURCE") or "mad-collector").strip()

    kuma_user = os.getenv("UPTIME_KUMA_USERNAME")
    kuma_password = os.getenv("UPTIME_KUMA_PASSWORD")
    kuma_api_key_id = os.getenv("UPTIME_KUMA_API_KEY_ID")
    kuma_api_key = os.getenv("UPTIME_KUMA_API_KEY")
    kuma_db_raw = os.getenv("UPTIME_KUMA_DB_PATH")

    state_path = _resolve_path(base_dir, state_raw, "state.json")
    debug_report_path = _resolve_path(base_dir, debug_report_raw, "debug_report.json")
    last_payload_path = _resolve_path(base_dir, last_payload_raw, "last_payload_sent.json")
    raw_snapshot_path = _resolve_path(base_dir, raw_snapshot_raw, "raw_monitors_snapshot.json")
    queue_dir = _resolve_path(base_dir, queue_dir_raw, "queue")

    kuma_db_path: Optional[Path] = None
    if kuma_db_raw and kuma_db_raw.strip():
        kuma_db_candidate = Path(kuma_db_raw.strip())
        if not kuma_db_candidate.is_absolute():
            kuma_db_candidate = (base_dir / kuma_db_candidate).resolve()
        kuma_db_path = kuma_db_candidate

    if output_mode not in {"stdout", "webhook", "all"}:
        raise SystemExit("UPTIME_OUTPUT_MODE/OUTPUT_MODE debe ser stdout, webhook o all.")
    if output_mode in {"webhook", "all"} and not webhook_url:
        raise SystemExit("TXDXAI_INGEST_URL es requerido cuando UPTIME_OUTPUT_MODE/OUTPUT_MODE=webhook/all.")
    if poll_interval <= 0:
        raise SystemExit("POLL_INTERVAL_SECONDS debe ser mayor que 0.")
    if force_send_every_cycles < 1:
        raise SystemExit("FORCE_SEND_EVERY_CYCLES debe ser mayor o igual a 1.")
    if queue_flush_max < 1:
        raise SystemExit("QUEUE_FLUSH_MAX debe ser mayor o igual a 1.")
    if not uptime_kuma_url:
        raise SystemExit("UPTIME_KUMA_URL es requerido.")

    return Config(
        base_dir=base_dir,
        uptime_kuma_url=uptime_kuma_url,
        metrics_path=metrics_path,
        output_mode=output_mode,
        webhook_url=webhook_url.strip() if webhook_url else None,
        company_id=company_id,
        api_key=api_key,
        scanner_type=scanner_type,
        event_type=event_type,
        poll_interval=poll_interval,
        request_timeout=request_timeout,
        verify_ssl=verify_ssl,
        http_retries=http_retries,
        backoff_seconds=backoff_seconds,
        force_send_every_cycles=force_send_every_cycles,
        snapshot_always_send=snapshot_always_send,
        include_all_monitors=include_all_monitors,
        include_extended_fields=include_extended_fields,
        queue_enabled=queue_enabled,
        queue_dir=queue_dir,
        queue_flush_max=queue_flush_max,
        state_path=state_path,
        debug_report_path=debug_report_path,
        last_payload_path=last_payload_path,
        raw_snapshot_path=raw_snapshot_path,
        mad_version=mad_version,
        integration_version=integration_version,
        source=source,
        kuma_user=kuma_user.strip() if kuma_user else None,
        kuma_password=kuma_password.strip() if kuma_password else None,
        kuma_api_key_id=kuma_api_key_id.strip() if kuma_api_key_id else None,
        kuma_api_key=kuma_api_key.strip() if kuma_api_key else None,
        kuma_db_path=kuma_db_path,
    )
