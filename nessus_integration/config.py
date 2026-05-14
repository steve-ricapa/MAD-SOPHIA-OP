import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


@dataclass(frozen=True)
class Config:
    base_dir: Path
    nessus_base_url: str
    nessus_access_key: str
    nessus_secret_key: str
    verify_ssl: bool
    output_mode: str
    webhook_url: Optional[str]
    company_id: int
    api_key: str
    scanner_type: str
    event_type: str
    poll_interval: int
    request_timeout: int
    http_retries: int
    backoff_seconds: int
    max_scans_per_cycle: int
    force_send_every_cycles: int
    snapshot_always_send: bool
    include_all_findings: bool
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
    scan_ids_filter: Optional[set[int]]
    folder_id_filter: Optional[int]

    @property
    def api_root(self) -> str:
        return self.nessus_base_url.rstrip("/")


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


def _parse_scan_ids(raw: Optional[str]) -> Optional[set[int]]:
    if not raw:
        return None
    out: set[int] = set()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if not token.isdigit():
            raise SystemExit(f"NESSUS_SCAN_IDS contiene valor invalido: {token}")
        out.add(int(token))
    return out or None


def load_config() -> Config:
    base_dir = Path(__file__).resolve().parent
    load_dotenv(base_dir / ".env")

    nessus_base_url = os.getenv("NESSUS_BASE_URL", "").strip()
    nessus_access_key = os.getenv("NESSUS_ACCESS_KEY", "").strip()
    nessus_secret_key = os.getenv("NESSUS_SECRET_KEY", "").strip()
    verify_ssl = _env_bool("NESSUS_VERIFY_SSL", False)

    output_mode = (os.getenv("NESSUS_OUTPUT_MODE") or os.getenv("OUTPUT_MODE") or "stdout").strip().lower()
    webhook_url = os.getenv("TXDXAI_INGEST_URL") or os.getenv("WEBHOOK_URL")
    company_id = int(os.getenv("TXDXAI_COMPANY_ID") or os.getenv("COMPANY_ID", "1"))
    api_key = (
        os.getenv("TXDXAI_API_KEY_NESSUS")
        or os.getenv("TXDXAI_API_KEY")
        or os.getenv("API_KEY", "local_test_key")
    ).strip()
    scanner_type = (os.getenv("NESSUS_SCANNER_TYPE") or os.getenv("SCANNER_TYPE", "nessus")).strip().lower()
    event_type = (os.getenv("NESSUS_EVENT_TYPE") or os.getenv("EVENT_TYPE", "vuln_scan_report")).strip()

    poll_interval = int(os.getenv("NESSUS_POLL_INTERVAL_SECONDS") or os.getenv("POLL_INTERVAL_SECONDS", "60"))
    request_timeout = int(os.getenv("NESSUS_REQUEST_TIMEOUT") or os.getenv("REQUEST_TIMEOUT", "30"))
    http_retries = int(os.getenv("NESSUS_HTTP_RETRIES") or os.getenv("HTTP_RETRIES", "3"))
    backoff_seconds = int(os.getenv("NESSUS_BACKOFF_SECONDS") or os.getenv("BACKOFF_SECONDS", "5"))
    max_scans_per_cycle = int(os.getenv("NESSUS_MAX_SCANS_PER_CYCLE", "5"))
    force_send_every_cycles = int(os.getenv("NESSUS_FORCE_SEND_EVERY_CYCLES") or os.getenv("FORCE_SEND_EVERY_CYCLES", "10"))
    snapshot_always_send = _env_bool("NESSUS_SNAPSHOT_ALWAYS_SEND", _env_bool("SNAPSHOT_ALWAYS_SEND", False))
    include_all_findings = _env_bool("NESSUS_INCLUDE_ALL_FINDINGS", _env_bool("INCLUDE_ALL_FINDINGS", True))

    queue_enabled = _env_bool("NESSUS_QUEUE_ENABLED", _env_bool("QUEUE_ENABLED", True))
    queue_flush_max = int(os.getenv("NESSUS_QUEUE_FLUSH_MAX") or os.getenv("QUEUE_FLUSH_MAX", "20"))

    state_raw = os.getenv("STATE_FILE", "state.json")
    debug_report_raw = os.getenv("DEBUG_REPORT_PATH", "debug_report.json")
    last_payload_raw = os.getenv("LAST_PAYLOAD_PATH", "last_payload_sent.json")
    raw_snapshot_raw = os.getenv("NESSUS_RAW_SNAPSHOT_PATH") or os.getenv("RAW_SNAPSHOT_PATH", "raw_scans_snapshot.json")
    mad_version = (os.getenv("MAD_VERSION") or "2.3.0").strip()
    integration_version = (os.getenv("NESSUS_INTEGRATION_VERSION") or os.getenv("INTEGRATION_VERSION", "1.0.0")).strip()
    source = (os.getenv("SOURCE") or "mad-collector").strip()
    queue_dir_raw = os.getenv("NESSUS_QUEUE_DIR") or os.getenv("QUEUE_DIR", "queue")

    scan_ids_filter = _parse_scan_ids(os.getenv("NESSUS_SCAN_IDS"))
    folder_raw = os.getenv("NESSUS_FOLDER_ID", "").strip()
    folder_id_filter = int(folder_raw) if folder_raw.isdigit() else None

    state_path = _resolve_path(base_dir, state_raw, "state.json")
    debug_report_path = _resolve_path(base_dir, debug_report_raw, "debug_report.json")
    last_payload_path = _resolve_path(base_dir, last_payload_raw, "last_payload_sent.json")
    raw_snapshot_path = _resolve_path(base_dir, raw_snapshot_raw, "raw_scans_snapshot.json")
    queue_dir = _resolve_path(base_dir, queue_dir_raw, "queue")

    if not nessus_base_url:
        raise SystemExit("NESSUS_BASE_URL es requerido.")
    if not nessus_access_key or not nessus_secret_key:
        raise SystemExit("NESSUS_ACCESS_KEY y NESSUS_SECRET_KEY son requeridos.")
    if output_mode not in {"stdout", "webhook", "all"}:
        raise SystemExit("NESSUS_OUTPUT_MODE/OUTPUT_MODE debe ser stdout, webhook o all.")
    if output_mode in {"webhook", "all"} and not webhook_url:
        raise SystemExit("TXDXAI_INGEST_URL es requerido cuando NESSUS_OUTPUT_MODE/OUTPUT_MODE=webhook/all.")
    if poll_interval <= 0:
        raise SystemExit("POLL_INTERVAL_SECONDS debe ser > 0.")
    if http_retries < 1:
        raise SystemExit("HTTP_RETRIES debe ser >= 1.")
    if backoff_seconds < 1:
        raise SystemExit("BACKOFF_SECONDS debe ser >= 1.")
    if max_scans_per_cycle < 1:
        raise SystemExit("NESSUS_MAX_SCANS_PER_CYCLE debe ser >= 1.")
    if force_send_every_cycles < 1:
        raise SystemExit("FORCE_SEND_EVERY_CYCLES debe ser >= 1.")
    if queue_flush_max < 1:
        raise SystemExit("QUEUE_FLUSH_MAX debe ser >= 1.")

    return Config(
        base_dir=base_dir,
        nessus_base_url=nessus_base_url,
        nessus_access_key=nessus_access_key,
        nessus_secret_key=nessus_secret_key,
        verify_ssl=verify_ssl,
        output_mode=output_mode,
        webhook_url=webhook_url.strip() if webhook_url else None,
        company_id=company_id,
        api_key=api_key,
        scanner_type=scanner_type,
        event_type=event_type,
        poll_interval=poll_interval,
        request_timeout=request_timeout,
        http_retries=http_retries,
        backoff_seconds=backoff_seconds,
        max_scans_per_cycle=max_scans_per_cycle,
        force_send_every_cycles=force_send_every_cycles,
        snapshot_always_send=snapshot_always_send,
        include_all_findings=include_all_findings,
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
        scan_ids_filter=scan_ids_filter,
        folder_id_filter=folder_id_filter,
    )
