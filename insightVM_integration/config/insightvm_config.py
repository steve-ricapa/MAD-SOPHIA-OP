from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union


def _truthy(v: Optional[str], default: bool) -> bool:
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "t", "yes", "y", "on")


@dataclass(frozen=True)
class InsightVMSettings:
    base_url: str
    username: str
    password: str
    timeout: int
    verify: Union[bool, str]


@dataclass(frozen=True)
class BackendSettings:
    url: Optional[str]
    company_id: int
    api_key: Optional[str]
    verify: bool
    force_send_every_cycles: int
    snapshot_always_send: bool
    mad_version: str
    integration_version: str
    source: str
    queue_enabled: bool
    queue_dir: Path
    queue_flush_max: int


@dataclass(frozen=True)
class GeneralSettings:
    state_file: str
    interval: int
    event_type: str


def load_insightvm_settings(
    timeout_override: Optional[int] = None,
    verify_ssl_override: Optional[str] = None,
) -> InsightVMSettings:
    base_url = (os.getenv("INSIGHTVM_BASE_URL") or "").strip()
    username = (os.getenv("INSIGHTVM_USER") or "").strip()
    password = (os.getenv("INSIGHTVM_PASSWORD") or "").strip()

    timeout = int(os.getenv("INSIGHTVM_TIMEOUT", "30"))
    if timeout_override is not None:
        timeout = int(timeout_override)

    ca_bundle = (os.getenv("INSIGHTVM_CA_BUNDLE") or "").strip()
    if ca_bundle:
        verify: Union[bool, str] = ca_bundle
    else:
        env_verify = os.getenv("INSIGHTVM_VERIFY_SSL")
        if verify_ssl_override is not None:
            env_verify = verify_ssl_override
        verify = _truthy(env_verify, True)

    return InsightVMSettings(
        base_url=base_url,
        username=username,
        password=password,
        timeout=timeout,
        verify=verify,
    )


def _resolve_path(base_dir: Path, raw_path: str, fallback_name: str) -> Path:
    candidate = Path((raw_path or fallback_name).strip())
    if not candidate.is_absolute():
        candidate = base_dir / candidate
    return candidate


def load_backend_settings() -> BackendSettings:
    base_dir = Path(__file__).resolve().parent

    queue_dir_raw = os.getenv("INSIGHTVM_QUEUE_DIR") or os.getenv("QUEUE_DIR", "queue")
    queue_dir = _resolve_path(base_dir, queue_dir_raw, "queue")

    return BackendSettings(
        url=os.getenv("TXDXAI_INGEST_URL"),
        company_id=int(os.getenv("TXDXAI_COMPANY_ID", "1")),
        api_key=(
            os.getenv("TXDXAI_API_KEY_INSIGHTVM")
            or os.getenv("TXDXAI_API_KEY")
            or os.getenv("API_KEY")
        ),
        verify=_truthy(os.getenv("BACKEND_VERIFY_SSL"), True),
        force_send_every_cycles=int(
            os.getenv("INSIGHTVM_FORCE_SEND_EVERY_CYCLES")
            or os.getenv("FORCE_SEND_EVERY_CYCLES", "10")
        ),
        snapshot_always_send=_truthy(
            os.getenv("INSIGHTVM_SNAPSHOT_ALWAYS_SEND"),
            _truthy(os.getenv("SNAPSHOT_ALWAYS_SEND"), False),
        ),
        mad_version=(os.getenv("MAD_VERSION") or "2.3.0").strip(),
        integration_version=(
            os.getenv("INSIGHTVM_INTEGRATION_VERSION")
            or os.getenv("INTEGRATION_VERSION", "1.0.0")
        ).strip(),
        source=(os.getenv("SOURCE") or "mad-collector").strip(),
        queue_enabled=_truthy(
            os.getenv("INSIGHTVM_QUEUE_ENABLED"),
            _truthy(os.getenv("QUEUE_ENABLED"), True),
        ),
        queue_dir=queue_dir,
        queue_flush_max=int(
            os.getenv("INSIGHTVM_QUEUE_FLUSH_MAX")
            or os.getenv("QUEUE_FLUSH_MAX", "20")
        ),
    )


def load_general_settings() -> GeneralSettings:
    return GeneralSettings(
        state_file=os.getenv("STATE_FILE", "state.json"),
        interval=int(os.getenv("INTERVAL", "60")),
        event_type=(os.getenv("EVENT_TYPE") or "vuln_scan_report").strip(),
    )
