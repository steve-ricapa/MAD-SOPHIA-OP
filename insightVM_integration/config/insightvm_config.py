from __future__ import annotations

import sys
from pathlib import Path
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from mad_common.delivery import DeliveryPolicy, resolve_delivery_policy


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
    delivery_policy: DeliveryPolicy
    url: Optional[str]
    tenant_id: int
    company_id: int
    api_key: Optional[str]
    verify: bool
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
    repo_root = Path(__file__).resolve().parents[2]

    queue_dir_raw = os.getenv("INSIGHTVM_QUEUE_DIR") or os.getenv("QUEUE_DIR", "runtime/insightvm/queue")
    queue_dir = _resolve_path(repo_root, queue_dir_raw, "runtime/insightvm/queue")

    company_id = int(os.getenv("TXDXAI_COMPANY_ID") or "0")
    tenant_id = int(os.getenv("TXDXAI_TENANT_ID") or company_id)
    url = os.getenv("TXDXAI_INGEST_URL")
    if url and (company_id <= 0 or tenant_id <= 0):
        raise ValueError("TXDXAI_COMPANY_ID/TXDXAI_TENANT_ID debe ser > 0 para enviar al backend")

    api_key = (
        os.getenv("TXDXAI_API_KEY_INSIGHTVM")
        or os.getenv("TXDXAI_API_KEY")
        or os.getenv("API_KEY")
    )
    if url and not api_key:
        raise ValueError("TXDXAI_API_KEY_INSIGHTVM/TXDXAI_API_KEY/API_KEY es requerido para enviar al backend")

    return BackendSettings(
        delivery_policy=resolve_delivery_policy(os.environ, "insightvm"),
        url=url,
        tenant_id=tenant_id,
        company_id=company_id,
        api_key=api_key,
        verify=_truthy(os.getenv("BACKEND_VERIFY_SSL"), True),
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
    repo_root = Path(__file__).resolve().parents[2]
    state_file_raw = (os.getenv("INSIGHTVM_STATE_FILE") or os.getenv("STATE_FILE") or "runtime/insightvm/state.json").strip()
    state_file = str(_resolve_path(repo_root, state_file_raw, "runtime/insightvm/state.json"))
    return GeneralSettings(
        state_file=state_file,
        interval=int(os.getenv("INSIGHTVM_INTERVAL_SECONDS") or os.getenv("INTERVAL", "60")),
        event_type=(os.getenv("INSIGHTVM_EVENT_TYPE") or os.getenv("EVENT_TYPE") or "vuln_scan_report").strip(),
    )
