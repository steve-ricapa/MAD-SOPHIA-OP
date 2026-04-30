from __future__ import annotations

import os
from dataclasses import dataclass
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
    verify: Union[bool, str]  # bool o ruta


@dataclass(frozen=True)
class BackendSettings:
    url: Optional[str]
    company_id: Optional[str]
    api_key: Optional[str]
    verify: bool


@dataclass(frozen=True)
class GeneralSettings:
    state_file: str


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


def load_backend_settings() -> BackendSettings:
    return BackendSettings(
        url=os.getenv("TXDXAI_INGEST_URL"),
        company_id=os.getenv("TXDXAI_COMPANY_ID"),
        api_key=(
            os.getenv("TXDXAI_API_KEY_INSIGHTVM")
            or os.getenv("TXDXAI_API_KEY")
            or os.getenv("API_KEY")
        ),
        verify=_truthy(os.getenv("BACKEND_VERIFY_SSL"), True),
    )


def load_general_settings() -> GeneralSettings:
    return GeneralSettings(
        state_file=os.getenv("STATE_FILE", "state.json"),
    )
