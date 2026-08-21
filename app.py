from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlparse
import socket

import requests


@dataclass(frozen=True)
class AgentSpec:
    name: str
    command_builder: Callable[[str, dict[str, str]], list[str]]
    env_map: dict[str, str] = field(default_factory=dict)
    run_dir: str = ""


@dataclass(frozen=True)
class PrecheckResult:
    passed: bool
    phases: list[dict[str, Any]]


def _strip_quotes(value: Optional[str]) -> str:
    text = (value or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1]
    return text


def _normalize_openvas_transport(transport: str, socket_path: str) -> str:
    normalized = (transport or "").strip().lower()
    if normalized == "tcp":
        return "plain"
    if normalized:
        return normalized
    return "unix" if socket_path else "tls"


def _detect_critical_execution_error(output: str) -> tuple[bool, Optional[str]]:
    text = output or ""
    if "ERROR @ cycle.task[" in text:
        return True, "cycle_task_error"
    return False, None


def _resolve_dns(host: str) -> tuple[list[str], Optional[str]]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        return [], str(exc)
    ips = sorted({item[4][0] for item in infos if item[4]})
    return ips, None


def _tcp_probe(host: str, port: int, timeout: int) -> tuple[bool, Optional[str], Optional[str]]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, None, None
    except OSError as exc:
        return False, "tcp_connect_error", str(exc)


def _http_probe_detailed(
    method: str,
    url: str,
    timeout: int,
    auth: Any = None,
    headers: Optional[dict[str, str]] = None,
    json_body: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    try:
        response = requests.request(
            method=method,
            url=url,
            timeout=timeout,
            auth=auth,
            headers=headers,
            json=json_body,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        return {
            "ok": False,
            "status_code": None,
            "body_preview": "",
            "error_kind": "http_error",
            "error_text": str(exc),
        }
    return {
        "ok": 200 <= response.status_code < 300,
        "status_code": response.status_code,
        "body_preview": (response.text or "")[:300],
        "error_kind": None if 200 <= response.status_code < 300 else "http_status",
        "error_text": None if 200 <= response.status_code < 300 else (response.text or "")[:300],
    }


def run_agent_precheck_diagnostic(spec: AgentSpec, env: dict[str, str], timeout_seconds: int = 5) -> PrecheckResult:
    phases: list[dict[str, Any]] = []

    if spec.name != "uptimekuma":
        return PrecheckResult(passed=False, phases=[{"phase": "agent", "status": "FAIL", "normalized_error": "unsupported_agent"}])

    base_url = (env.get("UPTIME_KUMA_URL") or "").strip()
    metrics_path = (env.get("UPTIME_KUMA_METRICS_PATH") or "/metrics").strip() or "/metrics"
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    ips, dns_error = _resolve_dns(host)
    phases.append({
        "phase": "dns",
        "status": "PASS" if ips else "FAIL",
        "normalized_error": None if ips else "dns_error",
        "details": ",".join(ips) if ips else dns_error,
    })

    tcp_ok, tcp_error_kind, tcp_error_text = _tcp_probe(host, port, timeout_seconds)
    phases.append({
        "phase": "tcp",
        "status": "PASS" if tcp_ok else "FAIL",
        "normalized_error": tcp_error_kind,
        "details": tcp_error_text,
    })

    api_key_id = _strip_quotes(env.get("UPTIME_KUMA_API_KEY_ID"))
    api_key = _strip_quotes(env.get("UPTIME_KUMA_API_KEY"))
    username = _strip_quotes(env.get("UPTIME_KUMA_USERNAME"))
    password = _strip_quotes(env.get("UPTIME_KUMA_PASSWORD"))

    auth: Any = None
    if api_key_id and api_key:
        auth = (api_key_id, api_key)
    elif username and password:
        auth = (username, password)

    auth_ok = auth is not None
    phases.append({
        "phase": "auth",
        "status": "PASS" if auth_ok else "FAIL",
        "normalized_error": None if auth_ok else "missing_auth",
        "details": None if auth_ok else "Missing Uptime Kuma API key or username/password",
    })

    api_ok = False
    api_error = None
    if auth_ok:
        url = f"{base_url.rstrip('/')}{metrics_path if metrics_path.startswith('/') else '/' + metrics_path}"
        response = _http_probe_detailed("GET", url, timeout_seconds, auth=auth)
        api_ok = bool(response.get("ok"))
        api_error = response.get("error_kind") or response.get("error_text")

    phases.append({
        "phase": "api",
        "status": "PASS" if api_ok else "FAIL",
        "normalized_error": None if api_ok else (api_error or "api_probe_failed"),
        "details": None if api_ok else api_error,
    })

    passed = all(phase["status"] == "PASS" for phase in phases)
    return PrecheckResult(passed=passed, phases=phases)
