from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import requests
import urllib3

from dotenv import load_dotenv

# Disable noisy SSL warnings during prechecks (self-signed certs are expected)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


ROOT = Path(__file__).resolve().parent

# Branch-local override for troubleshooting false negatives in startup tests.
# When enabled, orchestrator startup prechecks are skipped and agents run directly.
DISABLE_STARTUP_PRECHECKS = True


def now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(message: str) -> None:
    print(f"{now()} | ORCH | {message}", flush=True)


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_agents(raw: str | None, available: list[str]) -> list[str]:
    if not raw or raw.strip().lower() == "all":
        return available

    wanted = [item.strip().lower() for item in raw.split(",") if item.strip()]
    unknown = [name for name in wanted if name not in available]
    if unknown:
        raise SystemExit(f"Unknown agent(s): {', '.join(unknown)}")

    unique_ordered: list[str] = []
    seen: set[str] = set()
    for name in wanted:
        if name not in seen:
            unique_ordered.append(name)
            seen.add(name)
    return unique_ordered


def parse_test_targets(raw: str | None, selected: list[str], available: list[str]) -> list[str]:
    """
    Parse startup test target scope:
      - all
      - selected
      - single agent name (e.g. wazuh)
      - comma-separated list of names
    """
    value = (raw or "selected").strip().lower()
    if value == "all":
        return list(available)
    if value == "selected":
        return list(selected)

    requested = [item.strip().lower() for item in value.split(",") if item.strip()]
    if not requested:
        return list(selected)
    unknown = [name for name in requested if name not in available]
    if unknown:
        raise SystemExit(f"Unknown startup test target(s): {', '.join(unknown)}")
    # preserve order and remove duplicates
    unique_ordered: list[str] = []
    seen: set[str] = set()
    for name in requested:
        if name not in seen:
            unique_ordered.append(name)
            seen.add(name)
    return unique_ordered


@dataclass
class PrecheckResult:
    name: str
    required: bool
    passed: bool
    details: str
    phases: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""


@dataclass
class DiagnosticExecResult:
    name: str
    status: str  # PASS | FAIL | SKIPPED
    details: str
    phase: str = "execution"
    raw_error_excerpt: str | None = None
    return_code: int | None = None
    log_file: str | None = None
    phases: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""


@dataclass
class AgentSpec:
    name: str
    command_builder: Callable[[str, dict[str, str]], list[str]]
    env_map: dict[str, str] = field(default_factory=dict)
    run_dir: str = ""

    def build_env(self, base_env: dict[str, str]) -> dict[str, str]:
        env = dict(base_env)
        for source_name, target_name in self.env_map.items():
            value = base_env.get(source_name)
            if value:
                env[target_name] = value
        return env


def first_nonempty(values: list[str | None]) -> str:
    for value in values:
        if value and str(value).strip():
            return str(value).strip()
    return ""


def parse_host_port(raw: str, default_port: int) -> tuple[str, int] | None:
    if not raw:
        return None
    raw = raw.strip()
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname
    if not host:
        return None
    port = parsed.port or default_port
    return host, port


def can_connect(raw: str, default_port: int, timeout_seconds: float) -> tuple[bool, str]:
    host_port = parse_host_port(raw, default_port)
    if not host_port:
        return False, "invalid host/url"
    host, port = host_port
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True, f"tcp ok {host}:{port}"
    except Exception as exc:
        return False, f"tcp fail {host}:{port} ({type(exc).__name__})"


def api_probe(
    method: str,
    url: str,
    timeout: float,
    auth: tuple[str, str] | None = None,
    headers: dict[str, str] | None = None,
    json_body: dict | None = None,
) -> tuple[bool, int, str]:
    """Perform a single read-only HTTP request. Returns (success, status_code, detail)."""
    try:
        resp = requests.request(
            method,
            url,
            auth=auth,
            headers=headers,
            json=json_body,
            timeout=timeout,
            verify=False,
        )
        body_preview = resp.text[:200] if resp.text else ""
        return resp.ok, resp.status_code, body_preview
    except requests.ConnectionError as exc:
        return False, 0, f"connection error: {exc}"
    except requests.Timeout:
        return False, 0, "request timed out"
    except Exception as exc:
        return False, 0, f"request error: {type(exc).__name__}: {exc}"


def _phase_result(
    phase: str,
    status: str,
    started_at: float,
    normalized_error: str | None = None,
    raw_error_excerpt: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "phase": phase,
        "status": status,
        "duration_ms": int((time.perf_counter() - started_at) * 1000),
        "normalized_error": normalized_error,
        "raw_error_excerpt": raw_error_excerpt,
        "evidence": evidence or {},
    }


def _is_placeholder(value: str) -> bool:
    low = (value or "").strip().lower()
    return any(token in low for token in ("your_", "changeme", "example", "replace_me", "<", ">"))


def _resolve_dns(host: str) -> tuple[list[str], str | None]:
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({item[4][0] for item in infos if item and item[4] and item[4][0]})
        return ips, None
    except socket.gaierror as exc:
        return [], f"dns_error:{exc}"
    except Exception as exc:
        return [], f"dns_error:{type(exc).__name__}:{exc}"


def _tcp_probe(host: str, port: int, timeout_seconds: float) -> tuple[bool, str | None, str | None]:
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True, None, None
    except socket.timeout as exc:
        return False, "timeout", str(exc)
    except ConnectionRefusedError as exc:
        return False, "refused", str(exc)
    except ConnectionResetError as exc:
        return False, "reset", str(exc)
    except OSError as exc:
        txt = str(exc).lower()
        if "unreach" in txt:
            return False, "unreachable", str(exc)
        return False, "network_error", str(exc)
    except Exception as exc:
        return False, "network_error", f"{type(exc).__name__}: {exc}"


def _http_probe_detailed(
    method: str,
    url: str,
    timeout: float,
    auth: tuple[str, str] | None = None,
    headers: dict[str, str] | None = None,
    json_body: dict | None = None,
) -> dict[str, Any]:
    try:
        resp = requests.request(
            method,
            url,
            auth=auth,
            headers=headers,
            json=json_body,
            timeout=timeout,
            verify=False,
        )
        return {
            "ok": resp.ok,
            "status_code": resp.status_code,
            "body_preview": (resp.text or "")[:200],
            "error_kind": None,
            "error_text": None,
        }
    except requests.exceptions.SSLError as exc:
        return {"ok": False, "status_code": 0, "body_preview": "", "error_kind": "tls_error", "error_text": str(exc)}
    except requests.exceptions.Timeout as exc:
        return {"ok": False, "status_code": 0, "body_preview": "", "error_kind": "timeout", "error_text": str(exc)}
    except requests.exceptions.ConnectionError as exc:
        return {"ok": False, "status_code": 0, "body_preview": "", "error_kind": "connection_error", "error_text": str(exc)}
    except Exception as exc:
        return {"ok": False, "status_code": 0, "body_preview": "", "error_kind": "request_error", "error_text": f"{type(exc).__name__}: {exc}"}


def _add_skipped(phases: list[dict[str, Any]], phase: str, reason: str) -> None:
    phases.append({"phase": phase, "status": "SKIPPED", "duration_ms": 0, "normalized_error": reason, "raw_error_excerpt": reason[:200], "evidence": {}})


def run_agent_precheck_diagnostic(spec: AgentSpec, base_env: dict[str, str], timeout_seconds: float) -> PrecheckResult:
    env = spec.build_env(base_env)
    phases: list[dict[str, Any]] = []

    required_map: dict[str, list[str]] = {
        "wazuh": ["TXDXAI_API_KEY_WAZUH", "TXDXAI_INGEST_URL", "TXDXAI_COMPANY_ID", "WAZUH_API_HOST", "WAZUH_API_USER", "WAZUH_API_PASSWORD", "WAZUH_INDEXER_HOST", "WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASSWORD"],
        "zabbix": ["TXDXAI_API_KEY_ZABBIX", "TXDXAI_INGEST_URL", "TXDXAI_COMPANY_ID", "ZABBIX_API_URL", "ZABBIX_USER", "ZABBIX_PASS"],
        "openvas": ["TXDXAI_API_KEY_OPENVAS", "TXDXAI_INGEST_URL", "TXDXAI_COMPANY_ID"],
        "insightvm": ["TXDXAI_API_KEY_INSIGHTVM", "TXDXAI_INGEST_URL", "TXDXAI_COMPANY_ID", "INSIGHTVM_BASE_URL", "INSIGHTVM_USER", "INSIGHTVM_PASSWORD"],
        "uptimekuma": ["TXDXAI_API_KEY_UPTIMEKUMA", "TXDXAI_INGEST_URL", "TXDXAI_COMPANY_ID", "UPTIME_KUMA_URL"],
        "nessus": ["TXDXAI_API_KEY_NESSUS", "TXDXAI_INGEST_URL", "TXDXAI_COMPANY_ID", "NESSUS_BASE_URL", "NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY"],
        "backend": ["TXDXAI_INGEST_URL"],
    }
    required = spec.name != "backend"
    env_start = time.perf_counter()
    missing: list[str] = []
    placeholders: list[str] = []
    for key in required_map.get(spec.name, []):
        val = (env.get(key) or "").strip()
        if not val:
            missing.append(key)
        elif _is_placeholder(val):
            placeholders.append(key)
    if spec.name == "openvas":
        output_mode = (env.get("OUTPUT_MODE") or "").strip().lower()
        collector = (env.get("COLLECTOR") or "").strip().lower()
        if output_mode not in {"console", "http"}:
            missing.append("OUTPUT_MODE")
        if collector not in {"gmp", "simulated"}:
            missing.append("COLLECTOR")
    if spec.name == "uptimekuma":
        has_auth = bool(env.get("UPTIME_KUMA_API_KEY")) or (bool(env.get("UPTIME_KUMA_USERNAME")) and bool(env.get("UPTIME_KUMA_PASSWORD")))
        if not has_auth:
            missing.append("UPTIME_KUMA_API_KEY or UPTIME_KUMA_USERNAME+PASSWORD")
    if missing or placeholders:
        norm = f"missing_env:{','.join(missing)}" if missing else f"placeholder_env:{','.join(placeholders)}"
        raw = f"missing={missing} placeholders={placeholders}"
        phases.append(_phase_result("env", "FAIL", env_start, norm, raw, {"missing": missing, "placeholders": placeholders}))
        for phase in ("dns", "tcp", "tls", "auth", "api"):
            _add_skipped(phases, phase, "blocked_by_env")
        summary = f"env FAIL: {raw}"
        return PrecheckResult(spec.name, required, False, summary, phases=phases, summary=summary)
    phases.append(_phase_result("env", "PASS", env_start, evidence={"required_keys": required_map.get(spec.name, [])}))

    target = ""
    default_port = 443
    if spec.name == "wazuh":
        target = env.get("WAZUH_API_HOST", "")
        default_port = 55000
    elif spec.name == "zabbix":
        target = env.get("ZABBIX_API_URL", "")
        default_port = 80
    elif spec.name == "openvas":
        target = env.get("GVM_HOST", "")
        default_port = int(env.get("GVM_PORT", "9390"))
    elif spec.name == "insightvm":
        target = env.get("INSIGHTVM_BASE_URL", "")
        default_port = 3780
    elif spec.name == "uptimekuma":
        target = env.get("UPTIME_KUMA_URL", "")
        default_port = 3001
    elif spec.name == "nessus":
        target = env.get("NESSUS_BASE_URL", "")
        default_port = 8834
    elif spec.name == "backend":
        target = first_nonempty([env.get("TXDXAI_INGEST_URL"), env.get("WEBHOOK_URL")])
        default_port = 443

    host_port = parse_host_port(target, default_port) if target else None
    dns_start = time.perf_counter()
    if spec.name == "openvas" and (env.get("COLLECTOR") or "").strip().lower() == "simulated":
        phases.append(_phase_result("dns", "SKIPPED", dns_start, "collector_simulated", evidence={"collector": "simulated"}))
        _add_skipped(phases, "tcp", "collector_simulated")
        _add_skipped(phases, "tls", "collector_simulated")
        _add_skipped(phases, "auth", "collector_simulated")
        _add_skipped(phases, "api", "collector_simulated")
        summary = "collector=simulated"
        return PrecheckResult(spec.name, required, True, summary, phases=phases, summary=summary)
    if not host_port:
        phases.append(_phase_result("dns", "FAIL", dns_start, "invalid_host", f"invalid host/url: {target}", {"target": target}))
        for phase in ("tcp", "tls", "auth", "api"):
            _add_skipped(phases, phase, "blocked_by_dns")
        summary = f"dns FAIL invalid_host: {target}"
        return PrecheckResult(spec.name, required, False, summary, phases=phases, summary=summary)
    host, port = host_port
    ips, dns_err = _resolve_dns(host)
    if dns_err:
        phases.append(_phase_result("dns", "FAIL", dns_start, "dns_resolution_failed", dns_err, {"host": host}))
        for phase in ("tcp", "tls", "auth", "api"):
            _add_skipped(phases, phase, "blocked_by_dns")
        summary = f"dns FAIL: {dns_err}"
        return PrecheckResult(spec.name, required, False, summary, phases=phases, summary=summary)
    phases.append(_phase_result("dns", "PASS", dns_start, evidence={"host": host, "port": port, "resolved_ips": ips}))

    tcp_start = time.perf_counter()
    tcp_ok, tcp_err, tcp_raw = _tcp_probe(host, port, timeout_seconds)
    if not tcp_ok:
        phases.append(_phase_result("tcp", "FAIL", tcp_start, tcp_err or "tcp_error", tcp_raw, {"host": host, "port": port, "resolved_ips": ips}))
        for phase in ("tls", "auth", "api"):
            _add_skipped(phases, phase, "blocked_by_tcp")
        summary = f"tcp FAIL: {tcp_err}"
        return PrecheckResult(spec.name, required, False, summary, phases=phases, summary=summary)
    phases.append(_phase_result("tcp", "PASS", tcp_start, evidence={"host": host, "port": port}))

    tls_start = time.perf_counter()
    is_tls = target.lower().startswith("https://") or port in {443, 8834, 55000, 3780}
    if is_tls:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    pass
            phases.append(_phase_result("tls", "PASS", tls_start, evidence={"host": host, "port": port}))
        except ssl.SSLError as exc:
            phases.append(_phase_result("tls", "FAIL", tls_start, "tls_handshake_failed", str(exc), {"host": host, "port": port}))
            for phase in ("auth", "api"):
                _add_skipped(phases, phase, "blocked_by_tls")
            summary = f"tls FAIL: {exc}"
            return PrecheckResult(spec.name, required, False, summary, phases=phases, summary=summary)
        except Exception as exc:
            phases.append(_phase_result("tls", "FAIL", tls_start, "tls_handshake_failed", f"{type(exc).__name__}: {exc}", {"host": host, "port": port}))
            for phase in ("auth", "api"):
                _add_skipped(phases, phase, "blocked_by_tls")
            summary = f"tls FAIL: {type(exc).__name__}"
            return PrecheckResult(spec.name, required, False, summary, phases=phases, summary=summary)
    else:
        phases.append(_phase_result("tls", "SKIPPED", tls_start, "non_tls_target"))

    auth_start = time.perf_counter()
    api_start = time.perf_counter()
    auth_phase: dict[str, Any] | None = None
    api_phase: dict[str, Any] | None = None
    if spec.name == "wazuh":
        auth_url = f"{env.get('WAZUH_API_HOST', '').rstrip('/')}/security/user/authenticate"
        auth_probe = _http_probe_detailed("GET", auth_url, timeout_seconds, auth=(env.get("WAZUH_API_USER", ""), env.get("WAZUH_API_PASSWORD", "")))
        if auth_probe["ok"]:
            auth_phase = _phase_result("auth", "PASS", auth_start, evidence={"endpoint": auth_url, "http_status": auth_probe["status_code"]})
            idx_url = f"{env.get('WAZUH_INDEXER_HOST', '').rstrip('/')}/_cluster/health"
            idx_probe = _http_probe_detailed("GET", idx_url, timeout_seconds, auth=(env.get("WAZUH_INDEXER_USER", ""), env.get("WAZUH_INDEXER_PASSWORD", "")))
            api_phase = _phase_result("api", "PASS" if idx_probe["ok"] else "FAIL", api_start, None if idx_probe["ok"] else f"http_{idx_probe['status_code'] or idx_probe['error_kind']}", idx_probe["body_preview"] or idx_probe["error_text"], {"endpoint": idx_url, "http_status": idx_probe["status_code"]})
        else:
            auth_phase = _phase_result("auth", "FAIL", auth_start, f"http_{auth_probe['status_code']}" if auth_probe["status_code"] else (auth_probe["error_kind"] or "auth_error"), auth_probe["body_preview"] or auth_probe["error_text"], {"endpoint": auth_url, "http_status": auth_probe["status_code"]})
            _add_skipped(phases, "api", "blocked_by_auth")
    elif spec.name == "zabbix":
        api_url = env.get("ZABBIX_API_URL", "")
        login_body = {"jsonrpc": "2.0", "method": "user.login", "params": {"username": env.get("ZABBIX_USER", ""), "password": env.get("ZABBIX_PASS", "")}, "id": 2}
        auth_probe = _http_probe_detailed("POST", api_url, timeout_seconds, headers={"Content-Type": "application/json-rpc"}, json_body=login_body)
        auth_ok = auth_probe["ok"] and '"error"' not in auth_probe["body_preview"]
        auth_phase = _phase_result("auth", "PASS" if auth_ok else "FAIL", auth_start, None if auth_ok else f"http_{auth_probe['status_code'] or 'auth_error'}", auth_probe["body_preview"] or auth_probe["error_text"], {"endpoint": api_url, "http_status": auth_probe["status_code"]})
        if auth_ok:
            version_body = {"jsonrpc": "2.0", "method": "apiinfo.version", "params": {}, "id": 1}
            version_probe = _http_probe_detailed("POST", api_url, timeout_seconds, headers={"Content-Type": "application/json-rpc"}, json_body=version_body)
            api_phase = _phase_result("api", "PASS" if version_probe["ok"] else "FAIL", api_start, None if version_probe["ok"] else f"http_{version_probe['status_code'] or version_probe['error_kind']}", version_probe["body_preview"] or version_probe["error_text"], {"endpoint": api_url, "http_status": version_probe["status_code"]})
    elif spec.name == "openvas":
        auth_phase = _phase_result("auth", "SKIPPED", auth_start, "gmp_tcp_only")
        api_phase = _phase_result("api", "SKIPPED", api_start, "gmp_tcp_only")
    elif spec.name == "insightvm":
        info_url = f"{env.get('INSIGHTVM_BASE_URL', '').rstrip('/')}/administration/info"
        probe = _http_probe_detailed("GET", info_url, timeout_seconds, auth=(env.get("INSIGHTVM_USER", ""), env.get("INSIGHTVM_PASSWORD", "")))
        auth_ok = probe["ok"] or probe["status_code"] not in (401, 403)
        auth_phase = _phase_result("auth", "PASS" if auth_ok else "FAIL", auth_start, None if auth_ok else f"http_{probe['status_code']}", probe["body_preview"] or probe["error_text"], {"endpoint": info_url, "http_status": probe["status_code"]})
        api_phase = _phase_result("api", "PASS" if probe["ok"] else "FAIL", api_start, None if probe["ok"] else f"http_{probe['status_code'] or probe['error_kind']}", probe["body_preview"] or probe["error_text"], {"endpoint": info_url, "http_status": probe["status_code"]})
    elif spec.name == "uptimekuma":
        auth_phase = _phase_result("auth", "PASS", auth_start, evidence={"mode": "api_key_or_userpass_configured"})
        metrics_url = f"{env.get('UPTIME_KUMA_URL', '').rstrip('/')}{env.get('UPTIME_KUMA_METRICS_PATH', '/metrics')}"
        probe = _http_probe_detailed("GET", metrics_url, timeout_seconds)
        api_phase = _phase_result("api", "PASS" if probe["ok"] else "FAIL", api_start, None if probe["ok"] else f"http_{probe['status_code'] or probe['error_kind']}", probe["body_preview"] or probe["error_text"], {"endpoint": metrics_url, "http_status": probe["status_code"]})
    elif spec.name == "nessus":
        props_url = f"{env.get('NESSUS_BASE_URL', '').rstrip('/')}/server/properties"
        headers = {"X-ApiKeys": f"accessKey={env.get('NESSUS_ACCESS_KEY', '')}; secretKey={env.get('NESSUS_SECRET_KEY', '')}"}
        probe = _http_probe_detailed("GET", props_url, timeout_seconds, headers=headers)
        auth_ok = probe["ok"] or probe["status_code"] not in (401, 403)
        auth_phase = _phase_result("auth", "PASS" if auth_ok else "FAIL", auth_start, None if auth_ok else f"http_{probe['status_code']}", probe["body_preview"] or probe["error_text"], {"endpoint": props_url, "http_status": probe["status_code"]})
        status_url = f"{env.get('NESSUS_BASE_URL', '').rstrip('/')}/server/status"
        status_probe = _http_probe_detailed("GET", status_url, timeout_seconds)
        api_phase = _phase_result("api", "PASS" if status_probe["ok"] else "FAIL", api_start, None if status_probe["ok"] else f"http_{status_probe['status_code'] or status_probe['error_kind']}", status_probe["body_preview"] or status_probe["error_text"], {"endpoint": status_url, "http_status": status_probe["status_code"]})
    elif spec.name == "backend":
        auth_phase = _phase_result("auth", "SKIPPED", auth_start, "no_backend_auth_check")
        ingest_url = first_nonempty([env.get("TXDXAI_INGEST_URL"), env.get("WEBHOOK_URL")])
        probe = _http_probe_detailed("GET", ingest_url, timeout_seconds)
        ok = probe["ok"] or probe["status_code"] in (401, 403, 405)
        api_phase = _phase_result("api", "PASS" if ok else "FAIL", api_start, None if ok else f"http_{probe['status_code'] or probe['error_kind']}", probe["body_preview"] or probe["error_text"], {"endpoint": ingest_url, "http_status": probe["status_code"]})
    else:
        auth_phase = _phase_result("auth", "SKIPPED", auth_start, "no_precheck_implemented")
        api_phase = _phase_result("api", "SKIPPED", api_start, "no_precheck_implemented")

    if auth_phase:
        phases.append(auth_phase)
    if api_phase:
        phases.append(api_phase)

    passed = all(phase["status"] in {"PASS", "SKIPPED"} for phase in phases)
    failed_phase = next((phase for phase in phases if phase["status"] == "FAIL"), None)
    summary = "precheck PASS"
    if failed_phase:
        summary = f"{failed_phase['phase']} FAIL: {failed_phase.get('normalized_error') or failed_phase.get('raw_error_excerpt') or ''}"
    return PrecheckResult(spec.name, required, passed, summary, phases=phases, summary=summary)


def run_agent_precheck(spec: AgentSpec, base_env: dict[str, str], timeout_seconds: float) -> PrecheckResult:
    return run_agent_precheck_diagnostic(spec, base_env, timeout_seconds)


def resolve_startup_action(menu_enabled: bool, default_option: str, selected_agents: list[str]) -> tuple[str, str]:
    if not menu_enabled:
        return "run_and_continue", "selected"

    log("")
    log("Startup Menu (MAD)")
    log("1) Ejecutar pruebas (agentes seleccionados) + iniciar todos los agentes seleccionados (recomendado)")
    log("2) Ejecutar pruebas (agentes seleccionados) y salir")
    log("3) Omitir pruebas e iniciar todos los agentes seleccionados")
    log("4) Ejecutar pruebas de UNA integración + iniciar todos los agentes seleccionados")
    log("5) Ejecutar pruebas de UNA integración y salir")

    if not sys.stdin or not sys.stdin.isatty():
        log(f"No interactive console detected; using default option {default_option}")
        choice = default_option
    else:
        try:
            choice = input("Select option [1]: ").strip() or default_option
        except Exception:
            log(f"Could not read menu option; using default option {default_option}")
            choice = default_option

    mapping = {
        "1": "run_and_continue",
        "2": "run_and_exit",
        "3": "skip_and_continue",
        "4": "run_one_and_continue",
        "5": "run_one_and_exit",
    }
    action = mapping.get(choice)
    if action is None:
        log(f"Invalid menu option '{choice}'; using default option {default_option}")
        action = mapping.get(default_option, "run_and_continue")

    test_target = "selected"
    if action in {"run_one_and_continue", "run_one_and_exit"}:
        if not sys.stdin or not sys.stdin.isatty():
            test_target = selected_agents[0]
            log(f"No se detectó consola interactiva; usando la primera integración seleccionada para pruebas: {test_target}")
        else:
            log("Integraciones disponibles para modo de prueba única: " + ", ".join(selected_agents))
            try:
                raw_target = input(f"Integración a probar [{selected_agents[0]}]: ").strip().lower()
            except Exception:
                raw_target = ""
            test_target = raw_target or selected_agents[0]
            if test_target not in selected_agents:
                log(f"Integración inválida '{test_target}', usando valor por defecto {selected_agents[0]}")
                test_target = selected_agents[0]

    return action, test_target


def log_precheck_results(results: list[PrecheckResult]) -> tuple[int, int, list[PrecheckResult]]:
    log("")
    log("Integration Test Results (Global)")
    for idx, result in enumerate(results, start=1):
        status = "PASS" if result.passed else "FAIL"
        log(f"[{status}] {idx}. {result.name} | required={result.required} | {result.details}")

    passed_count = sum(1 for result in results if result.passed)
    total = len(results)
    failed_required = [result for result in results if result.required and not result.passed]
    log(f"Integration summary: {passed_count}/{total} tests passed")
    if failed_required:
        log("Required tests failed: " + ", ".join(result.name for result in failed_required))
    return passed_count, total, failed_required


def command_default(script_path: str) -> Callable[[str, dict[str, str]], list[str]]:
    def _builder(python_exec: str, env: dict[str, str]) -> list[str]:
        return [python_exec, str(ROOT / script_path)]

    return _builder


def detect_placeholder_env(env: dict[str, str]) -> list[str]:
    placeholder_tokens = ("your_", "changeme", "example", "replace_me", "<", ">")
    flagged: list[str] = []
    for key, value in env.items():
        key_u = key.upper()
        if not any(tok in key_u for tok in ("KEY", "TOKEN", "PASS", "PASSWORD", "USER", "URL", "HOST")):
            continue
        val = (value or "").strip()
        low = val.lower()
        if not val:
            continue
        if any(token in low for token in placeholder_tokens):
            flagged.append(key)
    return flagged


def sanitize_text(text: str, env: dict[str, str]) -> str:
    sanitized = text or ""
    sensitive_pattern = re.compile(r"(KEY|TOKEN|PASS|PASSWORD|SECRET|AUTHORIZATION|X-APIKEYS)", re.IGNORECASE)
    sensitive_values = []
    for key, value in env.items():
        if not value:
            continue
        if sensitive_pattern.search(key):
            sensitive_values.append(value)
    sensitive_values.extend(re.findall(r"(?i)authorization\s*:\s*[^\r\n]+", sanitized))
    sensitive_values.extend(re.findall(r"(?i)x-apikeys\s*:\s*[^\r\n]+", sanitized))
    for value in sorted(set(sensitive_values), key=len, reverse=True):
        if len(value) >= 4:
            sanitized = sanitized.replace(value, "***REDACTED***")
    sanitized = re.sub(r"(?i)(authorization\s*:\s*)([^\r\n]+)", r"\1***REDACTED***", sanitized)
    sanitized = re.sub(r"(?i)(x-apikeys\s*:\s*)([^\r\n]+)", r"\1***REDACTED***", sanitized)
    return sanitized


def classify_phase_from_details(details: str) -> str:
    low = (details or "").lower()
    if "env fail" in low or "missing_env" in low or "placeholder_env" in low:
        return "env"
    if "dns fail" in low or "dns_" in low or "invalid_host" in low:
        return "dns"
    if "tcp fail" in low or "timeout" in low or "refused" in low or "unreachable" in low:
        return "tcp"
    if "tls fail" in low or "tls_" in low:
        return "tls"
    if "auth" in low:
        return "auth"
    if "api" in low or "http_" in low:
        return "api"
    return "execution"


def command_once_or_none(spec: AgentSpec, python_exec: str, env: dict[str, str]) -> tuple[list[str] | None, str]:
    """
    Build a one-shot command for diagnostics.
    Returns (command, reason_if_none).
    """
    if spec.name == "nessus":
        return [python_exec, str(ROOT / "nessus_integration/agent.py"), "--once"], ""
    if spec.name == "uptimekuma":
        return [python_exec, str(ROOT / "uptimekuma_integration/agent.py"), "--once"], ""
    if spec.name == "insightvm":
        return [
            python_exec,
            str(ROOT / "insightVM_integration/main.py"),
            "--env",
            str(ROOT / ".env"),
            "--output",
            "security_data.json",
            "--normalized-output",
            "security_data_normalized.json",
            "--interval",
            "0",
        ], ""
    if spec.name == "zabbix":
        return [python_exec, str(ROOT / "zabix_integration/agent.py"), "--once"], ""
    if spec.name == "openvas":
        return [python_exec, str(ROOT / "openVAS_integration/main.py"), "--once"], ""
    if spec.name == "wazuh":
        return [python_exec, str(ROOT / "wazuh_integration/main.py"), "--once"], ""
    return None, "single-run command not implemented"


def command_insightvm(python_exec: str, env: dict[str, str]) -> list[str]:
    interval = env.get("INSIGHTVM_INTERVAL_SECONDS", "600")
    return [
        python_exec,
        str(ROOT / "insightVM_integration/main.py"),
        "--env",
        str(ROOT / ".env"),
        "--output",
        "security_data.json",
        "--normalized-output",
        "security_data_normalized.json",
        "--interval",
        interval,
    ]


def run_single_run_diagnostics(
    selected_specs: list[AgentSpec],
    base_env: dict[str, str],
    python_exec: str,
    timeout_seconds: float,
    target_scope: str = "selected",
    perform_precheck: bool = True,
) -> tuple[list[DiagnosticExecResult], Path]:
    started_perf = time.perf_counter()
    started_at = now()
    diag_root = ROOT / "runtime" / "diagnostics" / time.strftime("%Y%m%d_%H%M%S")
    diag_root.mkdir(parents=True, exist_ok=True)

    def env_snapshot_for(spec_env: dict[str, str]) -> dict[str, str]:
        relevant: dict[str, str] = {}
        for k, v in spec_env.items():
            key_u = k.upper()
            if any(tok in key_u for tok in ("TXDXAI", "WAZUH", "ZABBIX", "OPENVAS", "GVM", "INSIGHTVM", "UPTIME", "NESSUS", "API", "HOST", "URL", "USER", "PASS", "TOKEN", "SECRET", "KEY", "COMPANY")):
                relevant[k] = "***REDACTED***" if v else ""
        return relevant

    results: list[DiagnosticExecResult] = []
    env_snapshots: dict[str, dict[str, str]] = {}
    for spec in selected_specs:
        env = spec.build_env(base_env)
        env_snapshots[spec.name] = env_snapshot_for(env)
        if perform_precheck:
            precheck = run_agent_precheck_diagnostic(spec, base_env, timeout_seconds=5.0)
        else:
            precheck = PrecheckResult(
                name=spec.name,
                passed=True,
                required=True,
                details="startup precheck disabled",
                phases=[
                    {
                        "phase": "precheck",
                        "status": "SKIPPED",
                        "duration_ms": 0,
                        "normalized_error": "disabled_by_orchestrator",
                        "raw_error_excerpt": "startup precheck disabled",
                        "evidence": {},
                    }
                ],
                summary="precheck SKIPPED (disabled)",
            )
        command, reason = command_once_or_none(spec, python_exec, env)
        log_file_path = diag_root / f"{spec.name}.log"
        with open(log_file_path, "w", encoding="utf-8") as f:
            f.write(f"PRECHECK SUMMARY: {sanitize_text(precheck.summary, env)}\n")
            f.write(json.dumps({"phases": precheck.phases}, ensure_ascii=False, indent=2))
            f.write("\n\n")

        if command is None:
            result = DiagnosticExecResult(
                name=spec.name,
                status="SKIPPED",
                phase="execution",
                details=reason,
                raw_error_excerpt=reason,
                return_code=None,
                log_file=str(log_file_path),
                phases=precheck.phases + [{"phase": "execution", "status": "SKIPPED", "duration_ms": 0, "normalized_error": "single_run_not_implemented", "raw_error_excerpt": reason, "evidence": {}}],
                summary=precheck.summary,
            )
            with open(log_file_path, "a", encoding="utf-8") as f:
                f.write(f"SKIPPED: {sanitize_text(reason, env)}\n")
            results.append(result)
            log(f"[DIAG] {spec.name}: SKIPPED ({reason})")
            continue

        if perform_precheck and not precheck.passed:
            failed_phase = next((p for p in precheck.phases if p.get("status") == "FAIL"), None)
            phase = failed_phase.get("phase", "precheck") if failed_phase else classify_phase_from_details(precheck.details)
            raw_excerpt = sanitize_text(precheck.details, env)
            results.append(
                DiagnosticExecResult(
                    name=spec.name,
                    status="FAIL",
                    phase=phase,
                    details=precheck.details,
                    raw_error_excerpt=raw_excerpt,
                    return_code=None,
                    log_file=str(log_file_path),
                    phases=precheck.phases + [{"phase": "execution", "status": "SKIPPED", "duration_ms": 0, "normalized_error": "blocked_by_precheck", "raw_error_excerpt": raw_excerpt[:200], "evidence": {}}],
                    summary=precheck.summary,
                )
            )
            with open(log_file_path, "a", encoding="utf-8") as f:
                f.write("PRECHECK FAILED. EXECUTION SKIPPED.\n")
            log(f"[DIAG] {spec.name}: FAIL ({phase})")
            continue

        run_dir_path = ROOT / spec.run_dir if spec.run_dir else ROOT
        run_dir_path.mkdir(parents=True, exist_ok=True)
        log(f"[DIAG] Running single-run for {spec.name}: {' '.join(command)}")
        execution_start = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                cwd=str(run_dir_path),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout_seconds,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            output_raw = completed.stdout or ""
            output_sanitized = sanitize_text(output_raw, env)
            with open(log_file_path, "a", encoding="utf-8") as lf:
                lf.write(f"COMMAND: {' '.join(command)}\n")
                lf.write(f"WORKDIR: {run_dir_path}\n\n")
                lf.write(output_sanitized)
            status = "PASS" if completed.returncode == 0 else "FAIL"
            details = f"completed with return code {completed.returncode}"
            phase = "send" if status == "PASS" else "execution"
            raw_excerpt = output_sanitized[-600:] if output_sanitized else ""
            execution_phase = _phase_result(
                "execution",
                "PASS" if completed.returncode == 0 else "FAIL",
                execution_start,
                None if completed.returncode == 0 else f"return_code_{completed.returncode}",
                raw_excerpt,
                {"command": command, "workdir": str(run_dir_path), "return_code": completed.returncode},
            )
            results.append(
                DiagnosticExecResult(
                    name=spec.name,
                    status=status,
                    phase=phase,
                    details=details,
                    raw_error_excerpt=raw_excerpt,
                    return_code=completed.returncode,
                    log_file=str(log_file_path),
                    phases=precheck.phases + [execution_phase],
                    summary=f"{precheck.summary} | execution {status}",
                )
            )
            log(f"[DIAG] {spec.name}: {status} ({details})")
        except subprocess.TimeoutExpired:
            raw_timeout = f"TIMEOUT after {timeout_seconds}s"
            with open(log_file_path, "a", encoding="utf-8") as lf:
                lf.write(f"\nTIMEOUT after {timeout_seconds}s\n")
            execution_phase = _phase_result(
                "execution",
                "FAIL",
                execution_start,
                "timeout",
                raw_timeout,
                {"command": command, "workdir": str(run_dir_path)},
            )
            results.append(
                DiagnosticExecResult(
                    name=spec.name,
                    status="FAIL",
                    phase="execution",
                    details=f"timeout after {timeout_seconds}s",
                    raw_error_excerpt=raw_timeout,
                    return_code=None,
                    log_file=str(log_file_path),
                    phases=precheck.phases + [execution_phase],
                    summary=f"{precheck.summary} | execution FAIL",
                )
            )
            log(f"[DIAG] {spec.name}: FAIL (timeout after {timeout_seconds}s)")
        except Exception as exc:
            raw_exc = sanitize_text(f"{type(exc).__name__}: {exc}", env)
            with open(log_file_path, "a", encoding="utf-8") as lf:
                lf.write(f"\nERROR: {raw_exc}\n")
            execution_phase = _phase_result(
                "execution",
                "FAIL",
                execution_start,
                "execution_error",
                raw_exc,
                {"command": command, "workdir": str(run_dir_path)},
            )
            results.append(
                DiagnosticExecResult(
                    name=spec.name,
                    status="FAIL",
                    phase="execution",
                    details=f"execution error: {type(exc).__name__}: {exc}",
                    raw_error_excerpt=raw_exc,
                    return_code=None,
                    log_file=str(log_file_path),
                    phases=precheck.phases + [execution_phase],
                    summary=f"{precheck.summary} | execution FAIL",
                )
            )
            log(f"[DIAG] {spec.name}: FAIL (execution error)")

    report_payload = {
        "started_at": started_at,
        "finished_at": now(),
        "total_duration_ms": int((time.perf_counter() - started_perf) * 1000),
        "target_scope": target_scope,
        "env_snapshot_sanitized": env_snapshots,
        "results": [
            {
                "name": r.name,
                "status": r.status,
                "phase": r.phase,
                "details": r.details,
                "raw_error_excerpt": r.raw_error_excerpt,
                "return_code": r.return_code,
                "log_file": r.log_file,
                "phases": r.phases,
                "summary": r.summary,
            }
            for r in results
        ],
    }
    report_path = diag_root / "diagnostic_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, ensure_ascii=False, indent=2)
    return results, diag_root


AGENTS: list[AgentSpec] = [
    AgentSpec(
        name="wazuh",
        command_builder=command_default("wazuh_integration/main.py"),
        env_map={
            "WAZUH_OUTPUT_MODE": "OUTPUT_MODE",
            "WAZUH_POLL_INTERVAL_ALERTS": "POLL_INTERVAL_ALERTS",
            "WAZUH_POLL_INTERVAL_AGENTS": "POLL_INTERVAL_AGENTS",
            "WAZUH_RETRY_FAILED_INTERVAL_SECONDS": "RETRY_FAILED_INTERVAL_SECONDS",
            "WAZUH_HEARTBEAT_EMPTY_CYCLES": "HEARTBEAT_EMPTY_CYCLES",
            "WAZUH_SEND_HEARTBEAT": "SEND_HEARTBEAT",
            "WAZUH_MIN_RULE_LEVEL": "MIN_RULE_LEVEL",
            "WAZUH_CHECKPOINT_FILE": "CHECKPOINT_FILE",
            "WAZUH_ARTIFACTS_DIR": "ARTIFACTS_DIR",
            "WAZUH_LOG_LEVEL": "LOG_LEVEL",
            "WAZUH_HEALTH_HOST_PORT": "HEALTH_CHECK_PORT",
        },
        run_dir="runtime/wazuh",
    ),
    AgentSpec(
        name="zabbix",
        command_builder=command_default("zabix_integration/agent.py"),
        env_map={
            "ZABBIX_OUTPUT_MODE": "OUTPUT_MODE",
            "ZABBIX_INTERVAL": "INTERVAL",
            "ZABBIX_HOURS": "HOURS",
            "ZABBIX_PROBLEMS_LIMIT": "PROBLEMS_LIMIT",
            "ZABBIX_TRIGGERS_LIMIT": "TRIGGERS_LIMIT",
            "ZABBIX_EVENTS_LIMIT": "EVENTS_LIMIT",
            "ZABBIX_INCLUDE_EVENTS": "INCLUDE_EVENTS",
        },
        run_dir="runtime/zabbix",
    ),
    AgentSpec(
        name="openvas",
        command_builder=command_default("openVAS_integration/main.py"),
        env_map={
            "OPENVAS_OUTPUT_MODE": "OUTPUT_MODE",
            "OPENVAS_COLLECTOR": "COLLECTOR",
            "OPENVAS_POLL_SECONDS": "POLL_SECONDS",
            "OPENVAS_STATE_PATH": "STATE_PATH",
            "OPENVAS_DETAIL_LEVEL": "DETAIL_LEVEL",
        },
        run_dir="runtime/openvas",
    ),
    AgentSpec(
        name="insightvm",
        command_builder=command_insightvm,
        env_map={
            "INSIGHTVM_OUTPUT_MODE": "OUTPUT_MODE",
            "INSIGHTVM_STATE_FILE": "STATE_FILE",
            "INSIGHTVM_TIMEOUT": "INSIGHTVM_TIMEOUT",
        },
        run_dir="runtime/insightvm",
    ),
    AgentSpec(
        name="uptimekuma",
        command_builder=command_default("uptimekuma_integration/agent.py"),
        env_map={
            "UPTIME_OUTPUT_MODE": "OUTPUT_MODE",
            "UPTIME_SCANNER_TYPE": "SCANNER_TYPE",
            "UPTIME_POLL_INTERVAL_SECONDS": "POLL_INTERVAL_SECONDS",
            "UPTIME_FORCE_SEND_EVERY_CYCLES": "FORCE_SEND_EVERY_CYCLES",
            "UPTIME_INCLUDE_ALL_MONITORS": "INCLUDE_ALL_MONITORS",
            "UPTIME_INCLUDE_EXTENDED_FIELDS": "INCLUDE_EXTENDED_FIELDS",
        },
        run_dir="runtime/uptimekuma",
    ),
    AgentSpec(
        name="nessus",
        command_builder=command_default("nessus_integration/main.py"),
        env_map={
            "NESSUS_OUTPUT_MODE": "OUTPUT_MODE",
            "NESSUS_SCANNER_TYPE": "SCANNER_TYPE",
            "NESSUS_POLL_INTERVAL_SECONDS": "POLL_INTERVAL_SECONDS",
            "NESSUS_FORCE_SEND_EVERY_CYCLES": "FORCE_SEND_EVERY_CYCLES",
            "NESSUS_MAX_SCANS_PER_CYCLE": "NESSUS_MAX_SCANS_PER_CYCLE",
        },
        run_dir="runtime/nessus",
    ),
]


def stop_process(name: str, process: subprocess.Popen, timeout_seconds: int = 20) -> None:
    if process.poll() is not None:
        return

    log(f"Stopping {name} (pid={process.pid})")
    try:
        process.terminate()
        process.wait(timeout=timeout_seconds)
        log(f"{name} stopped gracefully")
    except subprocess.TimeoutExpired:
        log(f"{name} did not stop in time, killing it")
        process.kill()


def main() -> None:
    parser = argparse.ArgumentParser(description="Orquestador MAD todo-en-uno")
    parser.add_argument(
        "--agents",
        default=os.getenv("MAD_AGENTS", "all"),
        help="Lista separada por comas (ej. wazuh,zabbix) o 'all'",
    )
    parser.add_argument(
        "--restart-on-failure",
        default=os.getenv("MAD_RESTART_ON_FAILURE", "true"),
        help="true/false: reiniciar proceso hijo cuando termine inesperadamente",
    )
    parser.add_argument(
        "--restart-delay-seconds",
        type=int,
        default=int(os.getenv("MAD_RESTART_DELAY_SECONDS", "5")),
        help="Espera antes de reiniciar un proceso hijo fallido",
    )
    parser.add_argument(
        "--startup-menu-enabled",
        default=os.getenv("MAD_STARTUP_MENU_ENABLED", "true"),
        help="true/false: mostrar menú global de arranque",
    )
    parser.add_argument(
        "--startup-menu-default-option",
        default=os.getenv("MAD_STARTUP_MENU_DEFAULT_OPTION", "1"),
        help="Opción por defecto del menú en modo no interactivo (1/2/3/4/5)",
    )
    parser.add_argument(
        "--startup-require-all-tests",
        default=os.getenv("MAD_STARTUP_REQUIRE_ALL_TESTS", "true"),
        help="true/false: abortar arranque si falla cualquier precheck requerido",
    )
    parser.add_argument(
        "--startup-test-timeout-seconds",
        type=float,
        default=float(os.getenv("MAD_STARTUP_TEST_TIMEOUT_SECONDS", "3")),
        help="Timeout TCP para checks de conectividad por integración",
    )
    parser.add_argument(
        "--startup-test-target",
        default=os.getenv("MAD_STARTUP_TEST_TARGET", "selected"),
        help="selected|all|<integración>|lista separada por comas. Usado al ejecutar pruebas de arranque.",
    )
    parser.add_argument(
        "--diagnostic-single-run",
        default=os.getenv("MAD_DIAGNOSTIC_SINGLE_RUN", "false"),
        help="true/false: después de los prechecks, ejecutar diagnóstico one-shot por integración seleccionada/probada",
    )
    parser.add_argument(
        "--diagnostic-timeout-seconds",
        type=float,
        default=float(os.getenv("MAD_DIAGNOSTIC_TIMEOUT_SECONDS", "180")),
        help="timeout para cada comando de diagnóstico one-shot",
    )
    args = parser.parse_args()

    env_path = ROOT / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=False)
        log(f"Loaded environment from {env_path}")
    else:
        log("No .env found in repo root, using process environment only")

    python_exec = sys.executable
    base_env = dict(os.environ)
    restart_on_failure = parse_bool(args.restart_on_failure, default=True)
    menu_enabled = parse_bool(args.startup_menu_enabled, default=True)
    require_all_tests = parse_bool(args.startup_require_all_tests, default=True)
    diagnostic_single_run = parse_bool(args.diagnostic_single_run, default=False)
    available = [agent.name for agent in AGENTS]
    selected_names = parse_agents(args.agents, available)

    requested_specs = [agent for agent in AGENTS if agent.name in selected_names]
    if not requested_specs:
        raise SystemExit("No agents selected")

    selected_specs: list[AgentSpec] = []
    for spec in requested_specs:
        toggle_key = f"MAD_HAS_{spec.name.upper()}"
        is_enabled = parse_bool(base_env.get(toggle_key), default=True)
        if is_enabled:
            selected_specs.append(spec)
        else:
            log(f"{spec.name} disabled by {toggle_key}=false")

    if not selected_specs:
        raise SystemExit("No agents enabled after applying MAD_HAS_* flags")

    log(f"Selected agents: {', '.join(spec.name for spec in selected_specs)}")
    log(f"Restart on failure: {restart_on_failure}")

    action, menu_test_target = resolve_startup_action(
        menu_enabled=menu_enabled,
        default_option=args.startup_menu_default_option,
        selected_agents=[spec.name for spec in selected_specs],
    )
    test_specs: list[AgentSpec] = []
    if action != "skip_and_continue":
        if action in {"run_one_and_continue", "run_one_and_exit"}:
            effective_target_raw = menu_test_target
        else:
            effective_target_raw = args.startup_test_target

        test_target_names = parse_test_targets(
            effective_target_raw,
            selected=[spec.name for spec in selected_specs],
            available=[agent.name for agent in AGENTS],
        )
        test_specs = [spec for spec in AGENTS if spec.name in test_target_names]
        if DISABLE_STARTUP_PRECHECKS:
            log("Startup tests target: " + ", ".join(spec.name for spec in test_specs))
            log("Startup prechecks are disabled in this branch; skipping integration tests.")
            if action in {"run_and_exit", "run_one_and_exit"} and not diagnostic_single_run:
                raise SystemExit(0)
        else:
            log("Startup tests target: " + ", ".join(spec.name for spec in test_specs))

            results = [run_agent_precheck(spec, base_env, timeout_seconds=args.startup_test_timeout_seconds) for spec in test_specs]
            # Also test backend connectivity (non-required, won't block startup)
            backend_spec = AgentSpec(name="backend", command_builder=lambda p, e: [], env_map={})
            results.append(run_agent_precheck(backend_spec, base_env, timeout_seconds=args.startup_test_timeout_seconds))
            _, _, failed_required = log_precheck_results(results)

            if action in {"run_and_exit", "run_one_and_exit"}:
                raise SystemExit(0 if not failed_required else 1)

            if require_all_tests and failed_required:
                raise SystemExit("Startup aborted because required integration tests failed.")

    if diagnostic_single_run:
        diag_specs = test_specs if test_specs else selected_specs
        log("")
        log("Running diagnostic single-run execution...")
        diag_results, diag_dir = run_single_run_diagnostics(
            selected_specs=diag_specs,
            base_env=base_env,
            python_exec=python_exec,
            timeout_seconds=args.diagnostic_timeout_seconds,
            target_scope=args.startup_test_target,
            perform_precheck=not DISABLE_STARTUP_PRECHECKS,
        )
        pass_count = sum(1 for r in diag_results if r.status == "PASS")
        fail_count = sum(1 for r in diag_results if r.status == "FAIL")
        skip_count = sum(1 for r in diag_results if r.status == "SKIPPED")
        log(f"Diagnostic single-run summary: PASS={pass_count} FAIL={fail_count} SKIPPED={skip_count}")
        log(f"Diagnostic artifacts: {diag_dir}")

    process_table: dict[str, tuple[subprocess.Popen, AgentSpec]] = {}
    stopping = False

    def start_agent(spec: AgentSpec) -> subprocess.Popen:
        child_env = spec.build_env(base_env)
        # Evita doble menu global/local: Wazuh arranca sin bloquear ni abortar por sus propios prechecks.
        if spec.name == "wazuh":
            child_env.setdefault("STARTUP_MENU_ENABLED", "false")
            child_env.setdefault("STARTUP_REQUIRE_ALL_TESTS", "false")
        command = spec.command_builder(python_exec, child_env)
        run_dir_path = ROOT / spec.run_dir if spec.run_dir else ROOT
        run_dir_path.mkdir(parents=True, exist_ok=True)
        log(f"Starting {spec.name}: {' '.join(command)}")
        process = subprocess.Popen(command, cwd=str(run_dir_path), env=child_env)
        log(f"{spec.name} started with pid={process.pid}")
        return process

    def on_shutdown(signum, frame) -> None:
        nonlocal stopping
        if stopping:
            return
        stopping = True
        try:
            signal_name = signal.Signals(signum).name
        except Exception:
            signal_name = str(signum)
        log(f"Received signal {signal_name}, stopping all agents...")
        for name, (process, _) in list(process_table.items()):
            stop_process(name, process)

    signal.signal(signal.SIGINT, on_shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, on_shutdown)

    for spec in selected_specs:
        process_table[spec.name] = (start_agent(spec), spec)

    try:
        while process_table and not stopping:
            for name in list(process_table.keys()):
                process, spec = process_table[name]
                exit_code = process.poll()
                if exit_code is None:
                    continue

                log(f"{name} exited with code {exit_code}")
                if stopping:
                    process_table.pop(name, None)
                    continue

                if restart_on_failure:
                    log(f"Restarting {name} in {args.restart_delay_seconds}s")
                    time.sleep(args.restart_delay_seconds)
                    process_table[name] = (start_agent(spec), spec)
                else:
                    log(f"{name} will not be restarted")
                    process_table.pop(name, None)

            time.sleep(1)
    finally:
        if process_table:
            for name, (process, _) in list(process_table.items()):
                stop_process(name, process)

    log("Orchestrator finished")


if __name__ == "__main__":
    main()
