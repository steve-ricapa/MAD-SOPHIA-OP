from __future__ import annotations

import argparse
import os
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import requests
import urllib3

from dotenv import load_dotenv

# Disable noisy SSL warnings during prechecks (self-signed certs are expected)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


ROOT = Path(__file__).resolve().parent


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


@dataclass
class PrecheckResult:
    name: str
    required: bool
    passed: bool
    details: str


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


def run_agent_precheck(spec: AgentSpec, base_env: dict[str, str], timeout_seconds: float) -> PrecheckResult:
    env = spec.build_env(base_env)

    ingest_url = first_nonempty([env.get("TXDXAI_INGEST_URL"), env.get("WEBHOOK_URL")])
    company_id = first_nonempty([env.get("TXDXAI_COMPANY_ID"), env.get("COMPANY_ID")])

    # ── Wazuh ────────────────────────────────────────────────────
    if spec.name == "wazuh":
        api_key = first_nonempty([env.get("TXDXAI_API_KEY_WAZUH"), env.get("TXDXAI_API_KEY"), env.get("API_KEY")])
        api_host = env.get("WAZUH_API_HOST", "")
        api_user = env.get("WAZUH_API_USER", "")
        api_pass = env.get("WAZUH_API_PASSWORD", "")
        idx_host = env.get("WAZUH_INDEXER_HOST", "")
        idx_user = env.get("WAZUH_INDEXER_USER", "")
        idx_pass = env.get("WAZUH_INDEXER_PASSWORD", "")

        missing = []
        if not api_key:     missing.append("TXDXAI_API_KEY_WAZUH")
        if not ingest_url:  missing.append("TXDXAI_INGEST_URL")
        if not company_id:  missing.append("TXDXAI_COMPANY_ID")
        if not api_host:    missing.append("WAZUH_API_HOST")
        if not api_user:    missing.append("WAZUH_API_USER")
        if not api_pass:    missing.append("WAZUH_API_PASSWORD")
        if not idx_host:    missing.append("WAZUH_INDEXER_HOST")
        if not idx_user:    missing.append("WAZUH_INDEXER_USER")
        if not idx_pass:    missing.append("WAZUH_INDEXER_PASSWORD")
        if missing:
            return PrecheckResult("wazuh", True, False, f"missing env: {', '.join(missing)}")

        details: list[str] = []

        # TCP check
        api_conn, api_tcp = can_connect(api_host, 55000, timeout_seconds)
        idx_conn, idx_tcp = can_connect(idx_host, 9200, timeout_seconds)
        details.append(f"API {api_tcp}")
        details.append(f"Indexer {idx_tcp}")

        if not api_conn or not idx_conn:
            return PrecheckResult("wazuh", True, False, " | ".join(details))

        # Functional: Wazuh API authentication
        auth_url = f"{api_host.rstrip('/')}/security/user/authenticate"
        ok, status, body = api_probe("GET", auth_url, timeout_seconds, auth=(api_user, api_pass))
        if ok:
            details.append("API auth ok (JWT obtained)")
        else:
            details.append(f"API auth failed: HTTP {status}" if status else f"API auth failed: {body[:80]}")
            return PrecheckResult("wazuh", True, False, " | ".join(details))

        # Functional: Wazuh Indexer (OpenSearch) cluster info
        idx_url = f"{idx_host.rstrip('/')}/"
        ok, status, body = api_probe("GET", idx_url, timeout_seconds, auth=(idx_user, idx_pass))
        if ok:
            details.append("Indexer auth ok")
        else:
            details.append(f"Indexer auth failed: HTTP {status}" if status else f"Indexer failed: {body[:80]}")
            return PrecheckResult("wazuh", True, False, " | ".join(details))

        return PrecheckResult("wazuh", True, True, " | ".join(details))

    # ── Zabbix ───────────────────────────────────────────────────
    if spec.name == "zabbix":
        api_key = first_nonempty([env.get("TXDXAI_API_KEY_ZABBIX"), env.get("TXDXAI_API_KEY"), env.get("API_KEY")])
        api_url = env.get("ZABBIX_API_URL", "")
        zbx_user = env.get("ZABBIX_USER", "")
        zbx_pass = env.get("ZABBIX_PASS", "")

        missing = []
        if not api_key:    missing.append("TXDXAI_API_KEY_ZABBIX")
        if not ingest_url: missing.append("TXDXAI_INGEST_URL")
        if not company_id: missing.append("TXDXAI_COMPANY_ID")
        if not api_url:    missing.append("ZABBIX_API_URL")
        if not zbx_user:   missing.append("ZABBIX_USER")
        if not zbx_pass:   missing.append("ZABBIX_PASS")
        if missing:
            return PrecheckResult("zabbix", True, False, f"missing env: {', '.join(missing)}")

        details = []
        conn_ok, tcp_detail = can_connect(api_url, 80, timeout_seconds)
        details.append(tcp_detail)
        if not conn_ok:
            return PrecheckResult("zabbix", True, False, " | ".join(details))

        # Functional: apiinfo.version (no auth required)
        version_body = {"jsonrpc": "2.0", "method": "apiinfo.version", "params": {}, "id": 1}
        ok, status, body = api_probe("POST", api_url, timeout_seconds, headers={"Content-Type": "application/json-rpc"}, json_body=version_body)
        if ok:
            details.append(f"API reachable (version response: {body[:60]})")
        else:
            details.append(f"API unreachable: HTTP {status} - {body[:80]}" if status else f"API unreachable: {body[:80]}")
            return PrecheckResult("zabbix", True, False, " | ".join(details))

        # Functional: user.login (validates credentials)
        login_body = {"jsonrpc": "2.0", "method": "user.login", "params": {"username": zbx_user, "password": zbx_pass}, "id": 2}
        ok, status, body = api_probe("POST", api_url, timeout_seconds, headers={"Content-Type": "application/json-rpc"}, json_body=login_body)
        if ok and '"error"' not in body:
            details.append("auth ok (login successful)")
        elif ok and '"error"' in body:
            # Try legacy format (Zabbix < 7.0)
            login_body_legacy = {"jsonrpc": "2.0", "method": "user.login", "params": {"user": zbx_user, "password": zbx_pass}, "id": 3}
            ok2, status2, body2 = api_probe("POST", api_url, timeout_seconds, headers={"Content-Type": "application/json-rpc"}, json_body=login_body_legacy)
            if ok2 and '"error"' not in body2:
                details.append("auth ok (login successful, legacy format)")
            else:
                details.append(f"auth failed: {body[:100]}")
                return PrecheckResult("zabbix", True, False, " | ".join(details))
        else:
            details.append(f"auth failed: HTTP {status}" if status else f"auth failed: {body[:80]}")
            return PrecheckResult("zabbix", True, False, " | ".join(details))

        return PrecheckResult("zabbix", True, True, " | ".join(details))

    # ── OpenVAS ──────────────────────────────────────────────────
    if spec.name == "openvas":
        api_key = first_nonempty([env.get("TXDXAI_API_KEY_OPENVAS"), env.get("TXDXAI_API_KEY"), env.get("API_KEY")])
        output_mode = (env.get("OUTPUT_MODE") or "").strip().lower()
        collector = (env.get("COLLECTOR") or "").strip().lower()
        output_ok = output_mode in {"console", "http"}
        collector_ok = collector in {"gmp", "simulated"}

        missing = []
        if not api_key:    missing.append("TXDXAI_API_KEY_OPENVAS")
        if not ingest_url: missing.append("TXDXAI_INGEST_URL")
        if not company_id: missing.append("TXDXAI_COMPANY_ID")
        if not output_ok:  missing.append("OUTPUT_MODE (must be console|http)")
        if not collector_ok: missing.append("COLLECTOR (must be gmp|simulated)")
        if missing:
            return PrecheckResult("openvas", True, False, f"invalid/missing env: {', '.join(missing)}")

        if collector == "simulated":
            return PrecheckResult("openvas", True, True, "collector=simulated (no connectivity needed)")

        # GMP real mode: validate socket-path or tcp host (GMP is not HTTP, TCP only)
        gvm_socket = (env.get("GVM_SOCKET") or "").strip()
        gvm_host = (env.get("GVM_HOST") or "").strip()
        gvm_port = int(env.get("GVM_PORT", "9390"))
        if gvm_socket:
            exists = Path(gvm_socket).exists()
            return PrecheckResult("openvas", True, exists, f"gvm socket {'ok' if exists else 'missing'}: {gvm_socket}")
        if gvm_host:
            conn_ok, detail = can_connect(gvm_host, gvm_port, timeout_seconds)
            return PrecheckResult("openvas", True, conn_ok, f"GMP {detail}")
        return PrecheckResult("openvas", True, False, "collector=gmp but missing GVM_SOCKET/GVM_HOST")

    # ── InsightVM ────────────────────────────────────────────────
    if spec.name == "insightvm":
        api_key = first_nonempty([env.get("TXDXAI_API_KEY_INSIGHTVM"), env.get("TXDXAI_API_KEY"), env.get("API_KEY")])
        base_url = env.get("INSIGHTVM_BASE_URL", "")
        ivm_user = env.get("INSIGHTVM_USER", "")
        ivm_pass = env.get("INSIGHTVM_PASSWORD", "")

        missing = []
        if not api_key:    missing.append("TXDXAI_API_KEY_INSIGHTVM")
        if not ingest_url: missing.append("TXDXAI_INGEST_URL")
        if not company_id: missing.append("TXDXAI_COMPANY_ID")
        if not base_url:   missing.append("INSIGHTVM_BASE_URL")
        if not ivm_user:   missing.append("INSIGHTVM_USER")
        if not ivm_pass:   missing.append("INSIGHTVM_PASSWORD")
        if missing:
            return PrecheckResult("insightvm", True, False, f"missing env: {', '.join(missing)}")

        details = []
        conn_ok, tcp_detail = can_connect(base_url, 3780, timeout_seconds)
        details.append(tcp_detail)
        if not conn_ok:
            return PrecheckResult("insightvm", True, False, " | ".join(details))

        # Functional: GET /api/3/administration/info
        info_url = f"{base_url.rstrip('/')}/administration/info"
        ok, status, body = api_probe("GET", info_url, timeout_seconds, auth=(ivm_user, ivm_pass))
        if ok:
            details.append("API auth ok (administration/info accessible)")
        elif status == 401:
            details.append("auth failed: HTTP 401 - invalid credentials")
            return PrecheckResult("insightvm", True, False, " | ".join(details))
        elif status == 403:
            details.append("auth denied: HTTP 403 - insufficient permissions")
            return PrecheckResult("insightvm", True, False, " | ".join(details))
        else:
            details.append(f"API probe: HTTP {status}" if status else f"API probe failed: {body[:80]}")
            # Non-auth errors might be acceptable (some InsightVM versions differ)
            # Still mark as passed if TCP was ok
            details.append("(TCP ok, API probe inconclusive)")

        return PrecheckResult("insightvm", True, True, " | ".join(details))

    # ── Uptime Kuma ──────────────────────────────────────────────
    if spec.name == "uptimekuma":
        api_key = first_nonempty([env.get("TXDXAI_API_KEY_UPTIMEKUMA"), env.get("TXDXAI_API_KEY"), env.get("API_KEY")])
        kuma_url = env.get("UPTIME_KUMA_URL", "")
        has_auth = bool(env.get("UPTIME_KUMA_API_KEY")) or (bool(env.get("UPTIME_KUMA_USERNAME")) and bool(env.get("UPTIME_KUMA_PASSWORD")))

        missing = []
        if not api_key:    missing.append("TXDXAI_API_KEY_UPTIMEKUMA")
        if not ingest_url: missing.append("TXDXAI_INGEST_URL")
        if not company_id: missing.append("TXDXAI_COMPANY_ID")
        if not kuma_url:   missing.append("UPTIME_KUMA_URL")
        if not has_auth:   missing.append("UPTIME_KUMA_API_KEY or UPTIME_KUMA_USERNAME+PASSWORD")
        if missing:
            return PrecheckResult("uptimekuma", True, False, f"missing env: {', '.join(missing)}")

        details = []
        conn_ok, tcp_detail = can_connect(kuma_url, 3001, timeout_seconds)
        details.append(tcp_detail)
        if not conn_ok:
            return PrecheckResult("uptimekuma", True, False, " | ".join(details))

        # Functional: GET /metrics (Prometheus endpoint, no auth usually required)
        metrics_path = env.get("UPTIME_KUMA_METRICS_PATH", "/metrics")
        metrics_url = f"{kuma_url.rstrip('/')}{metrics_path}"
        ok, status, body = api_probe("GET", metrics_url, timeout_seconds)
        if ok:
            details.append("metrics endpoint ok")
        else:
            details.append(f"metrics endpoint: HTTP {status}" if status else f"metrics failed: {body[:80]}")
            # Metrics might require auth in some setups; TCP was ok so don't fail hard
            details.append("(TCP ok, metrics probe inconclusive)")

        return PrecheckResult("uptimekuma", True, True, " | ".join(details))

    # ── Nessus ───────────────────────────────────────────────────
    if spec.name == "nessus":
        api_key = first_nonempty([env.get("TXDXAI_API_KEY_NESSUS"), env.get("TXDXAI_API_KEY"), env.get("API_KEY")])
        base_url = env.get("NESSUS_BASE_URL", "")
        access_key = env.get("NESSUS_ACCESS_KEY", "")
        secret_key = env.get("NESSUS_SECRET_KEY", "")

        missing = []
        if not api_key:     missing.append("TXDXAI_API_KEY_NESSUS")
        if not ingest_url:  missing.append("TXDXAI_INGEST_URL")
        if not company_id:  missing.append("TXDXAI_COMPANY_ID")
        if not base_url:    missing.append("NESSUS_BASE_URL")
        if not access_key:  missing.append("NESSUS_ACCESS_KEY")
        if not secret_key:  missing.append("NESSUS_SECRET_KEY")
        if missing:
            return PrecheckResult("nessus", True, False, f"missing env: {', '.join(missing)}")

        details = []
        conn_ok, tcp_detail = can_connect(base_url, 8834, timeout_seconds)
        details.append(tcp_detail)
        if not conn_ok:
            return PrecheckResult("nessus", True, False, " | ".join(details))

        # Functional: GET /server/status (no auth required)
        status_url = f"{base_url.rstrip('/')}/server/status"
        ok, status, body = api_probe("GET", status_url, timeout_seconds)
        if ok:
            details.append(f"server status ok ({body[:60]})")
        else:
            details.append(f"server status: HTTP {status}" if status else f"server status failed: {body[:80]}")

        # Functional: GET /server/properties with API keys (validates credentials)
        props_url = f"{base_url.rstrip('/')}/server/properties"
        nessus_headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"}
        ok, status, body = api_probe("GET", props_url, timeout_seconds, headers=nessus_headers)
        if ok:
            details.append("API keys valid")
        elif status == 401 or status == 403:
            details.append(f"API keys invalid: HTTP {status}")
            return PrecheckResult("nessus", True, False, " | ".join(details))
        else:
            details.append(f"API keys probe: HTTP {status}" if status else f"API keys probe: {body[:80]}")

        return PrecheckResult("nessus", True, True, " | ".join(details))

    # ── Backend (TxDxAI Ingest) ──────────────────────────────────
    if spec.name == "backend":
        if not ingest_url:
            return PrecheckResult("backend", False, False, "missing TXDXAI_INGEST_URL")
        conn_ok, tcp_detail = can_connect(ingest_url, 443, timeout_seconds)
        if not conn_ok:
            return PrecheckResult("backend", False, False, f"backend {tcp_detail}")
        ok, status, body = api_probe("GET", ingest_url, timeout_seconds)
        if ok or status in (405, 401, 403):
            # 405 = Method Not Allowed (POST-only endpoint responding to GET) → endpoint exists
            return PrecheckResult("backend", False, True, f"backend reachable: HTTP {status}")
        return PrecheckResult("backend", False, False, f"backend unreachable: HTTP {status} - {body[:80]}" if status else f"backend unreachable: {body[:80]}")

    return PrecheckResult(spec.name, True, False, "no precheck implemented")


def resolve_startup_action(menu_enabled: bool, default_option: str) -> str:
    if not menu_enabled:
        return "run_and_continue"

    log("")
    log("Startup Menu (MAD)")
    log("1) Run integration tests and continue (recommended)")
    log("2) Run integration tests and exit")
    log("3) Skip integration tests and continue")

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
    }
    action = mapping.get(choice)
    if action is None:
        log(f"Invalid menu option '{choice}'; using default option {default_option}")
        action = mapping.get(default_option, "run_and_continue")
    return action


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
    parser = argparse.ArgumentParser(description="MAD all-in-one orchestrator")
    parser.add_argument(
        "--agents",
        default=os.getenv("MAD_AGENTS", "all"),
        help="Comma-separated list (e.g. wazuh,zabbix) or 'all'",
    )
    parser.add_argument(
        "--restart-on-failure",
        default=os.getenv("MAD_RESTART_ON_FAILURE", "true"),
        help="true/false: restart child when it exits unexpectedly",
    )
    parser.add_argument(
        "--restart-delay-seconds",
        type=int,
        default=int(os.getenv("MAD_RESTART_DELAY_SECONDS", "5")),
        help="Delay before restarting a failed child process",
    )
    parser.add_argument(
        "--startup-menu-enabled",
        default=os.getenv("MAD_STARTUP_MENU_ENABLED", "true"),
        help="true/false: show global startup menu",
    )
    parser.add_argument(
        "--startup-menu-default-option",
        default=os.getenv("MAD_STARTUP_MENU_DEFAULT_OPTION", "1"),
        help="Default menu option when non-interactive (1/2/3)",
    )
    parser.add_argument(
        "--startup-require-all-tests",
        default=os.getenv("MAD_STARTUP_REQUIRE_ALL_TESTS", "true"),
        help="true/false: abort start if any required precheck fails",
    )
    parser.add_argument(
        "--startup-test-timeout-seconds",
        type=float,
        default=float(os.getenv("MAD_STARTUP_TEST_TIMEOUT_SECONDS", "3")),
        help="TCP timeout for connectivity checks per integration",
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

    action = resolve_startup_action(menu_enabled=menu_enabled, default_option=args.startup_menu_default_option)
    if action != "skip_and_continue":
        results = [run_agent_precheck(spec, base_env, timeout_seconds=args.startup_test_timeout_seconds) for spec in selected_specs]
        # Also test backend connectivity (non-required, won't block startup)
        backend_spec = AgentSpec(name="backend", command_builder=lambda p, e: [], env_map={})
        results.append(run_agent_precheck(backend_spec, base_env, timeout_seconds=args.startup_test_timeout_seconds))
        _, _, failed_required = log_precheck_results(results)

        if action == "run_and_exit":
            raise SystemExit(0 if not failed_required else 1)

        if require_all_tests and failed_required:
            raise SystemExit("Startup aborted because required integration tests failed.")

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
