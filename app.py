from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from dotenv import load_dotenv


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
    available = [agent.name for agent in AGENTS]
    selected_names = parse_agents(args.agents, available)

    selected_specs = [agent for agent in AGENTS if agent.name in selected_names]
    if not selected_specs:
        raise SystemExit("No agents selected")

    log(f"Selected agents: {', '.join(selected_names)}")
    log(f"Restart on failure: {restart_on_failure}")

    process_table: dict[str, tuple[subprocess.Popen, AgentSpec]] = {}
    stopping = False

    def start_agent(spec: AgentSpec) -> subprocess.Popen:
        child_env = spec.build_env(base_env)
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
