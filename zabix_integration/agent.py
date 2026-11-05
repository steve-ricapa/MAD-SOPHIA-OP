import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from config import load_config
from snapshot import build_snapshot_signature
from mad_common.collector_delivery import private_json, run_snapshot_cycle
from zbx_api import ZabbixClient
from summarizer import summarize
from deliver import deliver, write_json

ZABBIX_BANNER = r"""
  ______       _     _     _
 |__  / | __ _| |__ | |__ (_)_  __
   / /| |/ _` | '_ \| '_ \| \ \/ /
  / /_| | (_| | |_) | |_) | |>  <
 /____|_|\__,_|_.__/|_.__/|_/_/\_\
"""


def _log(message: str) -> None:
    print(message, flush=True)


def _timed_fetch(timestamp: str, label: str, fetcher):
    _log(f"[{timestamp}] Fetching {label}...")
    started = time.perf_counter()
    data = fetcher()
    duration_ms = int((time.perf_counter() - started) * 1000)
    size = len(data) if hasattr(data, "__len__") else "unknown"
    _log(f"[{timestamp}] Fetched {label}: count={size} duration_ms={duration_ms}")
    return data


def _initial_state() -> Dict[str, Any]:
    return {
        "snapshot_signature": "",
        "unchanged_cycles": 0,
        "has_sent_once": False,
    }


def load_state(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return _initial_state()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        return _initial_state()
    except (json.JSONDecodeError, OSError):
        return _initial_state()


def atomic_json_dump(path: str | Path, data: Dict[str, Any]) -> None:
    target_path = Path(path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = target_path.with_suffix(target_path.suffix + ".tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(temp_path, target_path)


def save_state(path: str, state: Dict[str, Any]) -> None:
    private_json(Path(path), state)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Zabbix real-time integration agent")
    parser.add_argument("--once", action="store_true", help="Run one cycle and exit")
    return parser.parse_args()


def run_once(cfg, zbx, state):
    def collect():
        now = int(datetime.now(timezone.utc).timestamp())
        time_from = now - cfg.hours * 3600
        data = {
            "api_version": zbx.api_version(),
            "problems": zbx.get_problems(time_from=time_from, limit=cfg.problems_limit),
            "events": zbx.get_events(time_from=time_from, limit=cfg.events_limit) if cfg.include_events else [],
            "hosts": zbx.get_hosts(),
            "triggers": zbx.get_all_triggers(limit=cfg.triggers_limit),
        }
        for kind, limit in [("problems", cfg.problems_limit), ("events", cfg.events_limit), ("triggers", cfg.triggers_limit)]:
            if len(data[kind]) >= limit:
                _log(f"[WARN] {kind} limit reached ({limit}); source coverage may be partial")
        private_json(cfg.raw_snapshot_path, dict(data, saved_at_utc=datetime.now(timezone.utc).isoformat(), time_from=time_from, time_to=now))
        return data

    def signature(data):
        return build_snapshot_signature(data["problems"], data["events"], data["hosts"], data["triggers"])

    def prepare(data, baseline, decision):
        report, _ = summarize(
            scan_id=str(uuid.uuid4()), company_id=cfg.company_id, api_key=cfg.api_key,
            api_version=data["api_version"], idempotency_key="", problems=data["problems"],
            events=data["events"], all_hosts=data["hosts"], all_triggers=data["triggers"],
            snapshot_signature=signature(data), snapshot_mode=decision["snapshot_mode"],
            send_reason=decision["reason"], snapshot_changed=decision["changed"],
            mad_version=cfg.mad_version, integration_version=cfg.integration_version, source=cfg.source)
        return report, {}

    def send(report, key):
        return deliver(mode=cfg.output_mode, report=report, webhook_url=cfg.webhook_url,
                       tenant_id=getattr(cfg, "tenant_id", cfg.company_id), api_key=cfg.api_key,
                       idempotency_key=key, retries=cfg.http_retries, backoff_seconds=cfg.backoff_seconds,
                       timeout=cfg.request_timeout, verify_ssl=cfg.verify_ssl,
                       last_payload_path=cfg.last_payload_path, queue_enabled=False)

    return run_snapshot_cycle(integration="zabbix", cfg=cfg, state=state, collect=collect,
                              signature=signature, prepare=prepare, send=send,
                              persist=lambda value: private_json(Path(cfg.state_path), value))


def main():
    args = parse_args()
    _log("[INFO] Starting Zabbix integration")
    cfg = load_config()
    zbx = ZabbixClient(cfg.api_url, api_token=cfg.api_token, user=cfg.user, password=cfg.password,
                       timeout=cfg.request_timeout, verify_ssl=cfg.verify_ssl,
                       retries=cfg.http_retries, backoff_seconds=cfg.backoff_seconds)
    state = load_state(cfg.state_path)
    while True:
        try:
            state = run_once(cfg, zbx, state)
        except Exception as exc:
            _log(f"[ERROR] Cycle failure: {type(exc).__name__}")
            if args.once:
                raise SystemExit(1) from exc
            time.sleep(cfg.backoff_seconds)
            continue
        if args.once:
            break
        time.sleep(cfg.interval)


if __name__ == "__main__":
    main()
