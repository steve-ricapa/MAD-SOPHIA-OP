import argparse
import hashlib
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from collector import UptimeKumaCollector
from config import load_config
from deliver import deliver, write_json
from snapshot import build_snapshot_signature
from mad_common.collector_delivery import private_json, run_snapshot_cycle
from summarizer import build_findings, build_report

UPTIMEKUMA_BANNER = r"""
  _   _       _   _                 _  __
 | | | |_ __ | |_(_)_ __ ___   ___ | |/ /_   _ _ __ ___   __ _
 | | | | '_ \| __| | '_ ` _ \ / _ \| ' /| | | | '_ ` _ \ / _` |
 | |_| | |_) | |_| | | | | | |  __/| . \| |_| | | | | | | (_| |
  \___/| .__/ \__|_|_| |_| |_|\___||_|\_\\__,_|_| |_| |_|\__,_|
       |_|
"""


def _initial_state() -> Dict[str, Any]:
    return {
        "monitor_status": {},
        "snapshot_signature": "",
        "unchanged_cycles": 0,
        "has_sent_once": False,
        "last_idempotency_key": "",
        "last_sent_at": "",
        "last_send_result": "",
    }


def load_state(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return _initial_state()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return _initial_state()
        merged = _initial_state()
        merged.update(data)
        return merged
    except (json.JSONDecodeError, OSError):
        return _initial_state()


def save_state(path: Path, state: Dict[str, Any]) -> None:
    private_json(path, state)


def run_once(cfg, collector: UptimeKumaCollector, state: Dict[str, Any]) -> Dict[str, Any]:
    def collect():
        monitors = collector.collect()
        private_json(cfg.raw_snapshot_path, monitors)
        return monitors

    def prepare(monitors, baseline, decision):
        findings = build_findings(monitors=monitors, previous_statuses=baseline.get("monitor_status", {}),
                                  include_ongoing_non_up=True, include_all_monitors=cfg.include_all_monitors,
                                  include_extended_fields=cfg.include_extended_fields)
        report = build_report(
            scan_id=f"UK-{uuid.uuid4()}", company_id=cfg.company_id, api_key=cfg.api_key,
            scanner_type=cfg.scanner_type, event_type=cfg.event_type, idempotency_key="",
            monitors=monitors, findings=findings["findings"], snapshot_signature=build_snapshot_signature(monitors),
            snapshot_mode=decision["snapshot_mode"], send_reason=decision["reason"],
            snapshot_changed=decision["changed"], mad_version=cfg.mad_version,
            integration_version=cfg.integration_version, source=cfg.source)
        return report, {"monitor_status": findings["current_statuses"]}

    def send(report, key):
        return deliver(mode=cfg.output_mode, report=report, webhook_url=cfg.webhook_url,
                       tenant_id=getattr(cfg, "tenant_id", cfg.company_id), api_key=cfg.api_key,
                       idempotency_key=key, retries=cfg.http_retries, backoff_seconds=cfg.backoff_seconds,
                       timeout=cfg.request_timeout, verify_ssl=cfg.verify_ssl,
                       last_payload_path=cfg.last_payload_path, queue_enabled=False)

    persist = (lambda value: private_json(Path(cfg.state_path), value)) if hasattr(cfg, "state_path") else None
    return run_snapshot_cycle(integration="uptimekuma", cfg=cfg, state=state, collect=collect,
                              signature=build_snapshot_signature, prepare=prepare, send=send, persist=persist)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Uptime Kuma real-time integration agent")
    parser.add_argument("--once", action="store_true", help="Run a single collection cycle and exit")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print("[INFO] Starting Uptime Kuma Real-time Agent...")
    print(UPTIMEKUMA_BANNER)
    cfg = load_config()
    collector = UptimeKumaCollector(cfg)
    state = load_state(cfg.state_path)

    while True:
        try:
            state = run_once(cfg, collector, state)
            save_state(cfg.state_path, state)
        except KeyboardInterrupt:
            print("Stopped by user.")
            break
        except Exception as exc:
            print(f"[ERROR] Cycle failure: {exc}")
            if args.once:
                print("[ERROR] Single-run mode failed. Exiting (non-zero).")
                sys.exit(1)
            time.sleep(cfg.backoff_seconds)

        if args.once:
            break
        time.sleep(cfg.poll_interval)


if __name__ == "__main__":
    main()
