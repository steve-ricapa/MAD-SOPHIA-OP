import argparse
import dataclasses
import hashlib
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from collector import NessusCollector
from config import load_config
from deliver import deliver, write_json
from snapshot import build_snapshot_signature
from mad_common.collector_delivery import private_json, run_snapshot_cycle
from summarizer import build_findings, build_report

NESSUS_BANNER = r"""
  _   _                             
 | \ | | ___  ___ ___ _   _ ___     
 |  \| |/ _ \/ __/ __| | | / __|    
 | |\  |  __/\__ \__ \ |_| \__ \    
 |_| \_|\___||___/___/\__,_|___/    
"""


def _initial_state() -> Dict[str, Any]:
    return {
        "processed_scans": {},
        "snapshot_signature": "",
        "unchanged_cycles": 0,
        "has_sent_once": False,
    }


def load_state(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return _initial_state()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        return _initial_state()
    except (json.JSONDecodeError, OSError):
        return _initial_state()


def save_state(path: Path, state: Dict[str, Any]) -> None:
    private_json(path, state)


def run_once(cfg, collector: NessusCollector, state: Dict[str, Any]) -> Dict[str, Any]:
    def collect():
        scans = collector.collect()
        private_json(cfg.raw_snapshot_path, scans)
        return scans

    def prepare(scans, baseline, decision):
        findings = build_findings(scans=scans, processed_scans=baseline.get("processed_scans", {}),
                                  include_all_findings=cfg.include_all_findings)
        report = build_report(
            scan_id=str(uuid.uuid4()), company_id=cfg.company_id, api_key=cfg.api_key,
            scanner_type=cfg.scanner_type, event_type=cfg.event_type, idempotency_key="",
            scans=scans, findings=findings["findings"], snapshot_signature=build_snapshot_signature(scans),
            snapshot_mode=decision["snapshot_mode"], send_reason=decision["reason"],
            snapshot_changed=decision["changed"], mad_version=cfg.mad_version,
            integration_version=cfg.integration_version, source=cfg.source)
        return report, {"processed_scans": findings["processed_scans"]}

    def send(report, key):
        return deliver(mode=cfg.output_mode, report=report, webhook_url=cfg.webhook_url,
                       tenant_id=getattr(cfg, "tenant_id", cfg.company_id), api_key=cfg.api_key,
                       idempotency_key=key, retries=cfg.http_retries, backoff_seconds=cfg.backoff_seconds,
                       timeout=cfg.request_timeout, verify_ssl=cfg.verify_ssl,
                       last_payload_path=cfg.last_payload_path, queue_enabled=False)

    persist = (lambda value: private_json(Path(cfg.state_path), value)) if hasattr(cfg, "state_path") else None
    return run_snapshot_cycle(integration="nessus", cfg=cfg, state=state, collect=collect,
                              signature=build_snapshot_signature, prepare=prepare, send=send, persist=persist)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Nessus real-time integration agent")
    parser.add_argument("--once", action="store_true", help="Run one cycle and exit")
    parser.add_argument(
        "--preview",
        action="store_true",
        help="Force stdout mode and ignore .env: print payload, do not deliver to backend",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print("[INFO] Starting Nessus Real-time Agent...")
    print(NESSUS_BANNER)
    cfg = load_config()
    if args.preview:
        cfg = dataclasses.replace(cfg, output_mode="stdout")
        print("[INFO] PREVIEW mode: payload a stdout, sin envio a backend.")
    collector = NessusCollector(cfg)
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
