import argparse
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from collector import UptimeKumaCollector
from config import load_config
from deliver import deliver, write_json
from summarizer import build_findings, build_report, build_status_signature

UPTIMEKUMA_BANNER = r"""
  _   _       _   _                 _  __
 | | | |_ __ | |_(_)_ __ ___   ___ | |/ /_   _ _ __ ___   __ _
 | | | | '_ \| __| | '_ ` _ \ / _ \| ' /| | | | '_ ` _ \ / _` |
 | |_| | |_) | |_| | | | | | |  __/| . \| |_| | | | | | | (_| |
  \___/| .__/ \__|_|_| |_| |_|\___||_|\_\\__,_|_| |_| |_|\__,_|
       |_|
"""


def load_state(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"monitor_status": {}, "snapshot_signature": "", "unchanged_cycles": 0, "has_sent_once": False}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"monitor_status": {}, "snapshot_signature": "", "unchanged_cycles": 0, "has_sent_once": False}
        return data
    except (json.JSONDecodeError, OSError):
        return {"monitor_status": {}, "snapshot_signature": "", "unchanged_cycles": 0, "has_sent_once": False}


def save_state(path: Path, state: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)
    tmp.replace(path)


def build_idempotency_key(company_id: int, scanner_type: str, event_type: str, snapshot_signature: str) -> str:
    raw = f"{company_id}:{scanner_type}:{event_type}:{snapshot_signature}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"uptimekuma-snapshot-{digest}"


def run_once(cfg, collector: UptimeKumaCollector, state: Dict[str, Any]) -> Dict[str, Any]:
    monitors = collector.collect()
    write_json(cfg.raw_snapshot_path, monitors)
    current_signature = build_status_signature(monitors)

    prev_signature = str(state.get("snapshot_signature", ""))
    unchanged_cycles = int(state.get("unchanged_cycles", 0) or 0)
    has_sent_once = bool(state.get("has_sent_once", False))

    changed = current_signature != prev_signature
    unchanged_cycles = 0 if changed else unchanged_cycles + 1
    should_send = changed or (unchanged_cycles >= cfg.force_send_every_cycles) or not has_sent_once

    next_state = dict(state)
    next_state["snapshot_signature"] = current_signature
    next_state["unchanged_cycles"] = unchanged_cycles
    idempotency_key = build_idempotency_key(cfg.company_id, cfg.scanner_type, cfg.event_type, current_signature)

    if not should_send:
        print(
            f"[{datetime.now(timezone.utc).isoformat()}] Sin cambios de estado "
            f"(ciclo={unchanged_cycles}/{cfg.force_send_every_cycles})."
        )
        return next_state

    prev_statuses = state.get("monitor_status", {}) if isinstance(state.get("monitor_status"), dict) else {}
    findings_result = build_findings(
        monitors=monitors,
        previous_statuses={str(k): int(v) for k, v in prev_statuses.items()},
        include_ongoing_non_up=not changed,
        include_all_monitors=cfg.include_all_monitors,
        include_extended_fields=cfg.include_extended_fields,
    )

    scan_id = f"UK-{uuid.uuid4()}"
    report = build_report(
        scan_id=scan_id,
        company_id=cfg.company_id,
        api_key=cfg.api_key,
        scanner_type=cfg.scanner_type,
        event_type=cfg.event_type,
        idempotency_key=idempotency_key,
        monitors=monitors,
        findings=findings_result["findings"],
    )

    delivery_result = deliver(
        mode=cfg.output_mode,
        report=report,
        webhook_url=cfg.webhook_url,
        api_key=cfg.api_key,
        idempotency_key=idempotency_key,
        retries=cfg.http_retries,
        backoff_seconds=cfg.backoff_seconds,
        timeout=cfg.request_timeout,
        verify_ssl=cfg.verify_ssl,
        last_payload_path=cfg.last_payload_path,
        queue_enabled=cfg.queue_enabled,
        queue_dir=cfg.queue_dir,
        queue_flush_max=cfg.queue_flush_max,
    )

    write_json(cfg.debug_report_path, report)
    next_state["monitor_status"] = findings_result["current_statuses"]
    next_state["unchanged_cycles"] = 0
    next_state["has_sent_once"] = True
    next_state["last_idempotency_key"] = idempotency_key
    print(
        f"[{datetime.now(timezone.utc).isoformat()}] Report sent | monitors={len(monitors)} "
        f"findings={len(report.get('findings', []))} sent={delivery_result.get('sent')} "
        f"queued={delivery_result.get('queued')} flushed={delivery_result.get('flushed_from_queue')}"
    )
    return next_state


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
            time.sleep(cfg.backoff_seconds)

        if args.once:
            break
        time.sleep(cfg.poll_interval)


if __name__ == "__main__":
    main()
