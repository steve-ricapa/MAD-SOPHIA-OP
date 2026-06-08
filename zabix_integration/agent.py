import argparse
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from config import load_config
from snapshot import build_idempotency_key, build_snapshot_signature, decide_snapshot_send
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
    atomic_json_dump(path, state)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Zabbix real-time integration agent")
    parser.add_argument("--once", action="store_true", help="Run one cycle and exit")
    return parser.parse_args()


def main():
    args = parse_args()
    _log("[INFO] Starting Zabbix Real-time Agent...")
    _log(ZABBIX_BANNER)
    cfg = load_config()
    cfg.artifacts_dir.mkdir(parents=True, exist_ok=True)
    cfg.queue_dir.mkdir(parents=True, exist_ok=True)
    zbx = ZabbixClient(
        cfg.api_url,
        api_token=cfg.api_token,
        user=cfg.user,
        password=cfg.password,
        timeout=cfg.request_timeout,
        verify_ssl=cfg.verify_ssl,
        retries=cfg.http_retries,
        backoff_seconds=cfg.backoff_seconds,
    )

    state = load_state(cfg.state_path)

    while True:
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            api_ver = zbx.api_version()
            now = int(datetime.now(timezone.utc).timestamp())
            time_from = now - cfg.hours * 3600

            problems = _timed_fetch(
                timestamp,
                "problems",
                lambda: zbx.get_problems(time_from=time_from, limit=cfg.problems_limit),
            )
            events = _timed_fetch(
                timestamp,
                "events",
                lambda: zbx.get_events(time_from=time_from, limit=cfg.events_limit),
            ) if cfg.include_events else []
            all_hosts = _timed_fetch(timestamp, "hosts", zbx.get_hosts)
            all_triggers = _timed_fetch(
                timestamp,
                "triggers",
                lambda: zbx.get_all_triggers(limit=cfg.triggers_limit),
            )

            atomic_json_dump(
                cfg.raw_snapshot_path,
                {
                    "saved_at_utc": datetime.now(timezone.utc).isoformat(),
                    "time_from": time_from,
                    "time_to": now,
                    "problems": problems,
                    "events": events,
                    "hosts": all_hosts,
                    "triggers": all_triggers,
                },
            )

            if len(problems) >= cfg.problems_limit:
                _log(f"[{timestamp}] [WARN] Problems limit reached ({cfg.problems_limit}). Consider increasing PROBLEMS_LIMIT or paginating.")
            if len(all_triggers) >= cfg.triggers_limit:
                _log(f"[{timestamp}] [WARN] Triggers limit reached ({cfg.triggers_limit}). Consider increasing TRIGGERS_LIMIT or paginating.")
            if cfg.include_events and len(events) >= cfg.events_limit:
                _log(f"[{timestamp}] [WARN] Events limit reached ({cfg.events_limit}). Consider increasing EVENTS_LIMIT or disabling INCLUDE_EVENTS.")

            _log(f"[{timestamp}] Zabbix Scan: {len(all_hosts)} hosts and {len(all_triggers)} triggers identified.")

            current_signature = build_snapshot_signature(problems, events, all_hosts, all_triggers)
            prev_signature = str(state.get("snapshot_signature", ""))
            unchanged_cycles = int(state.get("unchanged_cycles", 0) or 0)
            has_sent_once = bool(state.get("has_sent_once", False))

            snapshot_decision = decide_snapshot_send(
                current_signature=current_signature,
                previous_signature=prev_signature,
                unchanged_cycles=unchanged_cycles,
                has_sent_once=has_sent_once,
                force_send_every_cycles=int(cfg.force_send_every_cycles),
                snapshot_always_send=bool(cfg.snapshot_always_send),
            )
            send_reason = str(snapshot_decision.get("reason", "snapshot_changed"))
            should_send = bool(snapshot_decision.get("should_send", False))
            snapshot_changed = bool(snapshot_decision.get("changed", False))
            unchanged_cycles = int(snapshot_decision.get("unchanged_cycles", 0))
            snapshot_mode = "always" if cfg.snapshot_always_send else "delta_with_periodic_forced"

            state["snapshot_signature"] = current_signature
            state["unchanged_cycles"] = unchanged_cycles

            if not should_send:
                state["last_send_result"] = "skipped_no_change"
                _log(
                    f"[{timestamp}] Snapshot sin cambios "
                    f"(ciclo={unchanged_cycles}/{cfg.force_send_every_cycles}) "
                    f"reason={send_reason}"
                )
                save_state(cfg.state_path, state)
                if args.once:
                    break
                time.sleep(cfg.interval)
                continue

            scan_id = str(uuid.uuid4())
            idempotency_key = build_idempotency_key(
                cfg.company_id, "zabbix", "vuln_scan_report", current_signature
            )
            report, _ = summarize(
                scan_id=scan_id,
                company_id=cfg.company_id,
                api_key=cfg.api_key,
                api_version=api_ver,
                idempotency_key=idempotency_key,
                problems=problems,
                events=events,
                all_hosts=all_hosts,
                all_triggers=all_triggers,
                snapshot_signature=current_signature,
                snapshot_mode=snapshot_mode,
                send_reason=send_reason,
                snapshot_changed=snapshot_changed,
                mad_version=cfg.mad_version,
                integration_version=cfg.integration_version,
                source=cfg.source,
            )

            _log(f"[{timestamp}] Prepared {len(report['findings'])} findings for delivery (reason={send_reason}).")

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
            write_json(
                cfg.delivery_meta_path,
                {
                    "saved_at_utc": datetime.now(timezone.utc).isoformat(),
                    "scan_id": scan_id,
                    "mode": cfg.output_mode,
                    "sent": delivery_result.get("sent", False),
                    "queued": delivery_result.get("queued", False),
                    "flushed_from_queue": delivery_result.get("flushed_from_queue", 0),
                },
            )

            state["snapshot_signature"] = current_signature
            state["unchanged_cycles"] = 0
            state["has_sent_once"] = True
            state["last_idempotency_key"] = idempotency_key
            state["last_send_result"] = "sent" if delivery_result.get("sent") else "queued"

            _log(
                f"[{timestamp}] Report sent | findings={len(report['findings'])} "
                f"sent={delivery_result.get('sent')} "
                f"queued={delivery_result.get('queued')} "
                f"flushed={delivery_result.get('flushed_from_queue')} "
                f"reason={send_reason}"
            )

            save_state(cfg.state_path, state)

        except Exception as e:
            _log(f"[ERROR] Cycle failure: {str(e)}")
            _log(f"[INFO] Retrying in {cfg.backoff_seconds} seconds...")
            time.sleep(cfg.backoff_seconds)
            continue

        if args.once:
            _log("[INFO] Single-run mode completed. Exiting.")
            break

        time.sleep(cfg.interval)


if __name__ == "__main__":
    main()
