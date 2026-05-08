import json
import os
import time
import uuid
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, Tuple, Optional

from config import load_config
from zbx_api import ZabbixClient
from summarizer import summarize
from deliver import deliver

ZABBIX_BANNER = r"""
  ______       _     _     _
 |__  / | __ _| |__ | |__ (_)_  __
   / /| |/ _` | '_ \| '_ \| \ \/ /
  / /_| | (_| | |_) | |_) | |>  <
 /____|_|\__,_|_.__/|_.__/|_/_/\_\
"""


def unix_now() -> int:
    return int(datetime.now(timezone.utc).timestamp())

def load_state(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}

def atomic_json_dump(path: str | Path, data: Dict[str, Any]) -> None:
    target_path = Path(path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = target_path.with_suffix(target_path.suffix + ".tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(temp_path, target_path)


def save_state(path: str, state: Dict[str, Any]) -> None:
    atomic_json_dump(path, state)

def compute_time_from(state: Dict[str, Any], hours_fallback: int) -> Tuple[int, int]:
    now = unix_now()
    last = state.get("last_run_utc")
    if isinstance(last, int) and last > 0:
        return int(last), now
    return now - hours_fallback * 3600, now


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Zabbix real-time integration agent")
    parser.add_argument("--once", action="store_true", help="Run one cycle and exit")
    return parser.parse_args()

def main():
    args = parse_args()
    print("[INFO] Starting Zabbix Real-time Agent...")
    print(ZABBIX_BANNER)
    cfg = load_config()
    zbx = ZabbixClient(
        cfg.api_url,
        cfg.user,
        cfg.password,
        timeout=cfg.request_timeout,
        verify_ssl=cfg.verify_ssl,
        retries=cfg.http_retries,
        backoff_seconds=cfg.backoff_seconds,
    )
    
    while True:
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # 1. Load state and version
            state = load_state(cfg.state_path)
            api_ver = zbx.api_version()
            time_from, now = compute_time_from(state, cfg.hours)

            # 2. Extract data from Zabbix
            problems = zbx.get_problems(time_from=time_from, limit=cfg.problems_limit)
            events = zbx.get_events(time_from=time_from, limit=cfg.events_limit) if cfg.include_events else []
            all_hosts = zbx.get_hosts()
            all_triggers = zbx.get_all_triggers(limit=cfg.triggers_limit)

            if len(problems) >= cfg.problems_limit:
                print(f"[{timestamp}] [WARN] Problems limit reached ({cfg.problems_limit}). Consider increasing PROBLEMS_LIMIT or paginating.")
            if len(all_triggers) >= cfg.triggers_limit:
                print(f"[{timestamp}] [WARN] Triggers limit reached ({cfg.triggers_limit}). Consider increasing TRIGGERS_LIMIT or paginating.")
            if cfg.include_events and len(events) >= cfg.events_limit:
                print(f"[{timestamp}] [WARN] Events limit reached ({cfg.events_limit}). Consider increasing EVENTS_LIMIT or disabling INCLUDE_EVENTS.")
            
            print(f"[{timestamp}] Zabbix Scan: {len(all_hosts)} hosts and {len(all_triggers)} triggers identified.")

            # 3. Generate Report (Delta Logic inside summarize)
            scan_id = str(uuid.uuid4())
            report, next_processed_findings = summarize(
                scan_id=scan_id,
                company_id=cfg.company_id,
                api_key=cfg.api_key,
                api_version=api_ver,
                problems=problems,
                events=events,
                all_hosts=all_hosts,
                all_triggers=all_triggers,
                state=state
            )

            # 4. Deliver if changes detected
            if report["findings"] or not state.get("processed_findings"):
                print(f"[{timestamp}] Prepared {len(report['findings'])} findings for delivery.")
                deliver(
                    cfg.output_mode,
                    report,
                    cfg.webhook_url,
                    cfg.api_key,
                    retries=cfg.http_retries,
                    backoff_seconds=cfg.backoff_seconds,
                    last_payload_path=cfg.last_payload_path,
                    timeout=cfg.request_timeout,
                )
                
                atomic_json_dump(cfg.debug_report_path, report)
            else:
                print(f"[{timestamp}] No changes detected. Skipping delivery.")

            # 5. Update state
            state["last_run_utc"] = now
            state["processed_findings"] = next_processed_findings
            save_state(cfg.state_path, state)
            
        except Exception as e:
            print(f"[ERROR] Cycle failure: {str(e)}")
            print(f"[INFO] Retrying in {cfg.backoff_seconds} seconds...")
            time.sleep(cfg.backoff_seconds)
            continue

        if args.once:
            print("[INFO] Single-run mode completed. Exiting.")
            break

        time.sleep(cfg.interval)

if __name__ == "__main__":
    main()
