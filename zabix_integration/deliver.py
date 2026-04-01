import json
import os
import time
import requests
from pathlib import Path
from typing import Optional, Any, Dict


def write_json(path: str | Path, data: Any) -> None:
    target_path = Path(path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = target_path.with_suffix(target_path.suffix + ".tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(temp_path, target_path)

def send_stdout(data: Any) -> None:
    if isinstance(data, dict):
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print(data)

def send_webhook(
    webhook_url: str,
    payload: Dict[str, Any],
    api_key: Optional[str] = None,
    retries: int = 3,
    backoff_seconds: int = 5,
    timeout: int = 30,
) -> None:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["x-api-key"] = api_key

    last_error: Optional[Exception] = None
    for attempt in range(1, max(retries, 1) + 1):
        try:
            r = requests.post(webhook_url, json=payload, headers=headers, timeout=timeout)
            if r.status_code >= 400:
                print(f"[ERROR] Webhook rejected ({r.status_code}): {r.text}")
            r.raise_for_status()
            return
        except Exception as e:
            last_error = e
            print(f"[WARN] Delivery attempt {attempt}/{max(retries, 1)} failed: {str(e)}")
            if attempt < max(retries, 1):
                time.sleep(backoff_seconds)

    print(f"[ERROR] Critical delivery failure: {str(last_error)}")
    raise last_error or RuntimeError("Critical delivery failure without detailed exception")

def deliver(
    mode: str,
    report: Any,
    webhook_url: Optional[str],
    api_key: Optional[str] = None,
    retries: int = 3,
    backoff_seconds: int = 5,
    last_payload_path: Optional[str | Path] = None,
    timeout: int = 30,
) -> None:
    if mode == "stdout":
        send_stdout(report)
        return

    if mode in ("webhook", "all"):
        if not webhook_url:
            raise SystemExit("[ERROR] OUTPUT_MODE requires WEBHOOK_URL")

        print(f"[INFO] Synchronizing data with TxDxAI Backend...")
        payload = {"text": report} if isinstance(report, str) else report
        send_webhook(webhook_url, payload, api_key, retries=retries, backoff_seconds=backoff_seconds, timeout=timeout)
        print("[SUCCESS] Data ingestion completed.")

    if mode == "all" and last_payload_path:
        write_json(last_payload_path, report)
