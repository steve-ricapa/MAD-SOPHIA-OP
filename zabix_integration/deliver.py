import json
import os
import time
import requests
from pathlib import Path
from typing import Optional, Any, Dict
from datetime import datetime, timezone
from uuid import uuid4


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


def _payload_debug_enabled() -> bool:
    return (os.getenv("ZABBIX_PAYLOAD_DEBUG", "false").strip().lower() in {"1", "true", "yes", "y", "on"})


def _collect_string_lengths(node: Any, path: str = "") -> Dict[str, int]:
    out: Dict[str, int] = {}
    if isinstance(node, dict):
        for k, v in node.items():
            next_path = f"{path}.{k}" if path else str(k)
            out.update(_collect_string_lengths(v, next_path))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out.update(_collect_string_lengths(v, f"{path}[{i}]"))
    elif isinstance(node, str):
        out[path or "$"] = len(node)
    return out


def _save_payload_debug(payload: Dict[str, Any], status_code: Optional[int], response_text: str, error_text: str = "") -> None:
    if not _payload_debug_enabled():
        return
    debug_dir = Path(os.getenv("ZABBIX_PAYLOAD_DEBUG_DIR", "runtime/payload_debug/zabbix"))
    debug_dir.mkdir(parents=True, exist_ok=True)
    scan_id = str(payload.get("scan_id") or payload.get("scanId") or "no_scan_id")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    base = f"{stamp}_{scan_id}_{uuid4().hex[:8]}".replace("/", "_").replace("\\", "_").replace(" ", "_")
    lengths = _collect_string_lengths(payload)
    top = sorted(lengths.items(), key=lambda kv: kv[1], reverse=True)[:40]
    meta = {
        "saved_at_utc": datetime.now(timezone.utc).isoformat(),
        "status_code": status_code,
        "response_excerpt": (response_text or "")[:1000],
        "error_text": (error_text or "")[:1000],
        "max_string_length": max(lengths.values()) if lengths else 0,
        "strings_over_255": [{"path": k, "length": v} for k, v in top if v > 255],
        "top_string_lengths": [{"path": k, "length": v} for k, v in top],
    }
    write_json(debug_dir / f"payload_{base}.json", payload)
    write_json(debug_dir / f"meta_{base}.json", meta)

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
            _save_payload_debug(payload, r.status_code, r.text or "")
            if r.status_code >= 400:
                print(f"[ERROR] Webhook rejected ({r.status_code}): {r.text}")
            r.raise_for_status()
            return
        except Exception as e:
            _save_payload_debug(payload, None, "", str(e))
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
