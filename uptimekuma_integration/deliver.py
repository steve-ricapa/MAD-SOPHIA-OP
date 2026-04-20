import json
import os
import random
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

import requests

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class PermanentDeliveryError(RuntimeError):
    pass


class TransientDeliveryError(RuntimeError):
    pass


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


def _backoff_with_jitter(base_seconds: int, attempt: int, max_wait: int = 60) -> float:
    # Exponential backoff + jitter to reduce synchronized retries.
    exp_wait = min(max_wait, max(1, base_seconds) * (2 ** max(0, attempt - 1)))
    return exp_wait + random.uniform(0, 0.5 * exp_wait)


def send_webhook(
    webhook_url: str,
    payload: Dict[str, Any],
    api_key: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    retries: int = 3,
    backoff_seconds: int = 5,
    timeout: int = 30,
    verify_ssl: bool = True,
) -> None:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["x-api-key"] = api_key
        headers["Authorization"] = f"Bearer {api_key}"
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key

    last_error: Optional[Exception] = None
    max_attempts = max(retries, 1)

    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.post(
                webhook_url,
                json=payload,
                headers=headers,
                timeout=timeout,
                verify=verify_ssl,
            )

            if 200 <= response.status_code < 300:
                return

            body_snippet = (response.text or "")[:300]
            if response.status_code in RETRYABLE_STATUS_CODES:
                last_error = TransientDeliveryError(
                    f"HTTP {response.status_code} retriable response: {body_snippet}"
                )
                if attempt < max_attempts:
                    wait_for = _backoff_with_jitter(backoff_seconds, attempt)
                    print(
                        f"[WARN] Delivery attempt {attempt}/{max_attempts} retriable "
                        f"HTTP {response.status_code}. retry in {wait_for:.1f}s"
                    )
                    time.sleep(wait_for)
                    continue
                raise last_error

            raise PermanentDeliveryError(
                f"HTTP {response.status_code} non-retriable response: {body_snippet}"
            )
        except PermanentDeliveryError:
            raise
        except requests.RequestException as exc:
            last_error = exc
            if attempt < max_attempts:
                wait_for = _backoff_with_jitter(backoff_seconds, attempt)
                print(
                    f"[WARN] Delivery attempt {attempt}/{max_attempts} connection error: {exc}. "
                    f"retry in {wait_for:.1f}s"
                )
                time.sleep(wait_for)
                continue
            raise TransientDeliveryError(str(last_error)) from exc


def enqueue_payload(queue_dir: str | Path, payload: Dict[str, Any], idempotency_key: Optional[str]) -> Path:
    queue_path = Path(queue_dir)
    queue_path.mkdir(parents=True, exist_ok=True)

    item = {
        "enqueued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "idempotency_key": idempotency_key,
        "payload": payload,
    }
    file_name = f"{int(time.time() * 1000)}_{uuid.uuid4().hex}.json"
    file_path = queue_path / file_name
    write_json(file_path, item)
    return file_path


def _load_queue_item(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "payload" in data:
        return data
    return {"payload": data, "idempotency_key": None}


def flush_queue(
    *,
    queue_dir: str | Path,
    max_items: int,
    webhook_url: str,
    api_key: Optional[str],
    retries: int,
    backoff_seconds: int,
    timeout: int,
    verify_ssl: bool,
) -> int:
    queue_path = Path(queue_dir)
    if not queue_path.exists():
        return 0

    pending = sorted(queue_path.glob("*.json"))[: max(1, int(max_items))]
    if not pending:
        return 0

    flushed = 0
    dead_letter_dir = queue_path / "dead-letter"
    dead_letter_dir.mkdir(parents=True, exist_ok=True)

    for file_path in pending:
        try:
            item = _load_queue_item(file_path)
            payload = item.get("payload", {})
            idempotency_key = item.get("idempotency_key")
            if not isinstance(payload, dict):
                raise PermanentDeliveryError("Queue payload is not a JSON object")

            send_webhook(
                webhook_url=webhook_url,
                payload=payload,
                api_key=api_key,
                idempotency_key=idempotency_key,
                retries=retries,
                backoff_seconds=backoff_seconds,
                timeout=timeout,
                verify_ssl=verify_ssl,
            )
            file_path.unlink(missing_ok=True)
            flushed += 1
        except PermanentDeliveryError as exc:
            print(f"[ERROR] Queue item non-retriable, moved to dead-letter: {file_path.name} ({exc})")
            target = dead_letter_dir / file_path.name
            try:
                os.replace(file_path, target)
            except OSError:
                file_path.unlink(missing_ok=True)
        except TransientDeliveryError as exc:
            print(f"[WARN] Queue flush paused due transient error: {exc}")
            break
        except Exception as exc:
            print(f"[WARN] Queue flush paused due parse/unknown error: {file_path.name} ({exc})")
            break

    return flushed


def deliver(
    mode: str,
    report: Dict[str, Any],
    webhook_url: Optional[str],
    api_key: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    retries: int = 3,
    backoff_seconds: int = 5,
    timeout: int = 30,
    verify_ssl: bool = True,
    last_payload_path: Optional[str | Path] = None,
    queue_enabled: bool = True,
    queue_dir: Optional[str | Path] = None,
    queue_flush_max: int = 20,
) -> Dict[str, Any]:
    result = {"sent": False, "queued": False, "flushed_from_queue": 0}

    if mode == "stdout":
        send_stdout(report)
        return result

    if mode in ("webhook", "all"):
        if not webhook_url:
            raise SystemExit("[ERROR] OUTPUT_MODE requires TXDXAI_INGEST_URL")

        if queue_enabled and queue_dir:
            flushed = flush_queue(
                queue_dir=queue_dir,
                max_items=queue_flush_max,
                webhook_url=webhook_url,
                api_key=api_key,
                retries=retries,
                backoff_seconds=backoff_seconds,
                timeout=timeout,
                verify_ssl=verify_ssl,
            )
            if flushed > 0:
                print(f"[INFO] Flushed queued payloads: {flushed}")
            result["flushed_from_queue"] = flushed

        try:
            send_webhook(
                webhook_url=webhook_url,
                payload=report,
                api_key=api_key,
                idempotency_key=idempotency_key,
                retries=retries,
                backoff_seconds=backoff_seconds,
                timeout=timeout,
                verify_ssl=verify_ssl,
            )
            result["sent"] = True
            print("[SUCCESS] Data ingestion completed.")
        except PermanentDeliveryError as exc:
            print(f"[ERROR] Backend rejected non-retriable payload: {exc}")
            raise
        except TransientDeliveryError as exc:
            if queue_enabled and queue_dir:
                queued_file = enqueue_payload(queue_dir=queue_dir, payload=report, idempotency_key=idempotency_key)
                result["queued"] = True
                print(f"[WARN] Backend temporarily unavailable. Payload queued: {queued_file.name} ({exc})")
            else:
                raise

    if mode == "all" and last_payload_path:
        write_json(last_payload_path, report)

    return result
