from __future__ import annotations

import json
import logging
import os
import random
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import requests

log = logging.getLogger("clients.backend")

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


def _payload_debug_enabled() -> bool:
    return os.getenv("INSIGHTVM_PAYLOAD_DEBUG", "false").strip().lower() in {"1", "true", "yes", "y", "on"}


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
    debug_dir = Path(os.getenv("INSIGHTVM_PAYLOAD_DEBUG_DIR", "runtime/payload_debug/insightvm"))
    debug_dir.mkdir(parents=True, exist_ok=True)
    scan_id = str(payload.get("scan_id") or payload.get("scanId") or "no_scan_id")
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    base = f"{stamp}_{scan_id}_{uuid.uuid4().hex[:8]}".replace("/", "_").replace("\\", "_").replace(" ", "_")
    lengths = _collect_string_lengths(payload)
    top = sorted(lengths.items(), key=lambda kv: kv[1], reverse=True)[:40]
    meta = {
        "saved_at_utc": datetime.utcnow().isoformat() + "Z",
        "status_code": status_code,
        "response_excerpt": (response_text or "")[:1000],
        "error_text": (error_text or "")[:1000],
        "max_string_length": max(lengths.values()) if lengths else 0,
        "strings_over_255": [{"path": k, "length": v} for k, v in top if v > 255],
        "top_string_lengths": [{"path": k, "length": v} for k, v in top],
    }
    write_json(debug_dir / f"payload_{base}.json", payload)
    write_json(debug_dir / f"meta_{base}.json", meta)


def _backoff_with_jitter(base_seconds: int, attempt: int, max_wait: int = 60) -> float:
    exp_wait = min(max_wait, max(1, base_seconds) * (2 ** max(0, attempt - 1)))
    return exp_wait + random.uniform(0, 0.5 * exp_wait)


class BackendClient:
    def __init__(
        self,
        ingest_url: str,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
    ) -> None:
        self.ingest_url = ingest_url
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = requests.Session()

    def send_webhook(
        self,
        payload: Dict[str, Any],
        idempotency_key: Optional[str] = None,
        retries: int = 3,
        backoff_seconds: int = 5,
        timeout: int = 60,
    ) -> None:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["x-api-key"] = self.api_key
            headers["Authorization"] = f"Bearer {self.api_key}"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key

        last_error: Optional[Exception] = None
        max_attempts = max(retries, 1)

        for attempt in range(1, max_attempts + 1):
            try:
                response = self.session.post(
                    self.ingest_url,
                    json=payload,
                    headers=headers,
                    timeout=timeout,
                    verify=self.verify_ssl,
                )
                _save_payload_debug(payload, response.status_code, response.text or "")

                if 200 <= response.status_code < 300:
                    return

                body_snippet = (response.text or "")[:300]
                if response.status_code in RETRYABLE_STATUS_CODES:
                    last_error = TransientDeliveryError(
                        f"HTTP {response.status_code} retriable: {body_snippet}"
                    )
                    if attempt < max_attempts:
                        wait_for = _backoff_with_jitter(backoff_seconds, attempt)
                        log.warning(
                            "Delivery attempt %s/%s retriable HTTP %s, retry in %.1fs",
                            attempt, max_attempts, response.status_code, wait_for,
                        )
                        time.sleep(wait_for)
                        continue
                    raise last_error

                raise PermanentDeliveryError(
                    f"HTTP {response.status_code} non-retriable: {body_snippet}"
                )
            except PermanentDeliveryError:
                raise
            except requests.RequestException as exc:
                _save_payload_debug(payload, None, "", str(exc))
                last_error = exc
                if attempt < max_attempts:
                    wait_for = _backoff_with_jitter(backoff_seconds, attempt)
                    log.warning(
                        "Delivery attempt %s/%s connection error: %s, retry in %.1fs",
                        attempt, max_attempts, exc, wait_for,
                    )
                    time.sleep(wait_for)
                    continue
                raise TransientDeliveryError(str(last_error)) from exc

    def enqueue_payload(
        self, queue_dir: str | Path, payload: Dict[str, Any], idempotency_key: Optional[str]
    ) -> Path:
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

    @staticmethod
    def _load_queue_item(path: Path) -> Dict[str, Any]:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "payload" in data:
            return data
        return {"payload": data, "idempotency_key": None}

    def flush_queue(
        self,
        *,
        queue_dir: str | Path,
        max_items: int,
        retries: int,
        backoff_seconds: int,
        timeout: int,
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
                item = self._load_queue_item(file_path)
                payload = item.get("payload", {})
                idempotency_key = item.get("idempotency_key")
                if not isinstance(payload, dict):
                    raise PermanentDeliveryError("Queue payload is not a JSON object")

                self.send_webhook(
                    payload=payload,
                    idempotency_key=idempotency_key,
                    retries=retries,
                    backoff_seconds=backoff_seconds,
                    timeout=timeout,
                )
                file_path.unlink(missing_ok=True)
                flushed += 1
            except PermanentDeliveryError as exc:
                log.error("Queue item non-retriable, moved to dead-letter: %s (%s)", file_path.name, exc)
                target = dead_letter_dir / file_path.name
                try:
                    os.replace(file_path, target)
                except OSError:
                    file_path.unlink(missing_ok=True)
            except TransientDeliveryError as exc:
                log.warning("Queue flush paused due transient error: %s", exc)
                break
            except Exception as exc:
                log.warning("Queue flush paused due parse/unknown error: %s (%s)", file_path.name, exc)
                break

        return flushed

    def send_data(
        self,
        data: Dict[str, Any],
        idempotency_key: Optional[str] = None,
        retries: int = 3,
        backoff_seconds: int = 5,
        timeout: int = 60,
        queue_enabled: bool = True,
        queue_dir: Optional[str | Path] = None,
        queue_flush_max: int = 20,
    ) -> Dict[str, Any]:
        result = {"sent": False, "queued": False, "flushed_from_queue": 0}

        if queue_enabled and queue_dir:
            flushed = self.flush_queue(
                queue_dir=queue_dir,
                max_items=queue_flush_max,
                retries=retries,
                backoff_seconds=backoff_seconds,
                timeout=timeout,
            )
            if flushed > 0:
                log.info("Flushed queued payloads: %s", flushed)
            result["flushed_from_queue"] = flushed

        try:
            self.send_webhook(
                payload=data,
                idempotency_key=idempotency_key,
                retries=retries,
                backoff_seconds=backoff_seconds,
                timeout=timeout,
            )
            result["sent"] = True
            log.info("Data ingestion completed.")
        except PermanentDeliveryError as exc:
            log.error("Backend rejected non-retriable payload: %s", exc)
            raise
        except TransientDeliveryError as exc:
            if queue_enabled and queue_dir:
                queued_file = self.enqueue_payload(
                    queue_dir=queue_dir, payload=data, idempotency_key=idempotency_key
                )
                result["queued"] = True
                log.warning("Backend unavailable. Payload queued: %s (%s)", queued_file.name, exc)
            else:
                raise

        return result
