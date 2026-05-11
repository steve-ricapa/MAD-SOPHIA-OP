import aiohttp
import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from loguru import logger

class Sender:
    def __init__(self, ingest_url):
        self.ingest_url = ingest_url
        self.last_status_code = None
        self.last_error_body = None
        self.last_failure_kind = None
        self.last_attempts = 0

    def _reset_last_result(self):
        self.last_status_code = None
        self.last_error_body = None
        self.last_failure_kind = None
        self.last_attempts = 0

    @staticmethod
    def _classify_failure(status_code, response_body):
        body = (response_body or "").lower()
        if status_code in (401, 403):
            return "auth"
        if status_code == 404:
            return "endpoint_not_found"
        if status_code == 400 and "api_key" in body and "required" in body:
            return "config_missing_api_key"
        if status_code in (429, 500, 502, 503, 504):
            return "transient_http"
        if 400 <= status_code < 500:
            return "validation"
        return "unknown"

    def is_last_failure_retryable(self):
        return self.last_failure_kind in {"network", "transient_http"}

    @staticmethod
    def _payload_debug_enabled():
        return os.getenv("WAZUH_PAYLOAD_DEBUG", "false").strip().lower() in {"1", "true", "yes", "y", "on"}

    @staticmethod
    def _collect_string_lengths(node, path=""):
        out = {}
        if isinstance(node, dict):
            for k, v in node.items():
                out.update(Sender._collect_string_lengths(v, f"{path}.{k}" if path else str(k)))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                out.update(Sender._collect_string_lengths(v, f"{path}[{i}]"))
        elif isinstance(node, str):
            out[path or "$"] = len(node)
        return out

    @staticmethod
    def _save_payload_debug(report, status_code, response_text="", error_text=""):
        if not isinstance(report, dict):
            return
        if not Sender._payload_debug_enabled():
            return
        debug_dir = Path(os.getenv("WAZUH_PAYLOAD_DEBUG_DIR", "runtime/payload_debug/wazuh"))
        debug_dir.mkdir(parents=True, exist_ok=True)
        scan_id = str(report.get("scan_id") or report.get("scanId") or "no_scan_id")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        base = f"{stamp}_{scan_id}_{uuid4().hex[:8]}".replace("/", "_").replace("\\", "_").replace(" ", "_")
        lengths = Sender._collect_string_lengths(report)
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
        with open(debug_dir / f"payload_{base}.json", "w", encoding="utf-8") as pf:
            json.dump(report, pf, ensure_ascii=False, indent=2)
        with open(debug_dir / f"meta_{base}.json", "w", encoding="utf-8") as mf:
            json.dump(meta, mf, ensure_ascii=False, indent=2)

    async def probe_endpoint(self, api_key=None, timeout_seconds=10):
        """Quick non-invasive endpoint check used by startup prechecks."""
        self._reset_last_result()

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["x-api-key"] = api_key
            headers["X-API-Key"] = api_key
            headers["Authorization"] = f"Bearer {api_key}"

        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        try:
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                async with session.options(self.ingest_url) as resp:
                    body = await resp.text()
                    self.last_status_code = resp.status
                    self.last_error_body = body

                    if resp.status in (200, 201, 202, 204, 405):
                        logger.info(
                            "Backend probe succeeded | status={} | endpoint={}",
                            resp.status,
                            self.ingest_url,
                        )
                        return True, f"status={resp.status}"

                    self.last_failure_kind = self._classify_failure(resp.status, body)
                    logger.error(
                        "Backend probe failed | status={} | kind={} | body={}",
                        resp.status,
                        self.last_failure_kind,
                        body,
                    )
                    return False, f"status={resp.status} kind={self.last_failure_kind}"
        except Exception as e:
            self.last_failure_kind = "network"
            self.last_error_body = str(e)
            logger.error("Backend probe connection error: {}", e)
            return False, f"network_error={e}"

    async def send_report(self, report, max_retries=3):
        """Sends the processed report to the backend (compression disabled)."""
        self._reset_last_result()

        api_key = None
        if isinstance(report, dict):
            api_key = report.get("api_key")

        if not api_key:
            self.last_failure_kind = "config_missing_api_key"
            self.last_error_body = "api_key missing in report payload"
            logger.error("Cannot send report: api_key is missing in payload")
            return False

        headers = {"Content-Type": "application/json"}
        headers["x-api-key"] = api_key
        headers["X-API-Key"] = api_key
        headers["Authorization"] = f"Bearer {api_key}"

        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            for attempt in range(max_retries):
                self.last_attempts = attempt + 1
                try:
                    async with session.post(self.ingest_url, json=report) as resp:
                        error_body = await resp.text()
                        self.last_status_code = resp.status
                        self.last_error_body = error_body
                        self._save_payload_debug(report, resp.status, error_body, "")

                        if resp.status in [200, 201]:
                            self.last_failure_kind = None
                            logger.info(
                                "Report sent successfully | status={} | attempt={}/{}",
                                resp.status,
                                attempt + 1,
                                max_retries,
                            )
                            return True

                        failure_kind = self._classify_failure(resp.status, error_body)
                        self.last_failure_kind = failure_kind

                        if failure_kind == "transient_http":
                            wait = 2 ** attempt
                            logger.warning(
                                "Backend transient error | status={} | attempt={}/{} | retry_in={}s | body={}",
                                resp.status,
                                attempt + 1,
                                max_retries,
                                wait,
                                error_body,
                            )
                            if attempt < max_retries - 1:
                                await asyncio.sleep(wait)
                            continue

                        logger.error(
                            "Backend rejected report | status={} | kind={} | body={}",
                            resp.status,
                            failure_kind,
                            error_body,
                        )
                        return False
                except Exception as e:
                    self.last_failure_kind = "network"
                    self.last_error_body = str(e)
                    self.last_status_code = None
                    self._save_payload_debug(report, None, "", str(e))
                    wait = 2 ** attempt
                    logger.error(
                        "Connection failed | attempt={}/{} | retry_in={}s | error={}",
                        attempt + 1,
                        max_retries,
                        wait,
                        e,
                    )
                    if attempt < max_retries - 1:
                        await asyncio.sleep(wait)

        logger.error(
            "Send report exhausted retries | kind={} | status={} | last_error={}",
            self.last_failure_kind,
            self.last_status_code,
            self.last_error_body,
        )
        return False
