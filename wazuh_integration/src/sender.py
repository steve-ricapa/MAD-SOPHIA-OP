import aiohttp
import asyncio
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
