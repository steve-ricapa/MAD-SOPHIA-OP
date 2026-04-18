import aiohttp
import asyncio
import json
import gzip
from loguru import logger

class Sender:
    def __init__(self, ingest_url):
        self.ingest_url = ingest_url

    async def send_report(self, report, max_retries=3):
        """Sends the processed report to the backend (Compression disabled)."""
        api_key = None
        if isinstance(report, dict):
            api_key = report.get("api_key")

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["x-api-key"] = api_key
            headers["X-API-Key"] = api_key
            headers["Authorization"] = f"Bearer {api_key}"

        async with aiohttp.ClientSession(headers=headers) as session:
            for attempt in range(max_retries):
                try:
                    async with session.post(self.ingest_url, json=report) as resp:
                        if resp.status in [200, 201]:
                            logger.info(f"Report sent successfully (Status: {resp.status})")
                            return True
                        elif resp.status in [429, 500, 502, 503, 504]:
                            error_body = await resp.text()
                            wait = 2 ** attempt
                            logger.warning(f"Backend error {resp.status} - Body: {error_body} - retrying in {wait}s...")
                            await asyncio.sleep(wait)
                        else:
                            error_body = await resp.text()
                            logger.error(f"Backend rejected report: {resp.status} - Body: {error_body}")
                            return False
                except Exception as e:
                    wait = 2 ** attempt
                    logger.error(f"Connection failed: {e}, retrying in {wait}s...")
                    await asyncio.sleep(wait)
        return False
