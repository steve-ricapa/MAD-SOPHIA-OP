from opensearchpy import AsyncOpenSearch
from loguru import logger

class IndexerClient:
    def __init__(self, host, user, password, verify_certs=False):
        self.host = host
        self.verify_certs = verify_certs
        self.last_error = None
        self.last_error_kind = None
        self.last_operation = None
        self.client = AsyncOpenSearch(
            hosts=[host],
            http_auth=(user, password),
            use_ssl=True,
            verify_certs=verify_certs,
            ssl_show_warn=verify_certs
        )

    def _reset_last_result(self, operation):
        self.last_operation = operation
        self.last_error = None
        self.last_error_kind = None

    @staticmethod
    def _classify_exception(exc):
        message = str(exc).lower()
        if "certificate verify failed" in message or "ssl" in message:
            return "tls"
        if "timed out" in message:
            return "timeout"
        return "network"

    async def get_new_alerts(self, last_timestamp, limit=500):
        """
        Fetches alerts newer than last_timestamp.
        Querying the wazuh-alerts-* index.
        """
        query = {
            "query": {
                "range": {
                    "timestamp": {"gt": last_timestamp}
                }
            },
            "sort": [
                {"timestamp": {"order": "asc"}},
                {"_id": {"order": "asc"}}
            ],
            "size": limit
        }

        try:
            self._reset_last_result("get_new_alerts")
            response = await self.client.search(
                index="wazuh-alerts-*",
                body=query
            )
            hits = response['hits']['hits']
            alerts = []
            for hit in hits:
                source = hit['_source']
                source.setdefault('_id', hit.get('_id'))
                alerts.append(source)
            return alerts
        except Exception as e:
            self.last_error_kind = self._classify_exception(e)
            self.last_error = f"{type(e).__name__}: {e}"
            logger.error(
                "Error querying Indexer | host={} | verify_certs={} | kind={} | error={}",
                self.host,
                self.verify_certs,
                self.last_error_kind,
                self.last_error,
            )
            return []

    async def ping(self):
        """Checks basic connectivity/authentication against Wazuh Indexer."""
        try:
            self._reset_last_result("ping")
            return bool(await self.client.ping())
        except Exception as e:
            self.last_error_kind = self._classify_exception(e)
            self.last_error = f"{type(e).__name__}: {e}"
            logger.error(
                "Error pinging Indexer | host={} | verify_certs={} | kind={} | error={}",
                self.host,
                self.verify_certs,
                self.last_error_kind,
                self.last_error,
            )
            return False

    async def get_alerts_page(self, start_timestamp, end_timestamp=None, size=1000, search_after=None):
        """Fetches one sorted page of alerts for a time range."""
        timestamp_range = {"gte": start_timestamp}
        if end_timestamp:
            timestamp_range["lte"] = end_timestamp

        query = {
            "query": {
                "range": {
                    "timestamp": timestamp_range
                }
            },
            "sort": [
                {"timestamp": {"order": "asc"}},
                {"_id": {"order": "asc"}}
            ],
            "size": size
        }

        if search_after:
            query["search_after"] = search_after

        try:
            self._reset_last_result("get_alerts_page")
            response = await self.client.search(index="wazuh-alerts-*", body=query)
            hits = response['hits']['hits']
            alerts = []
            next_search_after = None

            for hit in hits:
                source = dict(hit.get('_source', {}))
                source.setdefault('_id', hit.get('_id'))
                alerts.append(source)
                next_search_after = hit.get('sort')

            return alerts, next_search_after
        except Exception as e:
            self.last_error_kind = self._classify_exception(e)
            self.last_error = f"{type(e).__name__}: {e}"
            logger.error(
                "Error paginating Indexer alerts | host={} | verify_certs={} | kind={} | error={}",
                self.host,
                self.verify_certs,
                self.last_error_kind,
                self.last_error,
            )
            return [], None

    async def get_alerts_range(self, start_timestamp, end_timestamp=None, batch_size=1000, max_alerts=None):
        """Fetches all alerts for a time range using paginated search_after."""
        all_alerts = []
        search_after = None

        while True:
            page_alerts, next_search_after = await self.get_alerts_page(
                start_timestamp=start_timestamp,
                end_timestamp=end_timestamp,
                size=batch_size,
                search_after=search_after,
            )

            if not page_alerts:
                break

            if max_alerts is not None:
                remaining = max_alerts - len(all_alerts)
                if remaining <= 0:
                    break
                all_alerts.extend(page_alerts[:remaining])
            else:
                all_alerts.extend(page_alerts)

            logger.info(f"Indexer range fetch progress: {len(all_alerts)} alerts collected")

            if len(page_alerts) < batch_size or next_search_after is None:
                break

            if max_alerts is not None and len(all_alerts) >= max_alerts:
                break

            search_after = next_search_after

        return all_alerts

    async def close(self):
        await self.client.close()
