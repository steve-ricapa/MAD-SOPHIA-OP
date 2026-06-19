import asyncio
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from main import collect_missing_required_config, run_startup_integration_tests


class _FakeIndexer:
    def __init__(self):
        self.host = "https://indexer.local:9200"
        self.verify_certs = False
        self.last_operation = None
        self.last_error_kind = None
        self.last_error = None

    async def ping(self):
        self.last_operation = "ping"
        return True

    async def get_new_alerts(self, _last_timestamp, limit=1):
        return [{"_id": "evt-1"}][:limit]


class _FakeSender:
    def __init__(self):
        self.ingest_url = "https://ingest.local/api/scans/ingest"
        self.last_status_code = 200
        self.last_failure_kind = None
        self.last_error_body = None

    async def probe_endpoint(self, api_key=None, timeout_seconds=10):
        _ = api_key, timeout_seconds
        return True, "status=200"


class TestMainConfig(unittest.TestCase):
    def test_collect_missing_required_config_does_not_require_api(self):
        missing = collect_missing_required_config(
            company_id=4,
            api_key="k",
            ingest_url="https://ingest.local/api/scans/ingest",
            indexer_host="https://indexer.local:9200",
            indexer_user="user",
            indexer_pass="pass",
            api_host="",
            api_user="",
            api_pass="",
        )
        self.assertEqual(missing, [])

    def test_run_startup_integration_tests_marks_api_as_optional(self):
        results = asyncio.run(
            run_startup_integration_tests(
                indexer=_FakeIndexer(),
                api=None,
                sender=_FakeSender(),
                api_key="k",
                missing_required=[],
            )
        )

        api_result = next(r for r in results if r["name"] == "Wazuh API Authentication")
        indexer_result = next(r for r in results if r["name"] == "Wazuh Indexer Connectivity")

        self.assertFalse(api_result["required"])
        self.assertFalse(api_result["passed"])
        self.assertTrue(indexer_result["passed"])

    def test_run_startup_integration_tests_supports_api_disabled(self):
        results = asyncio.run(
            run_startup_integration_tests(
                indexer=_FakeIndexer(),
                api=None,
                sender=_FakeSender(),
                api_key="k",
                missing_required=[],
                api_enabled=False,
            )
        )

        api_result = next(r for r in results if r["name"] == "Wazuh API Authentication")

        self.assertFalse(api_result["required"])
        self.assertTrue(api_result["passed"])
        self.assertIn("WAZUH_API_ENABLED=false", api_result["details"])


if __name__ == "__main__":
    unittest.main()
