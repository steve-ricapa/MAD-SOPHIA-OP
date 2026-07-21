import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from src.sender import Sender


class _Response:
    def __init__(self, status, text=""):
        self.status = status
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self):
        return self._text


class _Session:
    calls = []

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def post(self, url, json, headers):
        self.calls.append(("post", url, json, headers))
        return _Response(200, '{"upload_url":"https://s3.example/upload"}')

    def put(self, url, data, headers):
        self.calls.append(("put", url, data, headers))
        return _Response(200, "")


class TestSender(unittest.IsolatedAsyncioTestCase):
    async def test_send_report_requests_upload_url_then_puts_snapshot(self):
        _Session.calls = []
        report = {
            "scan_id": "scan-1",
            "tenant_id": 9,
            "company_id": 1,
            "api_key": "agent-key",
            "scanner_type": "wazuh",
            "idempotency_key": "sha256:abc",
            "findings": [],
        }

        with patch("src.sender.aiohttp.ClientSession", _Session):
            ok = await Sender("https://api.example/scans/upload-url").send_report(report, max_retries=1)

        self.assertTrue(ok)
        self.assertEqual(
            _Session.calls[0],
            (
                "post",
                "https://api.example/scans/upload-url",
                {
                    "tenant_id": 9,
                    "api_key": "agent-key",
                    "scanner_type": "wazuh",
                    "idempotency_key": "sha256:abc",
                },
                {"Content-Type": "application/json"},
            ),
        )
        self.assertEqual(_Session.calls[1][0], "put")
        self.assertEqual(_Session.calls[1][1], "https://s3.example/upload")
        self.assertEqual(_Session.calls[1][3], {"Content-Type": "application/json"})
        self.assertIn(b'"scan_id":"scan-1"', _Session.calls[1][2])


if __name__ == "__main__":
    unittest.main()
