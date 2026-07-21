import sys
from pathlib import Path


for _module_name in ("services", "snapshot", "gvm_client", "config"):
    sys.modules.pop(_module_name, None)

OPENVAS_DIR = Path(__file__).resolve().parents[1]
if str(OPENVAS_DIR) not in sys.path:
    sys.path.insert(0, str(OPENVAS_DIR))

from services import emit_payload, map_status

def test_status():
    assert map_status("Running") == "running"
    assert map_status("Pending") == "pending"
    assert map_status("Done") == "completed"
    assert map_status("Completed") == "completed"


class _Response:
    def __init__(self, status_code, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_emit_payload_requests_upload_url_then_puts_snapshot(monkeypatch):
    calls = {"post": None, "put": None}

    def _post(url, json, headers, timeout, verify):
        calls["post"] = {
            "url": url,
            "json": json,
            "headers": headers,
            "timeout": timeout,
            "verify": verify,
        }
        return _Response(200, payload={"upload_url": "https://s3.example/upload"})

    def _put(url, data, headers, timeout, verify):
        calls["put"] = {
            "url": url,
            "data": data,
            "headers": headers,
            "timeout": timeout,
            "verify": verify,
        }
        return _Response(200)

    monkeypatch.setattr("services.requests.post", _post)
    monkeypatch.setattr("services.requests.put", _put)
    monkeypatch.setenv("BACKEND_TLS_VERIFY", "false")

    ok = emit_payload(
        output_mode="http",
        url="https://api.example/scans/upload-url",
        api_key="agent-key",
        tenant_id=9,
        company_id=4,
        payload={"scan_id": "OV-1", "scanner_type": "openvas", "idempotency_key": "sha256:abc", "findings": []},
        timeout=12,
    )

    assert ok is True
    assert calls["post"]["url"] == "https://api.example/scans/upload-url"
    assert calls["post"]["json"] == {
        "tenant_id": 9,
        "api_key": "agent-key",
        "scanner_type": "openvas",
        "idempotency_key": "sha256:abc",
    }
    assert calls["put"]["url"] == "https://s3.example/upload"
    assert calls["put"]["headers"] == {"Content-Type": "application/json"}
    assert b'"scan_id":"OV-1"' in calls["put"]["data"]
