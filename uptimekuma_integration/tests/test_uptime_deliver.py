import sys
from pathlib import Path

import pytest


for _module_name in ("deliver",):
    sys.modules.pop(_module_name, None)


UPTIME_DIR = Path(__file__).resolve().parents[1]
if str(UPTIME_DIR) not in sys.path:
    sys.path.insert(0, str(UPTIME_DIR))

import deliver


class _Response:
    def __init__(self, status_code, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_send_webhook_requests_upload_url_then_puts_snapshot(monkeypatch):
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

    monkeypatch.setattr(deliver.requests, "post", _post)
    monkeypatch.setattr(deliver.requests, "put", _put)

    payload = {"scan_id": "UK-1", "company_id": 4, "scanner_type": "uptime_kuma", "findings": []}
    deliver.send_webhook(
        webhook_url="https://api.example/scans/upload-url",
        payload=payload,
        tenant_id=9,
        api_key="agent-key",
        idempotency_key="sha256:abc",
        timeout=12,
        verify_ssl=False,
    )

    assert calls["post"]["url"] == "https://api.example/scans/upload-url"
    assert calls["post"]["json"] == {
        "tenant_id": 9,
        "api_key": "agent-key",
        "scanner_type": "uptime_kuma",
        "idempotency_key": "sha256:abc",
    }
    assert calls["put"]["url"] == "https://s3.example/upload"
    assert calls["put"]["headers"] == {"Content-Type": "application/json"}
    assert b'"scan_id":"UK-1"' in calls["put"]["data"]


def test_deliver_transient_error_queues_payload(monkeypatch, tmp_path):
    def _transient(**kwargs):
        raise deliver.TransientDeliveryError("temporary")

    monkeypatch.setattr(deliver, "send_webhook", _transient)
    monkeypatch.setattr(deliver, "flush_queue", lambda **kwargs: 0)

    result = deliver.deliver(
        mode="webhook",
        report={"scan_id": "UK-2"},
        webhook_url="https://ingest.example/scans/upload-url",
        tenant_id=4,
        api_key="k",
        idempotency_key="sha256:def",
        queue_enabled=True,
        queue_dir=tmp_path,
    )

    queued_files = list(Path(tmp_path).glob("*.json"))
    assert result["sent"] is False
    assert result["queued"] is True
    assert len(queued_files) == 1


def test_deliver_permanent_error_raises(monkeypatch):
    def _permanent(**kwargs):
        raise deliver.PermanentDeliveryError("bad request")

    monkeypatch.setattr(deliver, "send_webhook", _permanent)

    with pytest.raises(deliver.PermanentDeliveryError):
        deliver.deliver(
            mode="webhook",
            report={"scan_id": "UK-3"},
            webhook_url="https://ingest.example/scans/upload-url",
            tenant_id=4,
            api_key="k",
            queue_enabled=False,
        )
