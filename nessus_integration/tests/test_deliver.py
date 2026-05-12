import sys
from pathlib import Path

import pytest


NESSUS_DIR = Path(__file__).resolve().parents[1]
if str(NESSUS_DIR) not in sys.path:
    sys.path.insert(0, str(NESSUS_DIR))

import deliver


def test_deliver_webhook_success(monkeypatch, tmp_path):
    sent = {"ok": False}

    def _fake_send_webhook(**kwargs):
        sent["ok"] = True

    monkeypatch.setattr(deliver, "send_webhook", _fake_send_webhook)
    monkeypatch.setattr(deliver, "flush_queue", lambda **kwargs: 0)

    result = deliver.deliver(
        mode="webhook",
        report={"scan_id": "NE-1"},
        webhook_url="https://ingest.example/api/scans/ingest",
        api_key="k",
        idempotency_key="id-1",
        queue_enabled=True,
        queue_dir=tmp_path,
    )

    assert sent["ok"] is True
    assert result["sent"] is True
    assert result["queued"] is False


def test_deliver_transient_error_queues_payload(monkeypatch, tmp_path):
    def _transient(**kwargs):
        raise deliver.TransientDeliveryError("temporary")

    monkeypatch.setattr(deliver, "send_webhook", _transient)
    monkeypatch.setattr(deliver, "flush_queue", lambda **kwargs: 0)

    result = deliver.deliver(
        mode="webhook",
        report={"scan_id": "NE-2"},
        webhook_url="https://ingest.example/api/scans/ingest",
        api_key="k",
        idempotency_key="id-2",
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
            report={"scan_id": "NE-3"},
            webhook_url="https://ingest.example/api/scans/ingest",
            api_key="k",
            queue_enabled=False,
        )
