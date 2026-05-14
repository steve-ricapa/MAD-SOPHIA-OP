import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests


for _module_name in ("collector", "summarizer", "agent", "deliver", "config"):
    sys.modules.pop(_module_name, None)


NESSUS_DIR = Path(__file__).resolve().parents[1]
if str(NESSUS_DIR) not in sys.path:
    sys.path.insert(0, str(NESSUS_DIR))

from collector import NessusCollector


def _cfg(**overrides):
    base = {
        "nessus_access_key": "ak",
        "nessus_secret_key": "sk",
        "api_root": "https://nessus.local",
        "request_timeout": 5,
        "verify_ssl": False,
        "http_retries": 2,
        "backoff_seconds": 1,
        "scan_ids_filter": None,
        "folder_id_filter": None,
        "max_scans_per_cycle": 5,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class _Resp:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload


def test_collector_sets_nessus_apikey_header():
    collector = NessusCollector(_cfg())
    header = collector.session.headers.get("X-ApiKeys")
    assert header == "accessKey=ak; secretKey=sk"


def test_request_retries_then_succeeds(monkeypatch):
    collector = NessusCollector(_cfg())
    calls = {"n": 0}

    def _fake_request(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return _Resp(503, text="busy")
        return _Resp(200, payload={"ok": True})

    monkeypatch.setattr(collector.session, "request", _fake_request)
    monkeypatch.setattr("collector.time.sleep", lambda _: None)

    data = collector._request("GET", "/scans")
    assert data == {"ok": True}
    assert calls["n"] == 2


def test_request_network_error_raises_runtime(monkeypatch):
    collector = NessusCollector(_cfg(http_retries=1))

    def _fail(**kwargs):
        raise requests.RequestException("boom")

    monkeypatch.setattr(collector.session, "request", _fail)

    with pytest.raises(RuntimeError, match="Nessus request failed"):
        collector._request("GET", "/scans")


def test_collect_filters_status_and_limits(monkeypatch):
    collector = NessusCollector(_cfg(max_scans_per_cycle=1))

    monkeypatch.setattr(
        collector,
        "list_scans",
        lambda: [
            {"id": 1, "status": "running", "last_modification_date": 10},
            {"id": 2, "status": "completed", "last_modification_date": 20, "name": "Scan 2", "total_targets": 3},
            {"id": 3, "status": "imported", "last_modification_date": 30, "name": "Scan 3", "total_targets": 4},
        ],
    )
    monkeypatch.setattr(
        collector,
        "get_scan_details",
        lambda sid: {
            "info": {"name": f"Scan {sid}", "targets": "10.0.0.1", "scan_start": "s", "scan_end": "e"},
            "vulnerabilities": [],
            "hosts": [{"hostname": "h"}],
        },
    )

    rows = collector.collect()
    assert len(rows) == 1
    assert rows[0]["scan_id"] == 3
    assert rows[0]["status"].lower() == "imported"
