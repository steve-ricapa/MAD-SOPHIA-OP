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

from collector import NessusCollector, parse_plugin_detail


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


def test_parse_plugin_detail_extracts_cve_cvss_host_port():
    data = {
        "info": {
            "plugin_id": "5678",
            "plugin_name": "SSH Weak Key Exchange",
            "severity": 3,
            "cvss_base_score": 7.5,
            "cvss_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "cvss3_base_score": 8.1,
            "solution": "Upgrade OpenSSH",
            "synopsis": "SSH allows weak algorithms.",
            "cve": "CVE-2016-6210,CVE-2016-20012",
        },
        "vulnerabilities": [
            {"hostname": "10.0.0.5", "ip": "10.0.0.5", "port": 22, "protocol": "tcp", "severity": 3,
             "plugin_output": "output text"},
        ],
    }

    findings = parse_plugin_detail(5678, data)
    assert len(findings) == 1
    assert findings[0]["cve"] == "CVE-2016-6210, CVE-2016-20012"
    assert findings[0]["cves"] == ["CVE-2016-6210", "CVE-2016-20012"]
    assert findings[0]["cvss_base_score"] == 7.5
    assert findings[0]["cvss3_base_score"] == 8.1
    assert findings[0]["host"] == "10.0.0.5"
    assert findings[0]["ip"] == "10.0.0.5"
    assert findings[0]["port"] == "22"
    assert findings[0]["protocol"] == "tcp"
    assert findings[0]["solution"] == "Upgrade OpenSSH"
    assert findings[0]["plugin_output"] == "output text"


def test_parse_plugin_detail_empty_entries_uses_info_severity():
    data = {
        "info": {"plugin_name": "Plugin X", "severity": 2, "cve": ""},
        "vulnerabilities": [],
    }
    findings = parse_plugin_detail(999, data)
    assert len(findings) == 1
    assert findings[0]["severity"] == 2
    assert findings[0]["host"] == "N/A"
    assert findings[0]["cves"] == []


def test_collect_falls_back_to_plugin_detail_when_export_unavailable(monkeypatch):
    collector = NessusCollector(_cfg(max_scans_per_cycle=1))
    detail_row = {"plugin_id": 5678, "cve": "CVE-2020-1234", "cvss_base_score": 9.8}

    monkeypatch.setattr(
        collector,
        "list_scans",
        lambda: [{"id": 2, "status": "completed", "last_modification_date": 20, "name": "Scan 2"}],
    )
    monkeypatch.setattr(
        collector,
        "get_scan_details",
        lambda sid: {
            "info": {"name": "Scan 2"},
            "vulnerabilities": [{"plugin_id": 5678, "severity": 3, "count": 1}],
            "hosts": [],
        },
    )
    monkeypatch.setattr(collector, "_enrich_scan_vulns", lambda _sid, vulns: None)
    monkeypatch.setattr(collector, "_enrich_scan_vulns_detail", lambda _sid, vulns: [detail_row])

    rows = collector.collect()
    assert rows[0]["vulnerabilities"] == [detail_row]
