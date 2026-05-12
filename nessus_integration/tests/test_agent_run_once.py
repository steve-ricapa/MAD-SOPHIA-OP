import sys
from pathlib import Path
from types import SimpleNamespace


NESSUS_DIR = Path(__file__).resolve().parents[1]
if str(NESSUS_DIR) not in sys.path:
    sys.path.insert(0, str(NESSUS_DIR))

import agent


def _cfg(tmp_path, **overrides):
    base = {
        "raw_snapshot_path": tmp_path / "raw.json",
        "force_send_every_cycles": 3,
        "include_all_findings": True,
        "company_id": 4,
        "scanner_type": "nessus",
        "event_type": "vuln_scan_report",
        "api_key": "k",
        "output_mode": "webhook",
        "webhook_url": "https://ingest.example/api/scans/ingest",
        "http_retries": 1,
        "backoff_seconds": 1,
        "request_timeout": 5,
        "verify_ssl": False,
        "last_payload_path": tmp_path / "last_payload.json",
        "queue_enabled": True,
        "queue_dir": tmp_path / "queue",
        "queue_flush_max": 10,
        "debug_report_path": tmp_path / "debug_report.json",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class _Collector:
    def __init__(self, scans):
        self._scans = scans

    def collect(self):
        return self._scans


def test_run_once_sends_and_updates_state(monkeypatch, tmp_path):
    cfg = _cfg(tmp_path)
    scans = [
        {
            "scan_id": 10,
            "scan_name": "Scan A",
            "status": "completed",
            "last_modification_date": 100,
            "targets": "10.0.0.1",
            "hosts_total": 1,
            "vulnerabilities": [{"plugin_id": 1, "plugin_name": "p1", "severity": 3, "count": 1}],
        }
    ]
    collector = _Collector(scans)

    calls = {"deliver": 0}
    monkeypatch.setattr(agent, "write_json", lambda path, data: None)

    def _fake_deliver(**kwargs):
        calls["deliver"] += 1
        return {"sent": True, "queued": False, "flushed_from_queue": 0}

    monkeypatch.setattr(agent, "deliver", _fake_deliver)

    state = {
        "processed_scans": {},
        "snapshot_signature": "",
        "unchanged_cycles": 0,
        "has_sent_once": False,
    }
    next_state = agent.run_once(cfg, collector, state)

    assert calls["deliver"] == 1
    assert next_state["has_sent_once"] is True
    assert next_state["unchanged_cycles"] == 0
    assert "10" in next_state["processed_scans"]
    assert next_state.get("last_idempotency_key", "").startswith("nessus-snapshot-")


def test_run_once_skips_send_when_unchanged(monkeypatch, tmp_path):
    scans = [
        {
            "scan_id": 20,
            "scan_name": "Scan B",
            "status": "completed",
            "last_modification_date": 200,
            "targets": "10.0.0.2",
            "hosts_total": 1,
            "vulnerabilities": [],
        }
    ]
    cfg = _cfg(tmp_path, force_send_every_cycles=5)
    collector = _Collector(scans)
    signature = agent.build_snapshot_signature(scans)

    monkeypatch.setattr(agent, "write_json", lambda path, data: None)

    def _unexpected_deliver(**kwargs):
        raise AssertionError("deliver should not be called")

    monkeypatch.setattr(agent, "deliver", _unexpected_deliver)

    state = {
        "processed_scans": {"20": 200},
        "snapshot_signature": signature,
        "unchanged_cycles": 1,
        "has_sent_once": True,
    }
    next_state = agent.run_once(cfg, collector, state)

    assert next_state["snapshot_signature"] == signature
    assert next_state["unchanged_cycles"] == 2
    assert next_state["has_sent_once"] is True
