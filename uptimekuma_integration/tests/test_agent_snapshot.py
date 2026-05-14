import sys
from pathlib import Path
from types import SimpleNamespace


for _module_name in ("agent", "collector", "summarizer", "deliver", "config", "snapshot"):
    sys.modules.pop(_module_name, None)


UPTIME_DIR = Path(__file__).resolve().parents[1]
if str(UPTIME_DIR) not in sys.path:
    sys.path.insert(0, str(UPTIME_DIR))

import agent
import snapshot


def _cfg(tmp_path, **overrides):
    base = {
        "raw_snapshot_path": tmp_path / "raw_monitors_snapshot.json",
        "force_send_every_cycles": 6,
        "snapshot_always_send": False,
        "include_all_monitors": True,
        "include_extended_fields": False,
        "company_id": 4,
        "scanner_type": "uptimekuma",
        "event_type": "vuln_scan_report",
        "api_key": "api-k",
        "output_mode": "webhook",
        "webhook_url": "https://ingest.example/api/scans/ingest",
        "http_retries": 1,
        "backoff_seconds": 1,
        "request_timeout": 5,
        "verify_ssl": True,
        "last_payload_path": tmp_path / "last_payload_sent.json",
        "queue_enabled": True,
        "queue_dir": tmp_path / "queue",
        "queue_flush_max": 10,
        "debug_report_path": tmp_path / "debug_report.json",
        "poll_interval": 10,
        "mad_version": "2.3.0",
        "integration_version": "1.0.0",
        "source": "mad-collector",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class _Collector:
    def __init__(self, monitors):
        self._monitors = monitors

    def collect(self):
        return self._monitors


def _sample_monitors(status: int = 1):
    return {
        "1": {
            "id": "1",
            "name": "web-api",
            "status": status,
            "type": "http",
            "url": "https://api.example.com",
            "hostname": "api.example.com",
            "port": "443",
            "response_time_ms": 120.0,
            "response_time_seconds_30d": 0.12,
            "response_time_seconds_365d": 0.15,
            "uptime_1d": 0.99,
            "uptime_30d": 0.98,
            "uptime_365d": 0.97,
            "cert_days_remaining": 45.0,
            "cert_is_valid": True,
            "db": {},
        }
    }


def test_status_signature_stable_order():
    a = {"10": {"status": 1}, "2": {"status": 0}}
    b = {"2": {"status": 0}, "10": {"status": 1}}
    assert snapshot.build_snapshot_signature(a) == snapshot.build_snapshot_signature(b)


def test_run_once_sends_snapshot_with_metadata(monkeypatch, tmp_path):
    cfg = _cfg(tmp_path)
    collector = _Collector(_sample_monitors(status=0))
    captured = {"report": None}

    monkeypatch.setattr(agent, "write_json", lambda path, data: None)

    def _fake_deliver(**kwargs):
        captured["report"] = kwargs["report"]
        return {"sent": True, "queued": False, "flushed_from_queue": 0}

    monkeypatch.setattr(agent, "deliver", _fake_deliver)

    state = agent._initial_state()
    next_state = agent.run_once(cfg, collector, state)

    assert next_state["has_sent_once"] is True
    assert next_state["last_send_result"] == "sent"
    meta = captured["report"]["scan_summary"]["meta"]
    assert meta["schema_version"] == "1.0"
    assert meta["mad_version"] == "2.3.0"
    assert meta["integration_version"] == "1.0.0"
    assert meta["source"] == "mad-collector"
    assert meta["snapshot_mode"] == "delta_with_periodic_forced"
    assert meta["send_reason"] == "first_snapshot"
    assert isinstance(meta["snapshot_signature"], str)
    results = captured["report"]["scan_summary"]["results"]
    assert results["critical"] == 1
    assert results["info"] == 0


def test_run_once_skips_when_unchanged_below_threshold(monkeypatch, tmp_path):
    monitors = _sample_monitors(status=1)
    signature = snapshot.build_snapshot_signature(monitors)
    cfg = _cfg(tmp_path, force_send_every_cycles=6, snapshot_always_send=False)
    collector = _Collector(monitors)

    monkeypatch.setattr(agent, "write_json", lambda path, data: None)

    def _unexpected_deliver(**kwargs):
        raise AssertionError("deliver should not be called")

    monkeypatch.setattr(agent, "deliver", _unexpected_deliver)

    state = {
        "monitor_status": {"1": 1},
        "snapshot_signature": signature,
        "unchanged_cycles": 2,
        "has_sent_once": True,
        "last_idempotency_key": "old",
        "last_sent_at": "",
        "last_send_result": "sent",
    }
    next_state = agent.run_once(cfg, collector, state)

    assert next_state["unchanged_cycles"] == 3
    assert next_state["snapshot_signature"] == signature


def test_run_once_always_send_mode(monkeypatch, tmp_path):
    monitors = _sample_monitors(status=1)
    signature = snapshot.build_snapshot_signature(monitors)
    cfg = _cfg(tmp_path, snapshot_always_send=True)
    collector = _Collector(monitors)
    captured = {"report": None}

    monkeypatch.setattr(agent, "write_json", lambda path, data: None)

    def _fake_deliver(**kwargs):
        captured["report"] = kwargs["report"]
        return {"sent": True, "queued": False, "flushed_from_queue": 0}

    monkeypatch.setattr(agent, "deliver", _fake_deliver)

    state = {
        "monitor_status": {"1": 1},
        "snapshot_signature": signature,
        "unchanged_cycles": 5,
        "has_sent_once": True,
        "last_idempotency_key": "old",
        "last_sent_at": "",
        "last_send_result": "sent",
    }
    next_state = agent.run_once(cfg, collector, state)

    assert next_state["has_sent_once"] is True
    meta = captured["report"]["scan_summary"]["meta"]
    assert meta["schema_version"] == "1.0"
    assert meta["snapshot_mode"] == "always"
    assert meta["send_reason"] == "always_snapshot"
