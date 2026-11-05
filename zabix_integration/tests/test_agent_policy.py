import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "zabix_integration"))
import agent
from mad_common.delivery import DeliveryPolicy


class FakeZabbix:
    def __init__(self, hosts=None):
        self.hosts = hosts or [{"hostid": "1", "host": "server-a", "name": "Server A"}]

    def api_version(self): return "7.0"
    def get_problems(self, **kwargs): return []
    def get_events(self, **kwargs): return []
    def get_hosts(self): return self.hosts
    def get_all_triggers(self, **kwargs): return []


def cfg(tmp_path):
    return SimpleNamespace(
        hours=24, problems_limit=100, events_limit=100, triggers_limit=100,
        include_events=True, raw_snapshot_path=tmp_path / "raw.json", company_id=1,
        api_key="test", mad_version="test", integration_version="test", source="test",
        output_mode="webhook", webhook_url="https://unused.invalid", tenant_id=1,
        http_retries=0, backoff_seconds=0, request_timeout=1, verify_ssl=True,
        last_payload_path=tmp_path / "last.json", debug_report_path=tmp_path / "debug.json",
        queue_dir=tmp_path / "queue", delivery_policy=DeliveryPolicy("on_change"),
        queue_flush_max=10, delivery_meta_path=tmp_path / "receipt.json", state_path=tmp_path / "state.json",
    )


def test_zabbix_full_host_content_changes_create_delivery_event(tmp_path, monkeypatch):
    attempts = []
    monkeypatch.setattr(agent, "deliver", lambda **kwargs: attempts.append(kwargs) or {"sent": True, "queued": False})
    settings = cfg(tmp_path)
    first = agent.run_once(settings, FakeZabbix(), {})
    same = agent.run_once(settings, FakeZabbix(), first)
    changed = agent.run_once(settings, FakeZabbix([{"hostid": "2", "host": "server-b", "name": "Server B"}]), same)
    assert len(attempts) == 2
    assert attempts[0]["idempotency_key"] != attempts[1]["idempotency_key"]
    assert first["snapshot_signature"] == same["snapshot_signature"]
    assert changed["snapshot_signature"] != same["snapshot_signature"]
    assert changed["has_sent_once"] is True


def test_zabbix_failure_keeps_event_pending_and_does_not_ack(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "deliver", lambda **kwargs: {"sent": False, "queued": False})
    settings = cfg(tmp_path)
    with pytest.raises(RuntimeError, match="pending"):
        agent.run_once(settings, FakeZabbix(), {})
    assert not settings.state_path.exists()
