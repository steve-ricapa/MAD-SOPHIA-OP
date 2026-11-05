"""Offline delivery regressions; immediate fake awaitables need no event loop."""
import copy
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys

import pytest


WAZUH = Path(__file__).resolve().parents[1]


def immediate(coroutine):
    try:
        coroutine.send(None)
    except StopIteration as result:
        return result.value
    finally:
        coroutine.close()
    pytest.fail("Offline collector unexpectedly yielded to an event loop")


@pytest.fixture
def harness(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(WAZUH))
    for name in list(sys.modules):
        if name == "snapshot" or name == "src" or name.startswith("src."):
            monkeypatch.delitem(sys.modules, name)
    spec = importlib.util.spec_from_file_location("wazuh_delivery_test_main", WAZUH / "main.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from mad_common.delivery import DeliveryPolicy

    cfg = {"initial_lookback_hours": 2, "alert_batch_size": 500, "min_rule_level": 7,
           "poll_interval_alerts": 30, "dry_run": False, "delivery_policy": DeliveryPolicy(),
           "mad_version": "test", "integration_version": "test", "source": "offline-test"}
    for name in ("raw_dir", "payload_dir", "failed_dir", "delivery_dir"):
        cfg[name] = str(tmp_path / name)
        Path(cfg[name]).mkdir()
    for name in ("last_raw_path", "last_payload_path", "last_delivery_meta_path"):
        cfg[name] = str(tmp_path / (name + ".json"))
    state = module.StateStore(str(tmp_path / "state.db"))
    assert state.get_checkpoint("missing", "fallback") == "fallback"
    calls = []

    class Source:
        alert_id = "A"
        offline = False
        last_error = None
        last_error_kind = None

        async def get_new_alerts(self, *_args, **_kwargs):
            calls.append("source")
            if self.offline:
                self.last_error, self.last_error_kind = "source offline", "network"
                return []
            self.last_error = self.last_error_kind = None
            return [{"_id": self.alert_id, "timestamp": "2026-01-01T00:00:00Z",
                     "rule": {"id": "7", "level": 13, "description": "finding"},
                     "agent": {"id": "1", "name": "host"}}]

    class Sender:
        succeeds = True
        payloads = []
        last_status_code = 200
        last_failure_kind = None
        last_error_body = None

        async def send_report(self, payload):
            calls.append("send")
            self.payloads.append(copy.deepcopy(payload))
            return self.succeeds

    source, sender = Source(), Sender()
    sender.payloads = []
    aggregator = module.Aggregator("1")

    def cycle():
        return immediate(module.poll_alerts(source, aggregator, state, sender, 1, 1, "test-key", cfg, single_run=True))

    def journal():
        return json.loads((Path(cfg["delivery_dir"]) / "wazuh.json").read_text(encoding="utf-8"))

    return module, cfg, state, source, sender, calls, cycle, journal


def test_equal_count_alert_replacement_unchanged_and_recurrence(harness):
    _, _, state, source, sender, _, cycle, journal = harness
    assert cycle() is True
    first = sender.payloads[0]
    assert cycle() is True
    assert len(sender.payloads) == 1
    source.alert_id = "B"
    assert cycle() is True
    source.alert_id = "A"
    assert cycle() is True
    assert [p["findings"][0]["dedup_id"] for p in sender.payloads] == ["wazuh-A", "wazuh-B", "wazuh-A"]
    assert len({p["idempotency_key"] for p in sender.payloads}) == 3
    assert first["scan_summary"]["results"] == sender.payloads[1]["scan_summary"]["results"]
    assert journal()["pending"] == []
    assert state.get_checkpoint("snapshot_signature") == first["scan_summary"]["meta"]["snapshot_signature"]


def test_backup_on_sixth_successful_cycle_and_failed_source_does_not_count(harness):
    _, _, _, source, sender, _, cycle, journal = harness
    assert cycle() is True
    for count in range(1, 6):
        assert cycle() is True
        assert journal()["unchanged_cycles"] == count
    assert len(sender.payloads) == 1
    source.offline = True
    assert cycle() is False
    assert journal()["unchanged_cycles"] == 5
    source.offline = False
    assert cycle() is True
    assert len(sender.payloads) == 2
    assert sender.payloads[-1]["scan_summary"]["meta"]["send_reason"] == "backup_cycle"
    assert journal()["unchanged_cycles"] == 0


def test_failed_delivery_retries_original_payload_before_offline_source(harness):
    _, _, state, source, sender, calls, cycle, journal = harness
    sender.succeeds = False
    assert cycle() is False
    original = copy.deepcopy(sender.payloads[0])
    assert len(journal()["pending"]) == 1
    assert state.get_checkpoint("has_sent_once", None) is None
    assert state.get_checkpoint("snapshot_signature", None) is None
    sender.succeeds = True
    source.offline = True
    calls.clear()
    assert cycle() is False  # Source outage remains a failed collection cycle.
    assert calls == ["send", "source"]
    assert sender.payloads == [original, original]
    assert journal()["pending"] == []
    assert state.get_checkpoint("has_sent_once") == "true"
    assert state.get_checkpoint("last_idempotency_key") == original["idempotency_key"]


def test_dry_run_never_queues_or_acknowledges(harness):
    _, cfg, state, source, sender, _, cycle, journal = harness
    cfg["dry_run"] = True
    assert cycle() is True
    source.alert_id = "B"
    assert cycle() is True
    assert sender.payloads == []
    assert journal()["pending"] == []
    assert journal()["last_delivered_signature"] is None
    assert state.get_checkpoint("has_sent_once", None) is None
    assert state.get_checkpoint("snapshot_signature", None) is None
    assert Path(cfg["last_payload_path"]).exists()


def test_legacy_pending_queue_fails_closed(harness):
    _, cfg, state, _, sender, calls, cycle, _ = harness
    legacy = Path(cfg["failed_dir"]) / "failed_old.json"
    legacy.write_text('{"scan_id":"legacy"}', encoding="utf-8")
    assert cycle() is False
    assert calls == []
    assert sender.payloads == []
    assert legacy.exists()
    assert state.get_checkpoint("has_sent_once", None) is None


def test_checkpoint_failure_retains_acknowledged_event_for_idempotent_retry(harness, monkeypatch):
    _, _, state, _, sender, _, cycle, journal = harness

    def fail_checkpoint(*_args, **_kwargs):
        raise sqlite3.OperationalError("checkpoint disk unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(state, "update_checkpoint", fail_checkpoint)
        assert cycle() is False
    original = copy.deepcopy(sender.payloads[0])
    assert len(journal()["pending"]) == 1
    assert journal()["last_delivered_signature"] is None
    assert cycle() is True
    assert sender.payloads == [original, original]
    assert journal()["pending"] == []


@pytest.mark.parametrize("operation", [
    lambda store: store.get_checkpoint("x", "fallback"),
    lambda store: store.update_checkpoint("x", "value"),
    lambda store: store.is_alert_processed("alert"),
    lambda store: store.mark_alerts_processed(["alert"]),
    lambda store: store.purge_processed_alerts(),
])
def test_sqlite_failures_are_observable(harness, monkeypatch, operation):
    _, _, state, *_ = harness
    state_module = sys.modules[state.__class__.__module__]

    def fail(*_args, **_kwargs):
        raise sqlite3.OperationalError("disk unavailable")

    monkeypatch.setattr(state_module.sqlite3, "connect", fail)
    with pytest.raises(sqlite3.OperationalError, match="disk unavailable"):
        operation(state)
