import copy
import hashlib
import json
import os
from datetime import datetime

import pytest

from mad_common.delivery import DeliveryJournal, DeliveryPolicy, resolve_delivery_policy


def journal(tmp_path, mode="on_change", **kwargs):
    return DeliveryJournal(tmp_path / "journal", "nessus", DeliveryPolicy(mode, 60), **kwargs)


def test_defaults_and_explicit_overrides():
    for integration in ("nessus", "openvas", "wazuh", "insightvm", "uptimekuma", "zabbix"):
        assert resolve_delivery_policy({}, integration) == DeliveryPolicy("change_or_backup", 3600, "default", 6)
    cfg = resolve_delivery_policy({"MAD_DELIVERY_MODE": "periodic", "UPTIME_DELIVERY_MODE": "on_change", "MAD_DELIVERY_INTERVAL_SECONDS": "10", "UPTIME_DELIVERY_INTERVAL_SECONDS": "20"}, "uptimekuma")
    assert cfg.mode == "on_change" and cfg.interval_seconds == 20
    assert resolve_delivery_policy({"MAD_DELIVERY_MODE": "always"}, "nessus").mode == "always"


@pytest.mark.parametrize("key", ["FORCE_SEND_EVERY_CYCLES", "SNAPSHOT_ALWAYS_SEND", "NESSUS_FORCE_SEND_EVERY_CYCLES", "NESSUS_SNAPSHOT_ALWAYS_SEND"])
def test_legacy_settings_rejected_even_false(key):
    with pytest.raises(ValueError, match="migrate to"):
        resolve_delivery_policy({key: "false"}, "nessus")
    assert resolve_delivery_policy({"UPTIME_SNAPSHOT_ALWAYS_SEND": "true"}, "nessus").mode == "change_or_backup"


@pytest.mark.parametrize("env", [{"MAD_DELIVERY_MODE": "sometimes"}, {"MAD_DELIVERY_INTERVAL_SECONDS": "nan"}, {"MAD_DELIVERY_INTERVAL_SECONDS": "0"}, {"MAD_DELIVERY_INTERVAL_SECONDS": "bad"}])
def test_invalid_policy(env):
    with pytest.raises(ValueError):
        resolve_delivery_policy(env, "nessus")


def test_decision_pure_and_observation_not_delivery(tmp_path):
    with journal(tmp_path) as j:
        before = copy.deepcopy(j.state)
        assert j.decision("A", 1)["reason"] == "first_snapshot"
        assert j.state == before
        event = j.enqueue("A", {"value": 1}, now=1)
        assert j.state["last_delivered_signature"] is None
        assert j.state["last_delivered_at"] is None
        assert j.state["observed_signature"] == "A"
        assert j.enqueue("A", {"value": 2}, now=2) is None
        assert len(j.state["pending"]) == 1
        assert event["payload"]["idempotency_key"] == event["key"]
        assert event["key"] == "sha256:" + hashlib.sha256(f"delivery-v2:nessus:{event['event_id']}".encode()).hexdigest()


def test_restart_preserves_exact_retry_and_transition_identity(tmp_path):
    with journal(tmp_path) as j:
        a = j.enqueue("A", {"value": 1}, now=1)
        b = j.enqueue("B", {"value": 2}, now=2)
        a2 = j.enqueue("A", {"value": 3}, now=3)
        assert len({a["key"], b["key"], a2["key"]}) == 3
        with pytest.raises(OSError, match="offline"):
            j.drain(lambda *_: (_ for _ in ()).throw(OSError("offline")))
    sent = []
    with journal(tmp_path) as j:
        assert j.state["pending"] == [a, b, a2]
        assert j.drain(lambda payload, key: sent.append((payload, key)) or True, now=100) == 3
        assert sent == [(e["payload"], e["key"]) for e in (a, b, a2)]
        assert j.state["last_delivered_signature"] == "A"
        assert j.state["last_delivered_generation"] == 3
        assert j.state["last_delivered_at"] == 100
        assert not j.state["pending"]


def test_periodic_boundary_and_pending_rate_limit(tmp_path):
    with journal(tmp_path, "periodic") as j:
        j.enqueue("A", {}, now=10)
        assert j.decision("B", 69)["reason"] == "interval_not_due"
        assert j.enqueue("B", {}, now=69) is None
        assert j.decision("B", 70)["reason"] == "periodic_due"
        second = j.enqueue("B", {}, now=70)
        assert second and len(j.state["pending"]) == 2
        assert not j.decision("A", 71)["should_send"]
        assert j.drain(lambda *_: False, now=75) == 0
        assert j.state["last_delivered_signature"] is None
        assert j.drain(lambda *_: True, now=80) == 2
        assert j.decision("B", 130)["should_send"]


def test_strict_ack_and_callback_failure_leave_original_event(tmp_path):
    with journal(tmp_path) as j:
        event = j.enqueue("A", {"value": 1}, now=1)
        for result in (None, False, 1, {"sent": True}):
            assert j.drain(lambda *_: result) == 0
            assert j.state["pending"] == [event]
        def callback(_):
            raise ValueError("callback failed")
        with pytest.raises(ValueError, match="callback failed"):
            j.drain(lambda *_: True, on_ack=callback)
        assert j.state["pending"] == [event]
        assert j.state["last_delivered_at"] is None


def test_persistence_failure_cannot_send_unpersisted_event(tmp_path, monkeypatch):
    with journal(tmp_path) as j:
        original = copy.deepcopy(j.state)
        sent = []
        def fail(*_):
            raise OSError("disk full")
        monkeypatch.setattr(os, "replace", fail)
        with pytest.raises(OSError, match="disk full"):
            j.enqueue("A", {}, now=1)
        assert j.state == original
        assert j.drain(lambda *args: sent.append(args) or True) == 0
        assert not sent


def test_ack_persistence_failure_retries_same_event(tmp_path, monkeypatch):
    with journal(tmp_path) as j:
        event = j.enqueue("A", {}, now=1)
        with monkeypatch.context() as patch:
            patch.setattr(os, "replace", lambda *_: (_ for _ in ()).throw(OSError("disk full")))
            with pytest.raises(OSError):
                j.drain(lambda *_: True)
        assert j.state["pending"] == [event]
        assert j.state["last_delivered_signature"] is None
    with journal(tmp_path) as j:
        assert j.state["pending"] == [event]


def test_baseline_seed_only_once_and_backpressure(tmp_path):
    with journal(tmp_path, baseline_signature="old", baseline_sent_at=10, max_pending=1) as j:
        assert j.state["observed_signature"] == "old"
        j.enqueue("A", {}, now=20)
        before = copy.deepcopy(j.state)
        with pytest.raises(RuntimeError, match="backlog"):
            j.enqueue("B", {}, now=30)
        assert j.state == before
    with journal(tmp_path, baseline_signature="replacement", baseline_sent_at=99) as j:
        assert j.state["observed_signature"] == "A"
        assert j.state["last_delivered_signature"] == "old"
        assert j.state["last_delivered_at"] == 10


def test_lock_nonblocking_and_corrupt_state_rejected(tmp_path):
    with journal(tmp_path) as first:
        with pytest.raises(RuntimeError, match="locked"):
            with journal(tmp_path):
                pass
        path = first.path
    path.write_text('{"schema_version":1}', encoding="utf-8")
    with pytest.raises(ValueError, match="Corrupt"):
        with journal(tmp_path):
            pass
    path.write_text("{broken", encoding="utf-8")
    with pytest.raises(ValueError, match="Corrupt"):
        with journal(tmp_path):
            pass


def test_commit_observation_requires_no_event_and_always_is_explicit(tmp_path):
    with journal(tmp_path) as j:
        with pytest.raises(ValueError, match="durable event"):
            j.commit_observation("A", now=1)
        j.enqueue("A", {}, now=1)
        j.commit_observation("A", now=2)
        assert j.state["unchanged_cycles"] == 1
    with DeliveryJournal(tmp_path / "always", "nessus", DeliveryPolicy("always")) as j:
        a = j.enqueue("A", {}, now=1)
        b = j.enqueue("A", {}, now=2)
        assert a["key"] != b["key"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are not Windows ACLs")
def test_private_posix_permissions(tmp_path):
    with journal(tmp_path) as j:
        assert j.directory.stat().st_mode & 0o777 == 0o700
        assert j.path.stat().st_mode & 0o777 == 0o600
        assert j.lock_path.stat().st_mode & 0o777 == 0o600


def test_async_drain_ack_and_callback_failure(tmp_path):
    async def run():
        with journal(tmp_path) as j:
            event = j.enqueue("A", {}, now=1)
            async def send(payload, key):
                assert (payload, key) == (event["payload"], event["key"])
                return True
            async def failed_ack(_):
                raise OSError("callback failed")
            with pytest.raises(OSError, match="callback failed"):
                await j.drain_async(send, failed_ack, now=2)
            assert j.state["pending"] == [event]
            acknowledged = []
            async def ack(event):
                acknowledged.append(event["event_id"])
            assert await j.drain_async(send, ack, now=3) == 1
            assert acknowledged == [event["event_id"]]
            assert j.state["last_delivered_at"] == 3
    # These fake async callbacks complete without scheduling I/O. Advance the
    # coroutine directly so this test needs no Windows event-loop pipe/socket.
    coroutine = run()
    with pytest.raises(StopIteration):
        coroutine.send(None)


@pytest.mark.parametrize("timestamp", [True, False, "2026-01-01T12:30:00", datetime(2026, 1, 1)])
def test_reject_bool_and_naive_timestamps(tmp_path, timestamp):
    with pytest.raises(ValueError, match="boolean|timezone"):
        with journal(tmp_path, baseline_signature="A", baseline_sent_at=timestamp):
            pass
    with journal(tmp_path) as j:
        with pytest.raises(ValueError, match="boolean|timezone"):
            j.enqueue("A", {}, now=timestamp)
        j.enqueue("A", {}, now=1)
        sent = []
        with pytest.raises(ValueError, match="boolean|timezone"):
            j.drain(lambda *args: sent.append(args) or True, now=timestamp)
        assert not sent


def test_aware_baseline_and_future_rejection(tmp_path, monkeypatch):
    monkeypatch.setattr("mad_common.delivery.time.time", lambda: 100)
    with journal(tmp_path, baseline_signature="A", baseline_sent_at="1970-01-01T01:00:10+01:00") as j:
        assert j.state["last_delivered_at"] == 10
    with pytest.raises(ValueError, match="future"):
        with DeliveryJournal(tmp_path / "future", "nessus", DeliveryPolicy(), baseline_signature="A", baseline_sent_at=101):
            pass


def test_post_replace_failure_prevents_network_until_reopened(tmp_path, monkeypatch):
    with journal(tmp_path) as j:
        def fail():
            raise OSError("directory fsync failed")
        monkeypatch.setattr(j, "_sync_directory", fail)
        with pytest.raises(OSError, match="fsync failed"):
            j.enqueue("A", {"content": 1}, now=1)
        durable = json.loads(j.path.read_text(encoding="utf-8"))["pending"][0]
        sent = []
        with pytest.raises(RuntimeError, match="uncertain"):
            j.drain(lambda *args: sent.append(args) or True)
        with pytest.raises(RuntimeError, match="uncertain"):
            j.enqueue("B", {}, now=2)
        assert not sent
    with journal(tmp_path) as j:
        assert j.state["pending"] == [durable]
        assert j.drain(lambda payload, key: sent.append((payload, key)) or True, now=2) == 1
        assert sent == [(durable["payload"], durable["key"])]


@pytest.mark.parametrize("field,value", [
    ("signature", 12), ("generation", True), ("created_at", True),
    ("key", "sha256:wrong"), ("event_id", "replaced"),
])
def test_corrupt_pending_events_rejected_before_send(tmp_path, field, value):
    with journal(tmp_path) as j:
        j.enqueue("A", {}, now=1)
        j.state["pending"][0][field] = value
        sent = []
        with pytest.raises(ValueError):
            j.drain(lambda *args: sent.append(args) or True)
        assert not sent


@pytest.mark.parametrize("corruption", ["duplicate", "payload_key", "generation", "timestamp", "oversize"])
def test_corrupt_state_schema_on_load(tmp_path, corruption):
    with journal(tmp_path) as j:
        j.enqueue("A", {}, now=1)
        j.enqueue("B", {}, now=2)
        state, path = copy.deepcopy(j.state), j.path
    if corruption == "duplicate":
        state["pending"][1]["event_id"] = state["pending"][0]["event_id"]
        state["pending"][1]["key"] = state["pending"][0]["key"]
        state["pending"][1]["payload"]["idempotency_key"] = state["pending"][0]["key"]
    elif corruption == "payload_key":
        state["pending"][0]["payload"]["idempotency_key"] = "wrong"
    elif corruption == "generation":
        state["last_delivered_generation"] = 2
    elif corruption == "timestamp":
        state["last_delivered_at"] = True
    path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(ValueError, match="Corrupt"):
        with journal(tmp_path, max_pending=1 if corruption == "oversize" else 1000):
            pass


@pytest.mark.parametrize("value", [True, False, 1.1, 0, -1])
def test_invalid_backlog_limits(tmp_path, value):
    with pytest.raises(ValueError, match="positive integer"):
        journal(tmp_path, max_pending=value)
