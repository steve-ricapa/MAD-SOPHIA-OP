from pathlib import Path
from types import SimpleNamespace

import pytest

from mad_common.collector_delivery import run_snapshot_cycle
from mad_common.delivery import DeliveryPolicy, DeliveryJournal


def config(tmp_path, mode="on_change"):
    return SimpleNamespace(
        queue_dir=tmp_path / "queue", output_mode="webhook", delivery_policy=DeliveryPolicy(mode, 60),
        queue_flush_max=20, last_payload_path=tmp_path / "last.json",
        debug_report_path=tmp_path / "debug.json", delivery_meta_path=tmp_path / "receipt.json",
    )


def run(cfg, source, sender, state=None, prepare=None):
    def sign(data):
        return data["signature"]

    def build(data, current, decision):
        return (prepare(data, current, decision) if prepare else ({"scan_id": data["signature"]}, {}))

    return run_snapshot_cycle(integration="nessus", cfg=cfg, state=state or {}, collect=source,
                              signature=sign, prepare=build, send=sender)


def test_acknowledged_transition_updates_state_only_after_sender_ack(tmp_path):
    cfg = config(tmp_path)
    attempts = []
    with pytest.raises(RuntimeError, match="pending"):
        run(cfg, lambda: {"signature": "A"}, lambda payload, key: attempts.append((payload, key)) or {"sent": False})
    assert len(attempts) == 1
    assert not (tmp_path / "state.json").exists()
    with DeliveryJournal(cfg.queue_dir / "delivery-v2", "nessus", cfg.delivery_policy) as journal:
        event = journal.state["pending"][0]
    result = run(cfg, lambda: {"signature": "A"}, lambda payload, key: attempts.append((payload, key)) or {"sent": True})
    assert attempts[0] == attempts[1] == (event["payload"], event["key"])
    assert result["snapshot_signature"] == "A"
    assert result["last_idempotency_key"] == event["key"]
    assert result["delivered_generation"] == event["generation"]
    assert result["has_sent_once"] is True


def test_pending_retries_before_collection_and_preserves_payload_when_source_fails(tmp_path):
    cfg = config(tmp_path)
    with pytest.raises(RuntimeError, match="pending"):
        run(cfg, lambda: {"signature": "A"}, lambda *_: {"sent": False})
    events = []
    def sender(payload, key):
        events.append((payload, key))
        return {"sent": True}
    def unavailable():
        raise OSError("source offline")
    with pytest.raises(OSError, match="source offline"):
        run(cfg, unavailable, sender)
    assert len(events) == 1
    with DeliveryJournal(cfg.queue_dir / "delivery-v2", "nessus", cfg.delivery_policy) as journal:
        assert not journal.state["pending"]
        assert journal.state["last_delivered_signature"] == "A"


def test_changed_a_to_b_to_a_gets_distinct_events_and_keys(tmp_path):
    cfg = config(tmp_path)
    with pytest.raises(RuntimeError):
        run(cfg, lambda: {"signature": "A"}, lambda *_: {"sent": False})
    with pytest.raises(RuntimeError):
        run(cfg, lambda: {"signature": "B"}, lambda *_: {"sent": False})
    with pytest.raises(RuntimeError):
        run(cfg, lambda: {"signature": "A"}, lambda *_: {"sent": False})
    with DeliveryJournal(cfg.queue_dir / "delivery-v2", "nessus", cfg.delivery_policy) as journal:
        events = journal.state["pending"]
        assert [event["signature"] for event in events] == ["A", "B", "A"]
        assert len({event["key"] for event in events}) == 3


def test_nonempty_legacy_transport_queue_fails_closed(tmp_path):
    cfg = config(tmp_path)
    cfg.queue_dir.mkdir()
    (cfg.queue_dir / "legacy.json").write_text("{}", encoding="utf-8")
    sends = []
    with pytest.raises(RuntimeError, match="Legacy pending"):
        run(cfg, lambda: {"signature": "A"}, lambda *args: sends.append(args) or {"sent": True})
    assert not sends


def test_periodic_mode_uses_elapsed_time_not_cycle_count(tmp_path, monkeypatch):
    cfg = config(tmp_path, "periodic")
    cfg.delivery_policy = DeliveryPolicy("periodic", 3600)
    monkeypatch.setattr("mad_common.delivery.time.time", lambda: 10000)
    run(cfg, lambda: {"signature": "A"}, lambda *_: {"sent": True})
    with DeliveryJournal(cfg.queue_dir / "delivery-v2", "nessus", cfg.delivery_policy) as journal:
        assert journal.decision("B", 10000 + 3599)["reason"] == "interval_not_due"
        assert journal.decision("B", 10000 + 3600)["reason"] == "periodic_due"


def test_backup_real_collector_flow_does_not_count_source_errors(tmp_path):
    cfg = config(tmp_path, "change_or_backup")
    sent = []
    def sender(payload, key):
        sent.append((payload, key))
        return {"sent": True}
    state = run(cfg, lambda: {"signature": "A"}, sender)
    for _ in range(5):
        state = run(cfg, lambda: {"signature": "A"}, sender, state)
    assert len(sent) == 1
    def failed_source():
        raise OSError("offline")
    with pytest.raises(OSError):
        run(cfg, failed_source, sender, state)
    assert len(sent) == 1
    with DeliveryJournal(cfg.queue_dir / "delivery-v2", "nessus", cfg.delivery_policy) as journal:
        assert journal.state["unchanged_cycles"] == 5
    state = run(cfg, lambda: {"signature": "A"}, sender, state)
    assert len(sent) == 2
    assert sent[0][1] != sent[1][1]
    assert state["has_sent_once"] is True


def test_optional_archive_disk_failure_cannot_prevent_delivery(tmp_path, monkeypatch):
    monkeypatch.setenv("MAD_ARCHIVE_ENABLED", "true")
    monkeypatch.setattr("mad_common.artifacts._private_write", lambda *_: (_ for _ in ()).throw(OSError("diagnostic disk unavailable")))
    cfg = config(tmp_path)
    sent = []
    state = run(cfg, lambda: {"signature": "A"}, lambda payload, key: sent.append(key) or {"sent": True})
    assert len(sent) == 1 and state["has_sent_once"] is True
    assert Path(cfg.last_payload_path).exists()
