"""Real offline Wazuh polling preserves delivery state independently of diagnostics."""
import json
from pathlib import Path

from wazuh_integration.tests.test_delivery_policy import harness  # noqa: F401


def entries(cfg):
    home = Path(cfg["raw_dir"]).parent / ".mad-archive-v1" / "wazuh"
    return sorted(home.glob("entry-*")) if home.exists() else []


def test_default_keeps_latest_without_legacy_historical_copies(harness, monkeypatch):
    _, cfg, _, _, sender, _, cycle, journal = harness
    monkeypatch.delenv("MAD_ARCHIVE_ENABLED", raising=False)
    assert cycle() is True
    assert Path(cfg["last_raw_path"]).exists()
    assert Path(cfg["last_payload_path"]).exists()
    assert not list(Path(cfg["raw_dir"]).iterdir())
    assert not list(Path(cfg["payload_dir"]).iterdir())
    assert entries(cfg) == []
    assert journal()["pending"] == []
    assert journal()["last_delivered_generation"] == 1
    assert len(sender.payloads) == 1


def test_enabled_history_is_bounded_across_changed_observations(harness, monkeypatch):
    _, cfg, _, source, sender, _, cycle, journal = harness
    monkeypatch.setenv("MAD_ARCHIVE_ENABLED", "true")
    monkeypatch.setenv("MAD_ARCHIVE_MAX_ENTRIES", "2")
    for alert_id in ("A", "B", "A"):
        source.alert_id = alert_id
        assert cycle() is True
    bundles = entries(cfg)
    assert len(bundles) == 2
    for path in bundles:
        assert {p.name for p in path.iterdir()} == {"raw.json", "payload.json", ".entry.json"}
    assert len(sender.payloads) == 3
    assert journal()["pending"] == []
    assert journal()["last_delivered_generation"] == 3
    assert len({payload["idempotency_key"] for payload in sender.payloads}) == 3
    latest = json.loads(Path(cfg["last_payload_path"]).read_text())
    assert latest == sender.payloads[-1]


def test_unchanged_poll_prunes_only_managed_history(harness, monkeypatch):
    _, cfg, _, _, sender, _, cycle, journal = harness
    monkeypatch.setenv("MAD_ARCHIVE_ENABLED", "true")
    assert cycle() is True
    bundle = entries(cfg)[0]
    marker = bundle / ".entry.json"
    manifest = json.loads(marker.read_text())
    manifest["created_at"] = 0
    marker.write_text(json.dumps(manifest), encoding="utf-8")
    legacy = Path(cfg["raw_dir"]) / "raw_legacy.json"
    legacy.write_text('{"legacy": true}', encoding="utf-8")
    monkeypatch.setenv("MAD_ARCHIVE_ENABLED", "false")
    assert cycle() is True  # No new payload; retention still executes.
    assert entries(cfg) == []
    assert legacy.read_text() == '{"legacy": true}'
    assert Path(cfg["last_payload_path"]).exists()
    assert len(sender.payloads) == 1
    assert journal()["unchanged_cycles"] == 1


def test_archive_eviction_never_removes_pending_delivery(harness, monkeypatch):
    _, cfg, state, source, sender, _, cycle, journal = harness
    monkeypatch.setenv("MAD_ARCHIVE_ENABLED", "true")
    monkeypatch.setenv("MAD_ARCHIVE_MAX_ENTRIES", "1")
    sender.succeeds = False
    for alert_id in ("A", "B", "A"):
        source.alert_id = alert_id
        assert cycle() is False
    assert len(entries(cfg)) == 1
    pending = journal()["pending"]
    assert len(pending) == 3
    assert len({event["key"] for event in pending}) == 3
    assert journal()["last_delivered_signature"] is None
    assert state.get_checkpoint("has_sent_once", None) is None


def test_legacy_debug_flag_uses_bounded_archive_even_when_global_off(harness, monkeypatch, tmp_path):
    module, _, _, _, _, _, _, _ = harness
    debug = tmp_path / "debug"
    monkeypatch.setenv("MAD_ARCHIVE_ENABLED", "false")
    monkeypatch.setenv("MAD_ARCHIVE_MAX_ENTRIES", "1")
    monkeypatch.setenv("WAZUH_PAYLOAD_DEBUG", "false")
    monkeypatch.setenv("WAZUH_PAYLOAD_DEBUG_DIR", str(debug))
    module.Sender._save_payload_debug({"scan_id": "preview"}, 200)
    assert not debug.exists()
    monkeypatch.setenv("WAZUH_PAYLOAD_DEBUG", "true")
    for index in range(3):
        module.Sender._save_payload_debug({"scan_id": str(index)}, 200)
    bundles = list((debug / ".mad-archive-v1" / "wazuh").glob("entry-*"))
    assert len(bundles) == 1
    assert {p.name for p in bundles[0].iterdir()} == {"payload.json", "metadata.json", ".entry.json"}
    assert json.loads((bundles[0] / "payload.json").read_text()) == {"scan_id": "2"}
    assert not list(debug.glob("payload_*.json"))
