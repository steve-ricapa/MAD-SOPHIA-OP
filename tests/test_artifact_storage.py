import json
import os
from pathlib import Path

import pytest

from mad_common.artifacts import archive_bundle, maintain_history, resolve_artifact_policy, log_retention


def enabled(**overrides):
    return dict(MAD_ARCHIVE_ENABLED="true", MAD_ARCHIVE_MAX_ENTRIES="2", **overrides)


def entries(root, integration="nessus"):
    return list((root / ".mad-archive-v1" / integration).glob("entry-*"))


def test_default_disabled_does_not_create_or_touch_legacy_data(tmp_path):
    legacy = tmp_path / "queue" / "pending.json"
    legacy.parent.mkdir(); legacy.write_text('{"pending":true}')
    assert archive_bundle(tmp_path, "nessus", {"payload.json": {"x": 1}}, env={}) is None
    assert not (tmp_path / ".mad-archive-v1").exists()
    assert legacy.read_text() == '{"pending":true}'


def test_archive_bounds_and_manifest_only_history_eviction(tmp_path, monkeypatch):
    for i in range(4):
        monkeypatch.setattr("mad_common.artifacts.time.time", lambda: 1000 + i)
        archive_bundle(tmp_path, "nessus", {"raw.json": {"value": i}, "payload.json": {"value": i}}, env=enabled())
    assert len(entries(tmp_path)) == 2
    assert sorted(json.loads((p / "payload.json").read_text())["value"] for p in entries(tmp_path)) == [2, 3]
    for entry in entries(tmp_path):
        assert set(json.loads((entry / ".entry.json").read_text())["files"]) == {"raw.json", "payload.json"}


def test_age_retention_runs_even_when_archive_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr("mad_common.artifacts.time.time", lambda: 1)
    archive_bundle(tmp_path, "nessus", {"payload.json": {}}, env=enabled())
    monkeypatch.setattr("mad_common.artifacts.time.time", lambda: 10 * 86400)
    maintain_history(tmp_path, "nessus", {})
    assert not entries(tmp_path)


def test_byte_budget_and_oversize_bundle(tmp_path):
    env = enabled(MAD_ARCHIVE_MAX_MB="0.01")
    for _ in range(5):
        archive_bundle(tmp_path, "nessus", {"payload.json": {"text": "x" * 4000}}, env=env)
    assert len(entries(tmp_path)) <= 2
    assert sum(p.stat().st_size for e in entries(tmp_path) for p in e.iterdir()) <= 0.01 * 1024 * 1024
    original = set(entries(tmp_path))
    assert archive_bundle(tmp_path, "nessus", {"payload.json": {"text": "x" * 20000}}, env=env) is None
    assert set(entries(tmp_path)) == original


def test_corrupt_entry_preserved_and_new_writes_fail_closed(tmp_path):
    archive_bundle(tmp_path, "nessus", {"payload.json": {}}, env=enabled())
    entry = entries(tmp_path)[0]
    unexpected = entry / "state.json"
    unexpected.write_text('{"important":true}')
    maintain_history(tmp_path, "nessus", {"MAD_ARCHIVE_MAX_ENTRIES": "1"})
    assert archive_bundle(tmp_path, "nessus", {"payload.json": {}}, env=enabled()) is None
    assert unexpected.exists() and (entry / "payload.json").exists()


@pytest.mark.parametrize("value", [[], None, 12, "invalid"])
def test_wrong_manifest_shape_never_blocks_delivery(tmp_path, value):
    archive_bundle(tmp_path, "nessus", {"payload.json": {}}, env=enabled())
    entry = entries(tmp_path)[0]
    (entry / ".entry.json").write_text(json.dumps(value))
    maintain_history(tmp_path, "nessus", {})
    assert archive_bundle(tmp_path, "nessus", {"payload.json": {}}, env=enabled()) is None
    assert (entry / "payload.json").exists()


def test_optional_encoding_memory_failure_is_contained(tmp_path, monkeypatch):
    monkeypatch.setattr("mad_common.artifacts.BytesIO", lambda: (_ for _ in ()).throw(MemoryError()))
    assert archive_bundle(tmp_path, "nessus", {"payload.json": {}}, env=enabled()) is None
    assert not list(tmp_path.iterdir())


def test_symlink_never_followed(tmp_path):
    destination = tmp_path / "important"
    destination.mkdir()
    root = tmp_path / "archive"
    try:
        root.symlink_to(destination, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation unavailable")
    assert archive_bundle(root, "nessus", {"payload.json": {}}, env=enabled()) is None
    assert not list(destination.iterdir())


@pytest.mark.parametrize("key,value", [("MAD_ARCHIVE_ENABLED", "maybe"), ("MAD_ARCHIVE_MAX_MB", "nan"),
    ("MAD_ARCHIVE_RETENTION_DAYS", "0"), ("MAD_ARCHIVE_MAX_ENTRIES", "1.5"),
    ("MAD_LOG_MAX_MB", "-1"), ("MAD_LOG_MAX_MB", "1.5"), ("MAD_LOG_BACKUP_COUNT", "0")])
def test_invalid_settings_fail_without_creating_files(tmp_path, key, value):
    with pytest.raises(ValueError):
        archive_bundle(tmp_path, "nessus", {"payload.json": {}}, env={key: value})
    assert not list(tmp_path.iterdir())


def test_legacy_debug_force_is_still_bounded(tmp_path):
    for _ in range(5):
        archive_bundle(tmp_path, "nessus", {"payload.json": {}}, force=True,
                       env={"MAD_ARCHIVE_ENABLED": "false", "MAD_ARCHIVE_MAX_ENTRIES": "2"})
    assert len(entries(tmp_path)) == 2


def test_state_filenames_rejected(tmp_path):
    with pytest.raises(ValueError):
        archive_bundle(tmp_path, "nessus", {"state.json": {}}, env=enabled())
    assert not list(tmp_path.iterdir())


def test_io_failure_is_not_a_delivery_failure(tmp_path, monkeypatch):
    monkeypatch.setattr("mad_common.artifacts._private_write", lambda *_: (_ for _ in ()).throw(OSError("disk full")))
    assert archive_bundle(tmp_path, "nessus", {"payload.json": {}}, env=enabled()) is None


def test_rotated_log_retention_does_not_delete_latest_or_state(tmp_path, monkeypatch):
    monkeypatch.setenv("MAD_LOG_BACKUP_COUNT", "1")
    files = []
    for i in range(3):
        p = tmp_path / f"agent_console.2026-11-0{i}_00-00.json"
        p.write_text("log"); os.utime(p, (100 + i, 100 + i)); files.append(str(p))
    latest = tmp_path / "agent_console.json"; latest.write_text("latest")
    state = tmp_path / "state.json"; state.write_text("state")
    monkeypatch.setattr("mad_common.artifacts.time.time", lambda: 103)
    log_retention([*files, str(latest), str(state)])
    assert latest.exists() and state.exists()
    assert sum(Path(p).exists() for p in files) == 1
