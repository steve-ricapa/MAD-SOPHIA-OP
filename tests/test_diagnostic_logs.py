"""Diagnostic logs are optional and must not endanger operational state."""
import json
import os
from pathlib import Path
import time

import pytest

from mad_common import logs
from openVAS_integration.tests.test_delivery_policy import delivery_agent  # noqa: F401 - shared offline fixture


ENV = {"MAD_LOG_MAX_MB": "1", "MAD_LOG_BACKUP_COUNT": "2", "MAD_LOG_RETENTION_DAYS": "14"}


def append(path, record, env=None):
    return logs.append_jsonl(path, record, env=ENV if env is None else env)


def put(path, data, *, days=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    when = time.time() - days * 86400
    os.utime(path, (when, when))
    return path


def test_complete_unicode_record_and_lock_are_written(tmp_path):
    path = tmp_path / "cycle_errors.jsonl"
    record = {"error_type": "ConnectionError", "error_message": "Conexión caída", "traceback": "line1\nline2"}
    assert append(path, record) is True
    assert json.loads(path.read_text(encoding="utf-8")) == record
    assert path.read_bytes().count(b"\n") == 1
    assert path.with_name(path.name + ".lock").is_file()


def test_size_rotation_keeps_prior_records_and_bounded_count(tmp_path):
    path = tmp_path / "cycle_errors.jsonl"
    record = {"error_type": "SourceError", "message": "x" * 600_000}
    for _ in range(4):
        assert append(path, record) is True
    assert {p.name for p in tmp_path.iterdir()} == {
        "cycle_errors.jsonl", "cycle_errors.jsonl.1", "cycle_errors.jsonl.2", "cycle_errors.jsonl.lock"}
    for candidate in (path, path.with_name(path.name + ".1"), path.with_name(path.name + ".2")):
        assert candidate.stat().st_size <= 1024 * 1024
        assert json.loads(candidate.read_text()) == record


def test_expiry_and_excess_rotation_cleanup_preserves_siblings(tmp_path):
    path = put(tmp_path / "cycle_errors.jsonl", b'{"previous":true}\n')
    expired = put(path.with_name(path.name + ".1"), b"expired", days=15)
    valid = put(path.with_name(path.name + ".2"), b"keep", days=1)
    excess = put(path.with_name(path.name + ".3"), b"excess", days=1)
    state = put(tmp_path / "state.json", b"important")
    queue = put(tmp_path / "queue" / "pending.json", b"pending")
    sibling = put(tmp_path / "cycle_errors.jsonl.1.json", b"not-a-rotation", days=20)
    assert append(path, {"current": True}) is True
    assert not expired.exists() and not excess.exists()
    assert valid.read_bytes() == b"keep"
    assert state.read_bytes() == b"important"
    assert queue.read_bytes() == b"pending"
    assert sibling.read_bytes() == b"not-a-rotation"


def test_legacy_large_base_is_preserved_intact_when_rotated(tmp_path):
    original = (b'{"legacy":"' + b"x" * (2 * 1024 * 1024) + b'"}\n')
    path = put(tmp_path / "cycle_errors.jsonl", original)
    assert append(path, {"new": "failure"}) is True
    assert path.with_name(path.name + ".1").read_bytes() == original
    assert json.loads(path.read_text()) == {"new": "failure"}


def test_oversized_record_is_skipped_without_truncating_or_removing_other_logs(tmp_path, caplog):
    path = put(tmp_path / "cycle_errors.jsonl", b'{"original":true}\n')
    old = put(path.with_name(path.name + ".1"), b"original-old", days=40)
    assert append(path, {"message": "x" * (2 * 1024 * 1024)}) is False
    assert path.read_bytes() == b'{"original":true}\n'
    assert old.read_bytes() == b"original-old"
    assert "exceeds configured log size" in caplog.text


def symlink_or_skip(link, target, **kwargs):
    try:
        link.symlink_to(target, **kwargs)
    except OSError as exc:
        pytest.skip(f"Host cannot create symlinks: {exc}")


@pytest.mark.parametrize("candidate", ["base", "rotation", "lock"])
def test_symlinks_never_followed_or_deleted(tmp_path, candidate, caplog):
    target = put(tmp_path / "state.json", b"protected-state")
    path = tmp_path / "cycle_errors.jsonl"
    if candidate == "base":
        link = path
    else:
        put(path, b'{"original":true}\n')
        link = path.with_name(path.name + (".1" if candidate == "rotation" else ".lock"))
    symlink_or_skip(link, target)
    assert append(path, {"new": True}) is False
    assert target.read_bytes() == b"protected-state"
    assert link.is_symlink()
    assert "Diagnostic JSONL append skipped" in caplog.text


def test_directory_matching_rotation_name_fails_before_any_cleanup(tmp_path):
    path = put(tmp_path / "cycle_errors.jsonl", b'{"original":true}\n')
    old = put(path.with_name(path.name + ".1"), b"old", days=40)
    path.with_name(path.name + ".2").mkdir()
    assert append(path, {"new": True}) is False
    assert old.read_bytes() == b"old"
    assert path.read_bytes() == b'{"original":true}\n'


def test_io_failure_is_contained_for_original_source_error(tmp_path, monkeypatch, caplog):
    path = tmp_path / "cycle_errors.jsonl"
    def unavailable(*_args, **_kwargs):
        raise OSError("disk unavailable")
    monkeypatch.setattr(logs.os, "open", unavailable)
    assert append(path, {"error_type": "SourceError"}) is False
    assert "Diagnostic JSONL append skipped: OSError" in caplog.text


@pytest.mark.parametrize("key,value", [
    ("MAD_LOG_MAX_MB", "0"), ("MAD_LOG_BACKUP_COUNT", "-1"),
    ("MAD_LOG_RETENTION_DAYS", "nan"), ("MAD_LOG_MAX_MB", "1.5"),
])
def test_invalid_configuration_is_strict_before_mutation(tmp_path, key, value):
    path = put(tmp_path / "cycle_errors.jsonl", b'{"original":true}\n')
    old = put(path.with_name(path.name + ".1"), b"old", days=40)
    env = dict(ENV, **{key: value})
    with pytest.raises(ValueError, match=key):
        append(path, {"new": True}, env)
    assert old.read_bytes() == b"old"
    assert path.read_bytes() == b'{"original":true}\n'
    assert not path.with_name(path.name + ".lock").exists()


def test_non_jsonl_target_is_rejected_before_mutation(tmp_path):
    path = put(tmp_path / "state.db", b"important")
    with pytest.raises(ValueError, match=".jsonl"):
        append(path, {"new": True})
    assert path.read_bytes() == b"important"


def test_lock_contention_does_not_append_or_rotate(tmp_path, caplog):
    path = put(tmp_path / "cycle_errors.jsonl", b'{"original":true}\n')
    with logs._locked(path.with_name(path.name + ".lock")):
        assert append(path, {"new": True}) is False
    assert path.read_bytes() == b'{"original":true}\n'
    assert "Diagnostic JSONL append skipped" in caplog.text


def test_openvas_source_failure_records_original_error(delivery_agent):
    agent = delivery_agent
    agent.source_failure = True
    assert agent.run() == 1
    path = agent.root / "artifacts" / "logs" / "cycle_errors.jsonl"
    record = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    assert record["error_type"] == "RuntimeError"
    assert record["error_message"] == "source unavailable"
    assert "RuntimeError: source unavailable" in record["traceback"]
    assert record["cycle"] == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not Windows ACLs")
def test_new_log_and_lock_have_private_posix_permissions(tmp_path):
    path = tmp_path / "cycle_errors.jsonl"
    assert append(path, {"new": True}) is True
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.with_name(path.name + ".lock").stat().st_mode & 0o777 == 0o600
