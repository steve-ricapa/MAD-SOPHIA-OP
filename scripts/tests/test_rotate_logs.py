"""Exercise retention against isolated files, never operational logs or queues."""
import importlib.util
import os
from pathlib import Path
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "rotate_logs.py"
spec = importlib.util.spec_from_file_location("mad_rotate_logs_tests", SCRIPT)
rotation = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = rotation
spec.loader.exec_module(rotation)
NOW = 2_000_000_000
ENV = {"MAD_LOG_MAX_MB": "1", "MAD_LOG_BACKUP_COUNT": "2", "MAD_LOG_RETENTION_DAYS": "14"}


@pytest.fixture
def logs(tmp_path):
    directory = tmp_path / "runtime" / "logs"
    directory.mkdir(parents=True)
    return tmp_path, directory / "nessus.log"


def put(path, data=b"content", *, age=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.utime(path, (NOW - age * 86400, NOW - age * 86400))
    return path


def run(logs, **kwargs):
    repo, log = logs
    return rotation.rotate(log, repo=repo, env=ENV, now=NOW, **kwargs)


def test_size_rotation_preserves_current_and_recent_backup(logs):
    _, log = logs
    put(log, b"x" * 1024 * 1024)
    put(log.with_name(log.name + ".1"), b"prior")
    put(log.with_name(log.name + ".2"), b"oldest")
    actions = run(logs)
    assert len(actions) == 3
    assert not log.exists()
    assert log.with_name(log.name + ".1").stat().st_size == 1024 * 1024
    assert log.with_name(log.name + ".2").read_bytes() == b"prior"


def test_expiry_and_count_cleanup_does_not_require_current_rotation(logs):
    _, log = logs
    put(log)
    old = put(log.with_name(log.name + ".1"), age=15)
    valid = put(log.with_name(log.name + ".2"), b"keep")
    excess = put(log.with_name(log.name + ".3"))
    run(logs)
    assert not old.exists() and not excess.exists()
    assert valid.read_bytes() == b"keep"
    assert log.read_bytes() == b"content"


def test_dry_run_reports_changes_without_touching_files(logs):
    _, log = logs
    put(log, b"x" * 1024 * 1024)
    put(log.with_name(log.name + ".1"), age=20)
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in log.parent.iterdir()}
    actions = run(logs, dry_run=True)
    assert {action["action"] for action in actions} == {"remove", "move"}
    assert before == {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in log.parent.iterdir()}


@pytest.mark.parametrize("name", ["state.db", "other.log", "nessus.log.1", "last_run.status"])
def test_unknown_targets_rejected_before_mutation(logs, name):
    repo, log = logs
    target = put(log.parent / name, b"do-not-touch")
    with pytest.raises(ValueError, match="Only named MAD"):
        rotation.rotate(target, repo=repo, env=ENV, now=NOW)
    assert target.read_bytes() == b"do-not-touch"


def test_known_basename_outside_log_directory_rejected(logs):
    repo, _ = logs
    target = put(repo / "runtime" / "queue" / "nessus.log", b"pending")
    with pytest.raises(ValueError, match="Only named MAD"):
        rotation.rotate(target, repo=repo, env=ENV, now=NOW)
    assert target.read_bytes() == b"pending"


def symlink_or_skip(link, target, **kwargs):
    try:
        link.symlink_to(target, **kwargs)
    except OSError as exc:
        pytest.skip(f"Host cannot create symbolic links: {exc}")


@pytest.mark.parametrize("candidate", ["current", "rotation"])
def test_symlink_log_or_rotation_is_rejected(logs, candidate):
    repo, log = logs
    target = put(repo / "state.json", b"important-state")
    if candidate == "rotation":
        put(log, b"x" * 1024 * 1024)
        link = log.with_name(log.name + ".1")
    else:
        link = log
    symlink_or_skip(link, target)
    with pytest.raises(ValueError, match="regular files"):
        run(logs)
    assert target.read_bytes() == b"important-state"
    assert link.is_symlink()


def test_rotation_shaped_directory_is_rejected(logs):
    _, log = logs
    put(log, b"x" * 1024 * 1024)
    log.with_name(log.name + ".1").mkdir()
    with pytest.raises(ValueError, match="regular files"):
        run(logs)
    assert log.exists()


def test_invalid_dotenv_policy_fails_without_mutations(logs, monkeypatch, capsys):
    repo, log = logs
    put(log, b"x" * 1024 * 1024)
    old = put(log.with_name(log.name + ".1"), age=20)
    (repo / ".env").write_text("MAD_LOG_BACKUP_COUNT=0\n", encoding="utf-8")
    monkeypatch.setattr(rotation, "ROOT", repo)
    assert rotation.main([str(log)]) == 1
    assert "MAD_LOG_BACKUP_COUNT must be a positive integer" in capsys.readouterr().out
    assert old.exists() and log.exists()


def test_dotenv_overrides_inherited_log_policy(logs, monkeypatch, capsys):
    repo, log = logs
    put(log, b"x" * 1024 * 1024)
    monkeypatch.setenv("MAD_LOG_MAX_MB", "2")
    (repo / ".env").write_text("MAD_LOG_MAX_MB=1\n", encoding="utf-8")
    monkeypatch.setattr(rotation, "ROOT", repo)
    assert rotation.main([str(log), "--dry-run"]) == 0
    assert '"action": "move"' in capsys.readouterr().out
    assert log.exists()


def test_malformed_dotenv_is_rejected_before_cleanup(logs, monkeypatch, capsys):
    repo, log = logs
    put(log)
    old = put(log.with_name(log.name + ".1"), age=20)
    (repo / ".env").write_text("MAD_LOG_MAX_MB='unterminated\n", encoding="utf-8")
    monkeypatch.setattr(rotation, "ROOT", repo)
    assert rotation.main([str(log)]) == 1
    assert "Invalid .env syntax" in capsys.readouterr().out
    assert old.exists()


def test_old_large_rotation_is_removed_without_touching_unrelated_files(logs):
    repo, log = logs
    put(log)
    huge = put(log.with_name(log.name + ".2"), age=40)
    with huge.open("r+b") as stream:
        stream.truncate(8 * 1024 * 1024)
    os.utime(huge, (NOW - 40 * 86400, NOW - 40 * 86400))
    queue = put(repo / "runtime" / "queue" / "pending.json", b"pending")
    sibling = put(log.parent / "zabbix.log.2", b"other-collector", age=40)
    odd_name = put(log.parent / "nessus.log.1.json", b"not-a-rotation", age=40)
    run(logs)
    assert not huge.exists()
    assert queue.read_bytes() == b"pending"
    assert sibling.read_bytes() == b"other-collector"
    assert odd_name.read_bytes() == b"not-a-rotation"


def test_changed_file_refuses_rotation(logs, monkeypatch):
    _, log = logs
    put(log, b"x" * 1024 * 1024)
    original = Path.lstat
    calls = 0

    def racing_lstat(path):
        nonlocal calls
        if path == log:
            calls += 1
            if calls == 2:
                with path.open("ab") as stream:
                    stream.write(b"new-collector-output")
        return original(path)

    monkeypatch.setattr(Path, "lstat", racing_lstat)
    with pytest.raises(RuntimeError, match="Log changed during rotation"):
        run(logs)
    assert log.exists()
    assert not log.with_name(log.name + ".1").exists()


@pytest.mark.parametrize("value", ["0", "-1", "1.5", "true", "nan"])
def test_invalid_policy_values_are_rejected(value):
    with pytest.raises(ValueError):
        rotation.policy_from_env({"MAD_LOG_MAX_MB": value})
