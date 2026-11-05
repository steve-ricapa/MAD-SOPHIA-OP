import pytest

from mad_common import fs


def test_windows_transient_sharing_lock_retries_same_atomic_operation(monkeypatch):
    monkeypatch.setattr(fs, "_WINDOWS", True)
    attempts, pauses = [], []
    def replace(source, target):
        attempts.append((source, target))
        if len(attempts) < 3:
            error = PermissionError("sharing violation")
            error.winerror = 32
            raise error
    monkeypatch.setattr(fs.os, "replace", replace)
    monkeypatch.setattr(fs.time, "sleep", pauses.append)
    fs.atomic_replace("temporary", "state")
    assert attempts == [("temporary", "state")] * 3
    assert pauses == [0.01, 0.02]


def test_persistent_access_error_propagates_without_endless_retry(monkeypatch):
    monkeypatch.setattr(fs, "_WINDOWS", True)
    attempts = []
    def replace(*args):
        attempts.append(args)
        error = PermissionError("locked")
        error.winerror = 5
        raise error
    monkeypatch.setattr(fs.os, "replace", replace)
    monkeypatch.setattr(fs.time, "sleep", lambda *_: None)
    with pytest.raises(PermissionError):
        fs.atomic_replace("temporary", "state")
    assert len(attempts) == 6


def test_non_windows_errors_do_not_retry(monkeypatch):
    monkeypatch.setattr(fs, "_WINDOWS", False)
    attempts = []
    def replace(*args):
        attempts.append(args)
        raise PermissionError("denied")
    monkeypatch.setattr(fs.os, "replace", replace)
    with pytest.raises(PermissionError):
        fs.atomic_replace("temporary", "state")
    assert len(attempts) == 1
