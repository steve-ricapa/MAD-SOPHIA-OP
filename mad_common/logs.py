"""Bounded diagnostic JSONL logs; never inspects delivery queues or state."""
from __future__ import annotations

from contextlib import contextmanager
import json
import logging
import os
from pathlib import Path
import re
import stat
import time

from .artifacts import resolve_artifact_policy


LOGGER = logging.getLogger(__name__)


def _regular(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise OSError("Diagnostic logs must be regular files, not symlinks")


@contextmanager
def _locked(path):
    if path.exists() or path.is_symlink():
        _regular(path)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    stream = os.fdopen(fd, "r+b")
    locked = False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("Diagnostic log lock must be a regular file")
        if os.name == "nt":
            import msvcrt
            if os.fstat(fd).st_size == 0:
                stream.write(b"0"); stream.flush()
            stream.seek(0)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = True
        yield
    finally:
        if locked:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
        stream.close()


def append_jsonl(path, record, *, env=None):
    """Append one complete record with bounded size/count/age rotations.

    Invalid configuration raises ValueError before mutation. Diagnostic I/O
    failures return False and warn, preserving the caller's original failure.
    A record larger than the configured log size is skipped, never truncated.
    """
    policy = resolve_artifact_policy(env)
    encoded = (json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    maximum = int(policy.log_max_mb * 1024 * 1024)
    if len(encoded) > maximum:
        LOGGER.warning("Diagnostic JSONL record skipped: exceeds configured log size")
        return False
    path = Path(path).absolute()
    if path.suffix != ".jsonl":
        raise ValueError("Diagnostic append_jsonl requires a .jsonl file")
    try:
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise OSError("Diagnostic log path contains a symlink")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        pattern = re.compile(re.escape(path.name) + r"\.([1-9][0-9]*)\Z")
        with _locked(path.with_name(path.name + ".lock")):
            rotations = {}
            for candidate in path.parent.iterdir():
                match = pattern.fullmatch(candidate.name)
                if candidate == path or match:
                    _regular(candidate)
                if match:
                    rotations[int(match[1])] = candidate
            rotating = path.exists() and path.stat().st_size + len(encoded) > maximum
            cutoff = time.time() - policy.log_retention_days * 86400
            survivors = {}
            # Validate every matching path before deleting any rotated log.
            for index, candidate in rotations.items():
                if (candidate.stat().st_mtime < cutoff or index > policy.log_backup_count
                        or (rotating and index == policy.log_backup_count)):
                    candidate.unlink()
                else:
                    survivors[index] = candidate
            if rotating:
                for index in sorted(survivors, reverse=True):
                    destination = path.with_name(path.name + "." + str(index + 1))
                    if os.path.lexists(destination):
                        raise OSError("Diagnostic rotation destination unexpectedly exists")
                    survivors[index].rename(destination)
                destination = path.with_name(path.name + ".1")
                if os.path.lexists(destination):
                    raise OSError("Diagnostic rotation destination unexpectedly exists")
                path.rename(destination)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "ab") as stream:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise OSError("Diagnostic append target must be a regular file")
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        return True
    except OSError as exc:
        LOGGER.warning("Diagnostic JSONL append skipped: %s", type(exc).__name__)
        return False
