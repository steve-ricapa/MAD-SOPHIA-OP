"""Optional, bounded diagnostics. Never traverses states or delivery queues."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import logging
import math
import os
from pathlib import Path
import re
import tempfile
import time
import uuid
from io import BytesIO

LOGGER = logging.getLogger(__name__)
FORMAT = "mad-artifact-v1"
ALLOWED_FILES = {"raw.json", "snapshot.json", "normalized.json", "payload.json",
                 "metadata.json", "report.xml", "assets.json", "assets.csv"}


@dataclass(frozen=True)
class ArtifactPolicy:
    enabled: bool = False
    retention_days: float = 7
    max_bytes: int = 100 * 1024 * 1024
    max_entries: int = 100
    log_max_mb: float = 5
    log_backup_count: int = 5
    log_retention_days: float = 14


def resolve_artifact_policy(env=None):
    env = os.environ if env is None else env
    def number(key, default, integer=False):
        raw = env.get(key, str(default))
        try:
            value = int(raw) if integer else float(raw)
            if isinstance(raw, bool) or not math.isfinite(value) or value <= 0:
                raise ValueError()
            return value
        except (ValueError, TypeError, OverflowError):
            raise ValueError(f"{key} must be a positive {'integer' if integer else 'finite number'}") from None
    enabled = str(env.get("MAD_ARCHIVE_ENABLED", "false")).strip().lower()
    if enabled not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
        raise ValueError("MAD_ARCHIVE_ENABLED must be true or false")
    return ArtifactPolicy(
        enabled in {"true", "1", "yes", "on"},
        number("MAD_ARCHIVE_RETENTION_DAYS", 7),
        int(number("MAD_ARCHIVE_MAX_MB", 100) * 1024 * 1024),
        number("MAD_ARCHIVE_MAX_ENTRIES", 100, True),
        number("MAD_LOG_MAX_MB", 5, True),
        number("MAD_LOG_BACKUP_COUNT", 5, True),
        number("MAD_LOG_RETENTION_DAYS", 14, True),
    )


def _private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


@contextmanager
def _lock(home):
    lock_path = home / ".lock"
    if lock_path.is_symlink():
        raise OSError("Archive lock is a symlink")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    stream = os.fdopen(fd, "r+b")
    locked = False
    try:
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
                stream.seek(0); msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
        stream.close()


def _home(root, integration, create=False):
    if not re.fullmatch(r"[a-z][a-z0-9_]*", integration):
        raise ValueError("Invalid archive integration")
    root = Path(root).absolute()
    home = root / ".mad-archive-v1" / integration
    if any(p.is_symlink() for p in (home, *home.parents)):
        raise OSError("Archive path contains a symlink")
    if not home.exists() and not create:
        return None
    if create:
        home.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(home, 0o700)
    marker = home / ".owner.json"
    expected = {"format": FORMAT, "integration": integration}
    if marker.is_symlink():
        raise OSError("Archive marker is a symlink")
    if not marker.exists():
        if any(home.iterdir()):
            raise OSError("Unowned archive directory; manual review required")
        _private_write(marker, json.dumps(expected).encode())
    if json.loads(marker.read_text()) != expected:
        raise OSError("Archive owner mismatch")
    return home


def _entries(home, integration):
    entries = []
    for path in home.iterdir():
        if path.name in {".owner.json", ".lock"}:
            continue
        if path.is_symlink() or not path.is_dir() or not re.fullmatch(r"entry-[0-9a-f]{32}", path.name):
            raise OSError("Unrecognized archive entry; manual review required")
        marker = path / ".entry.json"
        if marker.is_symlink():
            raise OSError("Archive entry marker is a symlink")
        data = json.loads(marker.read_text())
        if not isinstance(data, dict):
            raise OSError("Invalid archive entry manifest")
        names = data.get("files")
        created = data.get("created_at")
        if (data.get("format") != FORMAT or data.get("integration") != integration
                or not isinstance(names, list) or not names or len(names) != len(set(names))
                or not all(isinstance(n, str) and n in ALLOWED_FILES for n in names)
                or type(created) not in (int, float) or not math.isfinite(created)
                or {p.name for p in path.iterdir()} != set(names) | {".entry.json"}):
            raise OSError("Invalid archive entry; manual review required")
        files = [path / n for n in [*names, ".entry.json"]]
        if any(p.is_symlink() or not p.is_file() for p in files):
            raise OSError("Unsafe archive entry")
        entries.append((created, path, files, sum(p.stat().st_size for p in files)))
    return sorted(entries, key=lambda row: (row[0], row[1].name))


def _prune(home, integration, policy, reserve_bytes=0, reserve_entries=0):
    entries = _entries(home, integration)
    total = sum(row[3] for row in entries) + reserve_bytes
    count = len(entries) + reserve_entries
    cutoff = time.time() - policy.retention_days * 86400
    for created, path, files, size in entries:
        if created >= cutoff and total <= policy.max_bytes and count <= policy.max_entries:
            continue
        # Only files listed in this manager's own validated manifest are removed.
        for file in files:
            file.unlink()
        path.rmdir()
        total -= size
        count -= 1


def maintain_history(root, integration, env=None):
    policy = resolve_artifact_policy(env)
    try:
        home = _home(root, integration)
        if home is not None:
            with _lock(home):
                _prune(home, integration, policy)
    except (OSError, ValueError, TypeError) as exc:
        LOGGER.warning("Diagnostic retention skipped for %s: %s", integration, type(exc).__name__)


def archive_bundle(root, integration, files, *, force=False, env=None):
    """Write optional diagnostic copies, never delivery state. Legacy dirs untouched.

    force is reserved for explicit legacy *_PAYLOAD_DEBUG flags; the same bounds apply.
    I/O problems in optional diagnostics do not interrupt metadata delivery.
    """
    policy = resolve_artifact_policy(env)
    if not policy.enabled and not force:
        maintain_history(root, integration, env)
        return None
    if not files or not set(files).issubset(ALLOWED_FILES):
        raise ValueError("Unsupported diagnostic filename")
    manifest = json.dumps({"format": FORMAT, "integration": integration,
                           "created_at": time.time(), "files": sorted(files)}).encode()
    encoded = {}
    size = len(manifest)
    try:
        encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False)
        for name, value in files.items():
            chunks = (value[i:i + 65536] for i in range(0, len(value), 65536)) if isinstance(value, str) else encoder.iterencode(value)
            with BytesIO() as stream:
                for chunk in chunks:
                    data = chunk.encode("utf-8")
                    if size + stream.tell() + len(data) > policy.max_bytes:
                        LOGGER.warning("Diagnostic bundle exceeds archive budget for %s; not saved", integration)
                        return None
                    stream.write(data)
                encoded[name] = stream.getvalue()
            size += len(encoded[name])
    except (MemoryError, ValueError, TypeError):
        LOGGER.warning("Diagnostic encoding skipped for %s", integration)
        return None
    try:
        home = _home(root, integration, create=True)
        with _lock(home):
            _prune(home, integration, policy, size, 1)
            target = home / ("entry-" + uuid.uuid4().hex)
            target.mkdir(mode=0o700)
            try:
                for name, data in encoded.items():
                    _private_write(target / name, data)
                _private_write(target / ".entry.json", manifest)
            except BaseException:
                for name in [*encoded, ".entry.json"]:
                    p = target / name
                    if p.is_file() and not p.is_symlink(): p.unlink()
                target.rmdir()
                raise
            return target
    except (OSError, ValueError, TypeError) as exc:
        LOGGER.warning("Diagnostic archive skipped for %s: %s", integration, type(exc).__name__)
        return None


def log_retention(files):
    """Loguru passes only rotated log candidates to this callback."""
    policy = resolve_artifact_policy()
    candidates = []
    for raw in files:
        p = Path(raw)
        if p.is_symlink() or not p.is_file() or not re.fullmatch(r"agent_console\..+\.json", p.name):
            continue
        candidates.append(p)
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    cutoff = time.time() - policy.log_retention_days * 86400
    for index, path in enumerate(candidates):
        if index >= policy.log_backup_count or path.stat().st_mtime < cutoff:
            path.unlink()
