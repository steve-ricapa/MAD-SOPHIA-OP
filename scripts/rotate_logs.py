#!/usr/bin/env python3
"""Rotate only MAD orchestration logs, under the caller's integration lock.

The size limit is checked before a collector starts; it is not a hard cap on
output produced during that collector's execution. --dry-run never mutates files.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from io import StringIO
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Mapping

from dotenv import dotenv_values
from dotenv.parser import parse_stream


ROOT = Path(__file__).resolve().parents[1]
NAMES = {"nessus", "uptimekuma", "zabbix", "openvas", "wazuh", "insightvm"}


@dataclass(frozen=True)
class LogPolicy:
    max_mb: int = 5
    backup_count: int = 5
    retention_days: int = 14


def policy_from_env(env: Mapping[str, str]) -> LogPolicy:
    values = []
    for name, default in (("MAD_LOG_MAX_MB", 5), ("MAD_LOG_BACKUP_COUNT", 5),
                          ("MAD_LOG_RETENTION_DAYS", 14)):
        raw = env.get(name, str(default))
        if not isinstance(raw, str) or not re.fullmatch(r"[0-9]+", raw.strip()):
            raise ValueError(f"{name} must be a positive integer")
        value = int(raw)
        if value < 1:
            raise ValueError(f"{name} must be a positive integer")
        values.append(value)
    return LogPolicy(*values)


def rotate(log: Path, *, repo: Path = ROOT, env: Mapping[str, str] | None = None,
           dry_run: bool = False, now: float | None = None) -> list[dict]:
    """Plan/apply bounded rotation. Never inspect or prune collector state/queues."""
    repo = Path(repo).absolute()
    log = Path(os.path.abspath(log))
    directory = repo / "runtime" / "logs"
    if log.parent != directory or log.name not in {name + ".log" for name in NAMES}:
        raise ValueError("Only named MAD runtime/logs collector logs are allowed")
    for parent in (repo, repo / "runtime", directory):
        if parent.is_symlink():
            raise ValueError("Log directories must not be symlinks")
    policy = policy_from_env(env if env is not None else os.environ)
    now = time.time() if now is None else now
    pattern = re.compile(re.escape(log.name) + r"\.([1-9][0-9]*)\Z")
    snapshots = {}
    rotations = {}
    for candidate in directory.iterdir() if directory.exists() else ():
        match = pattern.fullmatch(candidate.name)
        if candidate != log and not match:
            continue
        info = candidate.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("MAD log files and rotations must be regular files")
        snapshots[candidate] = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        if match:
            rotations[int(match[1])] = (candidate, info)
    actions = []
    rotating = log in snapshots and snapshots[log][2] >= policy.max_mb * 1024 * 1024
    expired = now - policy.retention_days * 86400
    survivors = {}
    for index, (candidate, info) in rotations.items():
        if info.st_mtime < expired or index > policy.backup_count or (rotating and index == policy.backup_count):
            actions.append({"action": "remove", "path": str(candidate)})
        else:
            survivors[index] = candidate
    if rotating:
        for index in sorted(survivors, reverse=True):
            actions.append({"action": "move", "path": str(survivors[index]),
                            "to": str(directory / (log.name + "." + str(index + 1)))})
        actions.append({"action": "move", "path": str(log), "to": str(directory / (log.name + ".1"))})
    if not dry_run:
        for action in actions:
            source = Path(action["path"])
            info = source.lstat()
            if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != snapshots[source]:
                raise RuntimeError("Log changed during rotation; integration lock is required")
            if action["action"] == "remove":
                source.unlink()
            else:
                destination = Path(action["to"])
                if os.path.lexists(destination):
                    raise RuntimeError("Rotation destination unexpectedly exists")
                source.rename(destination)
    return actions


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    # Match collectors: values declared in the repository .env override inherited
    # process values. Never source shell code or print the configuration contents.
    try:
        env = dict(os.environ)
        env_path = ROOT / ".env"
        if env_path.exists():
            contents = env_path.read_text(encoding="utf-8-sig")
            if any(binding.error for binding in parse_stream(StringIO(contents))):
                raise ValueError("Invalid .env syntax; log rotation was not started")
            env.update({key: value for key, value in dotenv_values(stream=StringIO(contents)).items() if value is not None})
        actions = rotate(args.log, repo=ROOT, env=env, dry_run=args.dry_run)
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"[log-rotation] failed: {type(exc).__name__}: {exc}")
        return 1
    print(json.dumps({"dry_run": args.dry_run, "actions": actions}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
