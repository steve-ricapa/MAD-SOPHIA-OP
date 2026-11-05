#!/usr/bin/env python3
"""Read-only inventory of MAD runtime files. Never deletes or opens payload contents."""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import re
import time


def category(path):
    parts = path.parts
    if "delivery-v2" in parts or "queue" in parts or "failed_payloads" in parts:
        return "protected_delivery_or_queue"
    if path.suffix in {".db", ".sqlite", ".sqlite3"} or path.name.endswith((".db-wal", ".db-shm")) or "state" in path.name:
        return "protected_state"
    if ".mad-archive-v1" in parts:
        return "managed_diagnostics"
    if "raw_batches" in parts or "payloads" in parts:
        return "legacy_wazuh_history_review_only"
    if "reports" in parts and "openvas" in str(path).lower():
        return "legacy_openvas_history_review_only"
    if "payload_debug" in parts:
        return "legacy_debug_history_review_only"
    if re.search(r"\.log\.[1-9][0-9]*$", path.name) or path.name.startswith("agent_console.") and path.name != "agent_console.json":
        return "rotated_logs_review_only"
    if "logs" in parts or path.suffix in {".log", ".jsonl"}:
        return "current_logs"
    if path.name.startswith(("last_", "raw_", "debug_report", "security_data")):
        return "latest_diagnostic_copy"
    return "other_review_only"


def inventory(repo, older_than_days=30, now=None):
    now = time.time() if now is None else now
    if older_than_days <= 0:
        raise ValueError("older-than-days must be positive")
    repo = Path(repo).absolute()
    groups = defaultdict(lambda: {"files": 0, "bytes": 0, "older_than_days_bytes": 0, "safe_to_delete": False})
    skipped = 0
    for directory in (repo / "runtime", repo / "artifacts", repo / "state"):
        if directory.is_symlink():
            skipped += 1; continue
        for root, dirs, files in os.walk(directory, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
            for name in files:
                path = Path(root) / name
                try:
                    if path.is_symlink() or not path.is_file():
                        skipped += 1; continue
                    info = path.stat()
                except OSError:
                    skipped += 1; continue
                relative = path.relative_to(repo)
                key = (category(relative), str(relative.parent))
                entry = groups[key]
                entry["files"] += 1
                entry["bytes"] += info.st_size
                if now - info.st_mtime > older_than_days * 86400:
                    entry["older_than_days_bytes"] += info.st_size
    return {"read_only": True, "older_than_days": older_than_days, "skipped": skipped,
            "groups": sorted([dict(category=k[0], directory=k[1], **v) for k, v in groups.items()], key=lambda r: -r["bytes"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--older-than-days", type=int, default=30)
    args = parser.parse_args()
    print(json.dumps(inventory(args.repo, args.older_than_days), indent=2))


if __name__ == "__main__":
    main()
