from __future__ import annotations

import json
from typing import Any


def _scan_sort_key(scan: dict[str, Any]) -> tuple[int, int]:
    return (
        int(scan.get("scan_id", 0) or 0),
        int(scan.get("last_modification_date", 0) or 0),
    )


def build_snapshot_signature(scans: list[dict[str, Any]]) -> str:
    compact = [
        {
            "scan_id": int(s.get("scan_id", 0) or 0),
            "last_modification_date": int(s.get("last_modification_date", 0) or 0),
            "status": str(s.get("status", "")),
        }
        for s in sorted(scans, key=_scan_sort_key)
    ]
    return json.dumps(compact, separators=(",", ":"), sort_keys=True)


def decide_snapshot_send(
    *,
    current_signature: str,
    previous_signature: str,
    unchanged_cycles: int,
    has_sent_once: bool,
    force_send_every_cycles: int,
    snapshot_always_send: bool,
) -> dict[str, Any]:
    changed = current_signature != previous_signature
    next_unchanged = 0 if changed else (int(unchanged_cycles) + 1)

    if snapshot_always_send:
        return {
            "changed": changed,
            "should_send": True,
            "reason": "always_snapshot",
            "unchanged_cycles": next_unchanged,
        }
    if not has_sent_once:
        return {
            "changed": changed,
            "should_send": True,
            "reason": "first_snapshot",
            "unchanged_cycles": next_unchanged,
        }
    if next_unchanged >= max(1, int(force_send_every_cycles)):
        return {
            "changed": changed,
            "should_send": True,
            "reason": "force_send_cycle",
            "unchanged_cycles": next_unchanged,
        }
    return {
        "changed": changed,
        "should_send": changed,
        "reason": "snapshot_changed" if changed else "no_change",
        "unchanged_cycles": next_unchanged,
    }
