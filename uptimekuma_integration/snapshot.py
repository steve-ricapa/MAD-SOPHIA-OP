from __future__ import annotations

import json
from typing import Any


def _monitor_sort_key(monitor_id: str) -> tuple[int, Any]:
    monitor_id_str = str(monitor_id)
    if monitor_id_str.isdigit():
        return 0, int(monitor_id_str)
    return 1, monitor_id_str


def build_snapshot_signature(monitors: dict[str, dict[str, Any]]) -> str:
    compact = {
        mid: int(m.get("status", -1))
        for mid, m in sorted(monitors.items(), key=lambda it: _monitor_sort_key(it[0]))
    }
    return json.dumps(compact, sort_keys=True, separators=(",", ":"))


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
