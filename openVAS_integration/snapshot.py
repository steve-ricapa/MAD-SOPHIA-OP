from __future__ import annotations

import json
from typing import Any


def _task_sort_key(task: dict[str, Any]) -> tuple[str, str]:
    return str(task.get("task_id") or ""), str(task.get("report_id") or "")


def build_snapshot_signature(task_rows: list[dict[str, Any]]) -> str:
    compact = [
        {
            "task_id": str(row.get("task_id") or ""),
            "task_name": str(row.get("task_name") or ""),
            "report_id": str(row.get("report_id") or ""),
            "status": str(row.get("status") or ""),
            "modification_time": str(row.get("modification_time") or ""),
        }
        for row in sorted(task_rows, key=_task_sort_key)
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
