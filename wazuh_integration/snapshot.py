from __future__ import annotations

import json
from typing import Any


def build_snapshot_signature(
    findings: list[dict[str, Any]],
    agent_summary: dict[str, Any] | None,
    window_start: str,
    window_end: str,
) -> str:
    compact = {
        "window_start": window_start,
        "window_end": window_end,
        "finding_count": len(findings),
        "agent_total": (agent_summary or {}).get("total", 0),
    }
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    compact["severity_counts"] = severity_counts
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
