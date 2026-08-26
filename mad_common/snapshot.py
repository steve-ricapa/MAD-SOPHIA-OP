from __future__ import annotations

import hashlib
from typing import Any


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


def build_idempotency_key(
    company_id: int, scanner_type: str, event_type: str, snapshot_signature: str
) -> str:
    raw = f"{company_id}:{scanner_type}:{event_type}:{snapshot_signature}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
