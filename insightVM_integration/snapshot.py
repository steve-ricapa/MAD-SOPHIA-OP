from __future__ import annotations

import hashlib
import json
from typing import Any


def _normalise_severity(sev: str | None) -> str:
    if sev is None:
        return "info"
    s = sev.strip().lower()
    if s in ("info", "informational", "unknown"):
        return "info"
    if s == "low":
        return "low"
    if s in ("medium", "moderate"):
        return "medium"
    if s in ("high", "severe"):
        return "high"
    if s == "critical":
        return "critical"
    return "info"


def build_snapshot_signature(
    assets_raw: dict[str, Any],
    normalized_assets: list[dict[str, Any]],
    normalized_findings: list[dict[str, Any]],
) -> str:
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in normalized_findings:
        sev = _normalise_severity(f.get("severity"))
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    asset_ids = sorted(
        a.get("id", "") for a in normalized_assets if a.get("id")
    )
    compact = {
        "asset_count": len(normalized_assets),
        "finding_count": len(normalized_findings),
        "severity_counts": severity_counts,
        "asset_ids": asset_ids[:500],
    }
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


def build_idempotency_key(
    company_id: int, scanner_type: str, event_type: str, snapshot_signature: str
) -> str:
    raw = f"{company_id}:{scanner_type}:{event_type}:{snapshot_signature}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"insightvm-snapshot-{digest}"
