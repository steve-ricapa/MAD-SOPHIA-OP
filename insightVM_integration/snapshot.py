from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mad_common.snapshot import build_idempotency_key, decide_snapshot_send  # noqa: E402


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
    finding_ids: list[str] = []
    for f in normalized_findings:
        sev = _normalise_severity(f.get("severity"))
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        fid = f.get("id")
        if fid is None:
            fid = ":".join(str(f.get(k) or "") for k in ("cve", "title", "asset_id"))
        finding_ids.append(f"{fid}:{sev}")

    asset_ids = sorted(
        a.get("id", "") for a in normalized_assets if a.get("id")
    )
    compact = {
        "asset_count": len(normalized_assets),
        "finding_count": len(normalized_findings),
        "severity_counts": severity_counts,
        "asset_ids": asset_ids[:500],
        "finding_ids": sorted(finding_ids)[:5000],
    }
    return json.dumps(compact, separators=(",", ":"), sort_keys=True)
