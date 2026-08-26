from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mad_common.snapshot import build_idempotency_key, decide_snapshot_send  # noqa: E402


def build_snapshot_signature(
    findings: list[dict[str, Any]],
    agent_summary: dict[str, Any] | None,
    window_start: str,
    window_end: str,
) -> str:
    # window_start/window_end se reciben por compatibilidad pero se ignoran:
    # la firma debe ser puramente de contenido para que el dedup funcione.
    _ = window_start, window_end

    severity_counts: dict[str, int] = {}
    finding_ids: list[str] = []
    for f in findings:
        sev = f.get("severity", "low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        fid = f.get("id") or f.get("_id")
        if fid is not None:
            finding_ids.append(f"{fid}:{sev}")

    compact = {
        "finding_count": len(findings),
        "agent_total": (agent_summary or {}).get("total", 0),
        "severity_counts": severity_counts,
        "finding_ids": sorted(finding_ids),
    }
    return json.dumps(compact, separators=(",", ":"), sort_keys=True)
