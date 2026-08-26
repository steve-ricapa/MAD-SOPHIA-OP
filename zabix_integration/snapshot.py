from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mad_common.snapshot import build_idempotency_key, decide_snapshot_send  # noqa: E402


def _normalise_severity(sev: int) -> str:
    mapping = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info", 0: "info"}
    return mapping.get(sev, "info")


def build_snapshot_signature(
    problems: list[dict[str, Any]],
    events: list[dict[str, Any]],
    all_hosts: list[dict[str, Any]],
    all_triggers: list[dict[str, Any]],
) -> str:
    severity_counts: dict[str, int] = {}
    problem_ids: list[str] = []
    for p in problems:
        sev = int(p.get("severity", 0))
        label = _normalise_severity(sev)
        severity_counts[label] = severity_counts.get(label, 0) + 1
        oid = p.get("objectid")
        if oid is not None:
            problem_ids.append(f"{oid}:{label}")

    trigger_ids: list[str] = []
    for t in all_triggers:
        tid = t.get("triggerid")
        if tid is not None:
            trigger_ids.append(f"{tid}:{int(t.get('priority', 0))}")

    compact = {
        "problem_count": len(problems),
        "event_count": len(events),
        "host_count": len(all_hosts),
        "trigger_count": len(all_triggers),
        "severity_counts": severity_counts,
        "problem_ids": sorted(problem_ids),
        "trigger_ids": sorted(trigger_ids),
    }
    return json.dumps(compact, separators=(",", ":"), sort_keys=True)
