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
    # Collection windows and normalized fallback timestamps change every poll.
    # Alert identity and all material normalized fields participate in comparison.
    _ = window_start, window_end
    canonical_findings = [
        {key: value for key, value in finding.items() if key not in {"timestamp", "collected_at", "scanned_at"}}
        for finding in findings
    ]
    canonical_findings.sort(key=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")))
    compact = {"findings": canonical_findings, "agent_summary": agent_summary or {}}
    return json.dumps(compact, separators=(",", ":"), sort_keys=True)
