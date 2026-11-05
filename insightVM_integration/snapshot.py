from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mad_common.snapshot import build_idempotency_key, decide_snapshot_send  # noqa: E402
from mad_common.canonical import canonical_signature


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


def build_snapshot_signature(assets_raw, normalized_assets, normalized_findings) -> str:
    # No truncation: replacements beyond former 500/5000 cutoffs remain visible.
    return canonical_signature({"assets": normalized_assets, "findings": normalized_findings})
