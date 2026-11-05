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


def _scan_sort_key(scan: dict[str, Any]) -> tuple[int, int]:
    return (
        int(scan.get("scan_id", 0) or 0),
        int(scan.get("last_modification_date", 0) or 0),
    )


def build_snapshot_signature(scans: list[dict[str, Any]]) -> str:
    # Source timestamps, findings and targets are meaningful; collection IDs are not present here.
    return canonical_signature(scans)
