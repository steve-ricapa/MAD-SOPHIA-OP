from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mad_common.snapshot import build_idempotency_key, decide_snapshot_send  # noqa: E402


def _scan_sort_key(scan: dict[str, Any]) -> tuple[int, int]:
    return (
        int(scan.get("scan_id", 0) or 0),
        int(scan.get("last_modification_date", 0) or 0),
    )


def build_snapshot_signature(scans: list[dict[str, Any]]) -> str:
    compact = [
        {
            "scan_id": int(s.get("scan_id", 0) or 0),
            "last_modification_date": int(s.get("last_modification_date", 0) or 0),
            "status": str(s.get("status", "")),
        }
        for s in sorted(scans, key=_scan_sort_key)
    ]
    return json.dumps(compact, separators=(",", ":"), sort_keys=True)
