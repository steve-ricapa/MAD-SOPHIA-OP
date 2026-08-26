from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mad_common.snapshot import build_idempotency_key, decide_snapshot_send  # noqa: E402


def _monitor_sort_key(monitor_id: str) -> tuple[int, Any]:
    monitor_id_str = str(monitor_id)
    if monitor_id_str.isdigit():
        return 0, int(monitor_id_str)
    return 1, monitor_id_str


def build_snapshot_signature(monitors: dict[str, dict[str, Any]]) -> str:
    compact = {
        mid: int(m.get("status", -1))
        for mid, m in sorted(monitors.items(), key=lambda it: _monitor_sort_key(it[0]))
    }
    return json.dumps(compact, sort_keys=True, separators=(",", ":"))
