from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mad_common.snapshot import build_idempotency_key, decide_snapshot_send  # noqa: E402


def _task_sort_key(task: dict[str, Any]) -> tuple[str, str]:
    return str(task.get("task_id") or ""), str(task.get("report_id") or "")


def build_snapshot_signature(task_rows: list[dict[str, Any]]) -> str:
    compact = [
        {
            "task_id": str(row.get("task_id") or ""),
            "task_name": str(row.get("task_name") or ""),
            "report_id": str(row.get("report_id") or ""),
            "status": str(row.get("status") or ""),
            "modification_time": str(row.get("modification_time") or ""),
        }
        for row in sorted(task_rows, key=_task_sort_key)
    ]
    return json.dumps(compact, separators=(",", ":"), sort_keys=True)
