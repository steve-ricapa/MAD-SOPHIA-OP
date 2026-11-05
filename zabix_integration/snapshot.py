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


def _normalise_severity(sev: int) -> str:
    mapping = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info", 0: "info"}
    return mapping.get(sev, "info")


def build_snapshot_signature(problems, events, all_hosts, all_triggers) -> str:
    return canonical_signature({"problems": problems, "events": events, "hosts": all_hosts, "triggers": all_triggers})
