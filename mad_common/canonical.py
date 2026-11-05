"""Stable fingerprints of domain data, independent of record ordering."""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_signature(value: Any, *, exclude_keys: frozenset[str] = frozenset()) -> str:
    def normalize(item):
        if isinstance(item, dict):
            return {str(k): normalize(v) for k, v in sorted(item.items(), key=lambda pair: str(pair[0]))
                    if k not in exclude_keys}
        if isinstance(item, (list, tuple)):
            values = [normalize(v) for v in item]
            return sorted(values, key=lambda v: json.dumps(v, sort_keys=True, separators=(",", ":"), allow_nan=False))
        return item
    encoded = json.dumps(normalize(value), sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
