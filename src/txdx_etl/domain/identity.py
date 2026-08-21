from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any

ASSET_PREFIX = "asset"
RECORD_PREFIX = "record"
DELIVERY_PREFIX = "delivery"

IDENTIFIER_PATTERN = r"^[a-z]+:sha256:[0-9a-f]{64}$"


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(payload: Any) -> str:
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _prefixed(prefix: str, digest: str) -> str:
    return f"{prefix}:sha256:{digest}"


def _require_non_empty(name: str, value: Any) -> str:
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{name} must be a non-empty string")
    return value


def raw_record_hash(sanitized_raw: Mapping[str, Any]) -> str:
    return f"sha256:{_digest(sanitized_raw)}"


def asset_id(
    tenant_id: str,
    source_type: str,
    instance_id: str,
    source_asset_id: str,
) -> str:
    components = {
        "instance_id": _require_non_empty("instance_id", instance_id),
        "source_asset_id": _require_non_empty("source_asset_id", source_asset_id),
        "source_type": _require_non_empty("source_type", source_type),
        "tenant_id": _require_non_empty("tenant_id", tenant_id),
    }
    return _prefixed(ASSET_PREFIX, _digest(components))


def record_id(
    tenant_id: str,
    source_type: str,
    instance_id: str,
    record_type: str,
    source_object_id: str,
    discriminators: Mapping[str, str | None] | None = None,
) -> str:
    components = {
        "instance_id": _require_non_empty("instance_id", instance_id),
        "record_type": _require_non_empty("record_type", record_type),
        "source_object_id": _require_non_empty("source_object_id", source_object_id),
        "source_type": _require_non_empty("source_type", source_type),
        "tenant_id": _require_non_empty("tenant_id", tenant_id),
    }
    for name, value in (discriminators or {}).items():
        if isinstance(value, str) and value != "":
            components[name] = value
        elif value is not None:
            raise ValueError(f"discriminator {name} must be a string or None")
    return _prefixed(RECORD_PREFIX, _digest(components))


def delivery_id(
    schema_version: str,
    tenant_id: str,
    source_type: str,
    instance_id: str,
    record_ids: Iterable[str],
) -> str:
    ordered_ids = sorted(record_ids)
    for item in ordered_ids:
        _require_non_empty("record_ids entry", item)
    components = {
        "instance_id": _require_non_empty("instance_id", instance_id),
        "record_ids": ordered_ids,
        "schema_version": _require_non_empty("schema_version", schema_version),
        "source_type": _require_non_empty("source_type", source_type),
        "tenant_id": _require_non_empty("tenant_id", tenant_id),
    }
    return _prefixed(DELIVERY_PREFIX, _digest(components))


__all__ = [
    "ASSET_PREFIX",
    "DELIVERY_PREFIX",
    "IDENTIFIER_PATTERN",
    "RECORD_PREFIX",
    "asset_id",
    "delivery_id",
    "raw_record_hash",
    "record_id",
]
