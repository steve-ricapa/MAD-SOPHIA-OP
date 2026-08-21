from __future__ import annotations

from typing import Any

from txdx_etl.domain import identity

SCHEMA_VERSION = "1.0.0"

_RECORD_TYPES = ("observations", "findings", "detections")
_TYPE_BY_SINGULAR = {
    "observation": "observations",
    "finding": "findings",
    "detection": "detections",
}
_OUTCOMES = ("accepted", "rejected", "quarantined")


def build_envelope(
    *,
    tenant_id: str,
    source_type: str,
    instance_id: str,
    generated_at: str,
    run_id: str,
    run_status: str,
    started_at: str,
    ended_at: str,
    collection_window_start: str,
    collection_window_end: str,
    assets: list[dict[str, Any]],
    records: list[dict[str, Any]],
    partial: bool = False,
    error_counts: dict[str, int] | None = None,
    display_name: str | None = None,
    schema_version: str = SCHEMA_VERSION,
) -> dict[str, Any]:
    counts: dict[str, int] = {"assets": len(assets)}
    for record_type in _RECORD_TYPES:
        counts[record_type] = 0
    for outcome in _OUTCOMES:
        counts[outcome] = 0

    for record in records:
        record_type = record.get("record_type")
        plural = _TYPE_BY_SINGULAR.get(record_type)
        if plural is not None:
            counts[plural] += 1
        outcome = (record.get("decision") or {}).get("outcome")
        if outcome in counts:
            counts[outcome] += 1

    source: dict[str, Any] = {"type": source_type, "instance_id": instance_id}
    if display_name is not None and display_name != "":
        source["display_name"] = display_name

    envelope: dict[str, Any] = {
        "schema_version": schema_version,
        "delivery_id": identity.delivery_id(
            schema_version,
            tenant_id,
            source_type,
            instance_id,
            [record["record_id"] for record in records],
        ),
        "tenant_id": tenant_id,
        "generated_at": generated_at,
        "source": source,
        "run": {
            "run_id": run_id,
            "status": run_status,
            "started_at": started_at,
            "ended_at": ended_at,
            "collection_window": {
                "start": collection_window_start,
                "end": collection_window_end,
            },
            "partial": partial,
            "record_counts": counts,
            "error_counts": error_counts or {},
        },
        "assets": list(assets),
        "records": list(records),
    }
    return envelope


__all__ = ["SCHEMA_VERSION", "build_envelope"]
