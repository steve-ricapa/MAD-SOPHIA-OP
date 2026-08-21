from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from txdx_etl.domain import identity

_RECORD_TYPES = ("observations", "findings", "detections")
_TYPE_TO_SINGULAR = {
    "observations": "observation",
    "findings": "finding",
    "detections": "detection",
}
_DECISION_OUTCOMES = ("accepted", "rejected", "quarantined")


@dataclass(frozen=True)
class Violation:
    code: str
    pointer: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code} at {self.pointer}: {self.detail}"


def validate_envelope(envelope: dict[str, Any]) -> list[Violation]:
    violations: list[Violation] = []
    violations.extend(_validate_delivery_identity(envelope))
    violations.extend(_validate_assets(envelope))
    violations.extend(_validate_records(envelope))
    violations.extend(_validate_counts(envelope))
    violations.extend(_validate_run_times(envelope))
    return violations


def _parse_timestamp(pointer: str, value: Any, violations: list[Violation]) -> datetime | None:
    if not isinstance(value, str):
        violations.append(
            Violation("run.time_order", pointer, "timestamp is not a string")
        )
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        violations.append(Violation("run.time_order", pointer, "unparseable timestamp"))
        return None


def _validate_delivery_identity(envelope: dict[str, Any]) -> list[Violation]:
    schema_version = envelope.get("schema_version")
    tenant_id = envelope.get("tenant_id")
    source = envelope.get("source") or {}
    source_type = source.get("type")
    instance_id = source.get("instance_id")
    records = envelope.get("records")
    stated = envelope.get("delivery_id")
    if any(
        value in (None, "")
        for value in (schema_version, tenant_id, source_type, instance_id, records, stated)
    ):
        return [
            Violation(
                "delivery.id_mismatch",
                "/delivery_id",
                "envelope lacks fields required to recompute delivery identity",
            )
        ]
    expected = identity.delivery_id(
        schema_version,
        tenant_id,
        source_type,
        instance_id,
        [record.get("record_id", "") for record in records],
    )
    if expected != stated:
        return [
            Violation(
                "delivery.id_mismatch",
                "/delivery_id",
                f"expected {expected}, found {stated}",
            )
        ]
    return []


def _validate_assets(envelope: dict[str, Any]) -> list[Violation]:
    violations: list[Violation] = []
    seen: set[str] = set()
    for index, asset in enumerate(envelope.get("assets") or []):
        asset_id_value = asset.get("asset_id")
        if not isinstance(asset_id_value, str) or asset_id_value == "":
            violations.append(
                Violation("asset.missing_id", f"/assets/{index}", "asset has no asset_id")
            )
            continue
        if asset_id_value in seen:
            violations.append(
                Violation(
                    "asset.duplicate_id",
                    f"/assets/{index}",
                    f"duplicate asset_id {asset_id_value}",
                )
            )
        seen.add(asset_id_value)
    return violations


def _validate_records(envelope: dict[str, Any]) -> list[Violation]:
    violations: list[Violation] = []
    asset_ids = {
        asset.get("asset_id")
        for asset in envelope.get("assets") or []
        if isinstance(asset.get("asset_id"), str)
    }
    seen: set[str] = set()
    for index, record in enumerate(envelope.get("records") or []):
        record_id_value = record.get("record_id")
        if not isinstance(record_id_value, str) or record_id_value == "":
            violations.append(
                Violation("record.missing_id", f"/records/{index}", "record has no record_id")
            )
        elif record_id_value in seen:
            violations.append(
                Violation(
                    "record.duplicate_id",
                    f"/records/{index}",
                    f"duplicate record_id {record_id_value}",
                )
            )
        else:
            seen.add(record_id_value)

        outcome = (record.get("decision") or {}).get("outcome")
        if outcome != "accepted":
            violations.append(
                Violation(
                    "boundary.record_not_accepted",
                    f"/records/{index}/decision/outcome",
                    f"delivery boundary requires accepted, found {outcome!r}",
                )
            )

        referenced_asset = record.get("asset_id")
        if referenced_asset not in asset_ids:
            violations.append(
                Violation(
                    "record.asset_reference_missing",
                    f"/records/{index}/asset_id",
                    f"asset_id {referenced_asset!r} not declared in assets",
                )
            )
    return violations


def _validate_counts(envelope: dict[str, Any]) -> list[Violation]:
    violations: list[Violation] = []
    run = envelope.get("run") or {}
    counts = run.get("record_counts")
    if not isinstance(counts, dict):
        return [
            Violation("counts.missing", "/run/record_counts", "record_counts is missing")
        ]

    assets = envelope.get("assets") or []
    records = envelope.get("records") or []

    if counts.get("assets") != len(assets):
        violations.append(
            Violation(
                "counts.assets_mismatch",
                "/run/record_counts/assets",
                f"declared {counts.get('assets')}, actual {len(assets)}",
            )
        )

    for plural in _RECORD_TYPES:
        actual = sum(
            1 for record in records if record.get("record_type") == _TYPE_TO_SINGULAR[plural]
        )
        if counts.get(plural) != actual:
            violations.append(
                Violation(
                    f"counts.{plural}_mismatch",
                    f"/run/record_counts/{plural}",
                    f"declared {counts.get(plural)}, actual {actual}",
                )
            )

    tallies = {outcome: 0 for outcome in _DECISION_OUTCOMES}
    for record in records:
        outcome = (record.get("decision") or {}).get("outcome")
        if outcome in tallies:
            tallies[outcome] += 1
    for outcome, tally in tallies.items():
        if counts.get(outcome) != tally:
            violations.append(
                Violation(
                    f"counts.{outcome}_mismatch",
                    f"/run/record_counts/{outcome}",
                    f"declared {counts.get(outcome)}, actual {tally}",
                )
            )

    total_declared = sum(counts.get(outcome, 0) for outcome in _DECISION_OUTCOMES)
    if total_declared != len(records):
        violations.append(
            Violation(
                "counts.total_mismatch",
                "/run/record_counts",
                f"decision totals {total_declared} do not match records length {len(records)}",
            )
        )
    return violations


def _validate_run_times(envelope: dict[str, Any]) -> list[Violation]:
    violations: list[Violation] = []
    run = envelope.get("run") or {}
    started = _parse_timestamp("/run/started_at", run.get("started_at"), violations)
    ended = _parse_timestamp("/run/ended_at", run.get("ended_at"), violations)
    if started is not None and ended is not None and ended < started:
        violations.append(
            Violation(
                "run.time_order",
                "/run/ended_at",
                "ended_at precedes started_at",
            )
        )

    window = run.get("collection_window") or {}
    window_start = _parse_timestamp(
        "/run/collection_window/start", window.get("start"), violations
    )
    window_end = _parse_timestamp(
        "/run/collection_window/end", window.get("end"), violations
    )
    if (
        window_start is not None
        and window_end is not None
        and window_end < window_start
    ):
        violations.append(
            Violation(
                "run.time_order",
                "/run/collection_window/end",
                "window end precedes window start",
            )
        )
    return violations


__all__ = ["Violation", "validate_envelope"]
