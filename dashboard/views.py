from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from txdx_etl.pipeline.cycle_log import SqliteCycleLog

_EMPTY_COUNTS = {"pending": 0, "delivered": 0, "failed": 0}


def _connect_readonly(db_path: str | Path) -> sqlite3.Connection | None:
    path = Path(db_path)
    if not path.exists():
        return None
    try:
        return sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    except sqlite3.OperationalError:
        return None


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone()
    return row is not None


def queue_counts(db_path: str | Path) -> dict[str, int]:
    conn = _connect_readonly(db_path)
    if conn is None or not _has_table(conn, "outbox"):
        return dict(_EMPTY_COUNTS)
    try:
        totals = dict(_EMPTY_COUNTS)
        for status, count in conn.execute(
            "SELECT status, COUNT(*) FROM outbox GROUP BY status"
        ):
            totals[status] = count
        return totals
    finally:
        conn.close()


def tracked_monitors(db_path: str | Path) -> list[dict[str, Any]]:
    conn = _connect_readonly(db_path)
    if conn is None or not _has_table(conn, "kuma_monitor_state"):
        return []
    try:
        monitors = []
        for row in conn.execute(
            "SELECT source_asset_id, identity_quality, labels_json, "
            "canonical_status, first_seen_at, last_seen_at, last_emitted_at, "
            "cert_is_valid, missing_scrapes FROM kuma_monitor_state "
            "ORDER BY source_asset_id"
        ):
            labels = json.loads(row[2])
            monitors.append(
                {
                    "source_asset_id": row[0],
                    "identity_quality": row[1],
                    "monitor_name": labels.get("monitor_name"),
                    "monitor_type": labels.get("monitor_type"),
                    "canonical_status": row[3],
                    "first_seen_at": row[4],
                    "last_seen_at": row[5],
                    "last_emitted_at": row[6],
                    "cert_is_valid": row[7],
                    "missing_scrapes": row[8],
                }
            )
        return monitors
    finally:
        conn.close()


def detector_cycles(db_path: str | Path) -> int:
    conn = _connect_readonly(db_path)
    if conn is None or not _has_table(conn, "kuma_detector_meta"):
        return 0
    try:
        row = conn.execute(
            "SELECT value FROM kuma_detector_meta WHERE key = 'cycles'"
        ).fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


def recent_cycles(db_path: str | Path, limit: int = 30) -> list[dict[str, Any]]:
    path = Path(db_path)
    if not path.exists() or not _has_cycle_log(path):
        return []
    log = SqliteCycleLog(path)
    try:
        return log.recent(limit=limit)
    finally:
        log.close()


def _has_cycle_log(path: Path) -> bool:
    conn = _connect_readonly(path)
    if conn is None:
        return False
    try:
        return _has_table(conn, "cycle_log")
    finally:
        conn.close()


def recent_events(
    db_path: str | Path,
    *,
    envelope_limit: int = 40,
    max_events: int = 80,
) -> list[dict[str, Any]]:
    conn = _connect_readonly(db_path)
    if conn is None or not _has_table(conn, "outbox"):
        return []
    try:
        rows = conn.execute(
            "SELECT status, created_at, envelope_json FROM outbox "
            "ORDER BY created_at DESC, delivery_id DESC LIMIT ?",
            (envelope_limit,),
        )
        events: list[dict[str, Any]] = []
        for status, created_at, envelope_json in rows:
            envelope = json.loads(envelope_json)
            for record in envelope.get("records", []):
                events.append(
                    {
                        "record_id": record.get("record_id"),
                        "asset_id": record.get("asset_id"),
                        "source_object_id": record.get("source_object_id"),
                        "observation_type": record.get("observation_type"),
                        "kind": record.get("kind"),
                        "observed_at": record.get("observed_at"),
                        "status": record.get("status"),
                        "previous_status": record.get("previous_status"),
                        "delivery_status": status,
                        "enqueued_at": created_at,
                    }
                )
        events.sort(key=lambda item: item["observed_at"] or "", reverse=True)
        return events[:max_events]
    finally:
        conn.close()


def overview(
    db_path: str | Path, *, cycles_limit: int = 30, events_limit: int = 80
) -> dict[str, Any]:
    cycles = recent_cycles(db_path, limit=cycles_limit)
    latest = cycles[0] if cycles else None
    return {
        "counts": queue_counts(db_path),
        "detector_cycles": detector_cycles(db_path),
        "tracked_monitors": tracked_monitors(db_path),
        "latest_cycle": latest,
        "cycles": cycles,
        "events": recent_events(
            db_path, max_events=events_limit
        ),
    }


__all__ = [
    "detector_cycles",
    "overview",
    "queue_counts",
    "recent_cycles",
    "recent_events",
    "tracked_monitors",
]
