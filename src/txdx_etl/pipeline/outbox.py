from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS outbox (
    delivery_id TEXT PRIMARY KEY,
    envelope_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_error TEXT
);
CREATE TABLE IF NOT EXISTS delivered_records (
    record_id TEXT PRIMARY KEY,
    delivery_id TEXT NOT NULL,
    delivered_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_outbox_status_created ON outbox(status, created_at);
"""

_CHUNK = 400


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


class SqliteOutbox:
    def __init__(self, db_path: str | Path, *, batch_limit: int = 100) -> None:
        self._path = Path(db_path)
        if self._path.parent != Path(""):
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(_SCHEMA)
        self._batch_limit = batch_limit

    def close(self) -> None:
        self._conn.close()

    def filter_new(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        identifiers = [record["record_id"] for record in records]
        known: set[str] = set()
        for start in range(0, len(identifiers), _CHUNK):
            chunk = identifiers[start : start + _CHUNK]
            placeholders = ",".join("?" * len(chunk))
            rows = self._conn.execute(
                f"SELECT record_id FROM delivered_records WHERE record_id IN ({placeholders})",
                chunk,
            )
            known.update(row[0] for row in rows)
        return [record for record in records if record["record_id"] not in known]

    def enqueue(self, envelope: dict[str, Any], *, created_at: str) -> None:
        self._conn.execute(
            "INSERT INTO outbox "
            "(delivery_id, envelope_json, status, attempts, created_at, updated_at) "
            "VALUES (?, ?, 'pending', 0, ?, ?) "
            "ON CONFLICT(delivery_id) DO NOTHING",
            (
                envelope["delivery_id"],
                canonical_json(envelope),
                created_at,
                created_at,
            ),
        )
        self._conn.commit()

    def pending_batch(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT delivery_id, envelope_json, attempts FROM outbox "
            "WHERE status = 'pending' ORDER BY created_at, delivery_id LIMIT ?",
            (self._batch_limit,),
        )
        return [
            {
                "delivery_id": row[0],
                "attempts": row[2],
                "envelope": json.loads(row[1]),
            }
            for row in rows
        ]

    def mark_delivered(self, delivery_id: str, *, delivered_at: str) -> None:
        with self._conn:
            row = self._conn.execute(
                "SELECT envelope_json FROM outbox WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown delivery_id: {delivery_id}")
            self._conn.execute(
                "UPDATE outbox SET status = 'delivered', updated_at = ? "
                "WHERE delivery_id = ?",
                (delivered_at, delivery_id),
            )
            envelope = json.loads(row[0])
            for record in envelope.get("records", []):
                self._conn.execute(
                    "INSERT OR IGNORE INTO delivered_records "
                    "(record_id, delivery_id, delivered_at) VALUES (?, ?, ?)",
                    (record["record_id"], delivery_id, delivered_at),
                )

    def mark_attempt_failed(
        self, delivery_id: str, *, error: str, attempted_at: str
    ) -> None:
        with self._conn:
            cursor = self._conn.execute(
                "UPDATE outbox SET attempts = attempts + 1, last_error = ?, "
                "updated_at = ? WHERE delivery_id = ? AND status = 'pending'",
                (error[:512], attempted_at, delivery_id),
            )
            if cursor.rowcount == 0:
                raise KeyError(f"pending delivery not found: {delivery_id}")

    def counts(self) -> dict[str, int]:
        totals = {"pending": 0, "delivered": 0}
        for status, count in self._conn.execute(
            "SELECT status, COUNT(*) FROM outbox GROUP BY status"
        ):
            totals[status] = count
        return totals


__all__ = ["SqliteOutbox", "canonical_json"]
