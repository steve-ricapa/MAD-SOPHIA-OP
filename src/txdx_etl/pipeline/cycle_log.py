from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from txdx_etl.pipeline.runtime import CycleReport

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cycle_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at TEXT NOT NULL,
    scrape_ok INTEGER NOT NULL,
    scrape_error TEXT,
    records_detected INTEGER NOT NULL,
    records_enqueued INTEGER NOT NULL,
    drain_attempted INTEGER NOT NULL,
    delivered INTEGER NOT NULL,
    parked INTEGER NOT NULL,
    transient_failures INTEGER NOT NULL,
    skipped_by_backoff INTEGER NOT NULL,
    pending_left INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cycle_log_id_desc ON cycle_log(id DESC);
"""


class SqliteCycleLog:
    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        if self._path.parent != Path(""):
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def append(self, report: CycleReport) -> None:
        self._conn.execute(
            "INSERT INTO cycle_log "
            "(observed_at, scrape_ok, scrape_error, records_detected, "
            "records_enqueued, drain_attempted, delivered, parked, "
            "transient_failures, skipped_by_backoff, pending_left) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                report.observed_at,
                1 if report.scrape_ok else 0,
                report.scrape_error,
                report.records_detected,
                report.records_enqueued,
                report.drain.attempted,
                report.drain.delivered,
                report.drain.parked,
                report.drain.transient_failures,
                1 if report.drain.skipped_by_backoff else 0,
                report.drain.pending_left,
            ),
        )
        self._conn.commit()

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id, observed_at, scrape_ok, scrape_error, "
            "records_detected, records_enqueued, drain_attempted, "
            "delivered, parked, transient_failures, skipped_by_backoff, "
            "pending_left FROM cycle_log ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [
            {
                "id": row[0],
                "observed_at": row[1],
                "scrape_ok": bool(row[2]),
                "scrape_error": row[3],
                "records_detected": row[4],
                "records_enqueued": row[5],
                "drain_attempted": row[6],
                "delivered": row[7],
                "parked": row[8],
                "transient_failures": row[9],
                "skipped_by_backoff": bool(row[10]),
                "pending_left": row[11],
            }
            for row in rows
        ]


__all__ = ["SqliteCycleLog"]
