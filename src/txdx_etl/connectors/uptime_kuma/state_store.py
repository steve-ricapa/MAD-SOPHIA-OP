from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from txdx_etl.connectors.uptime_kuma.detector import TrackedMonitor
from txdx_etl.pipeline.outbox import canonical_json

_SCHEMA = """
CREATE TABLE IF NOT EXISTS kuma_detector_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kuma_monitor_state (
    source_asset_id TEXT PRIMARY KEY,
    identity_quality TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    canonical_status TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_emitted_at TEXT NOT NULL,
    cert_is_valid INTEGER,
    missing_scrapes INTEGER NOT NULL DEFAULT 0
);
"""


class SqliteStateStore:
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

    def load(self) -> tuple[int, dict[str, TrackedMonitor]]:
        meta = {
            row[0]: row[1]
            for row in self._conn.execute(
                "SELECT key, value FROM kuma_detector_meta"
            )
        }
        cycles = int(meta.get("cycles", "0"))
        monitors: dict[str, TrackedMonitor] = {}
        for row in self._conn.execute(
            "SELECT source_asset_id, identity_quality, labels_json, "
            "canonical_status, first_seen_at, last_seen_at, last_emitted_at, "
            "cert_is_valid, missing_scrapes FROM kuma_monitor_state"
        ):
            monitors[row[0]] = TrackedMonitor(
                source_asset_id=row[0],
                identity_quality=row[1],
                labels=json.loads(row[2]),
                canonical_status=row[3],
                first_seen_at=row[4],
                last_seen_at=row[5],
                last_emitted_at=row[6],
                cert_is_valid=row[7],
                missing_scrapes=row[8],
            )
        return cycles, monitors

    def save(self, *, cycles: int, monitors: dict[str, TrackedMonitor]) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM kuma_monitor_state")
            for key in sorted(monitors):
                monitor = monitors[key]
                self._conn.execute(
                    "INSERT INTO kuma_monitor_state "
                    "(source_asset_id, identity_quality, labels_json, "
                    "canonical_status, first_seen_at, last_seen_at, "
                    "last_emitted_at, cert_is_valid, missing_scrapes) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        monitor.source_asset_id,
                        monitor.identity_quality,
                        canonical_json(monitor.labels),
                        monitor.canonical_status,
                        monitor.first_seen_at,
                        monitor.last_seen_at,
                        monitor.last_emitted_at,
                        monitor.cert_is_valid,
                        monitor.missing_scrapes,
                    ),
                )
            self._conn.execute(
                "INSERT OR REPLACE INTO kuma_detector_meta (key, value) "
                "VALUES ('cycles', ?)",
                (str(cycles),),
            )


__all__ = ["SqliteStateStore"]
