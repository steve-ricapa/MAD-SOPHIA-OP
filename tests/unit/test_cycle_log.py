from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from txdx_etl.pipeline.cycle_log import SqliteCycleLog


def report(observed_at: str, **overrides) -> SimpleNamespace:
    drain = SimpleNamespace(
        attempted=overrides.pop("drain_attempted", 1),
        delivered=overrides.pop("delivered", 1),
        parked=overrides.pop("parked", 0),
        transient_failures=overrides.pop("transient_failures", 0),
        skipped_by_backoff=overrides.pop("skipped_by_backoff", False),
        pending_left=overrides.pop("pending_left", 0),
    )
    return SimpleNamespace(
        observed_at=observed_at,
        scrape_ok=overrides.pop("scrape_ok", True),
        scrape_error=overrides.pop("scrape_error", None),
        records_detected=overrides.pop("records_detected", 2),
        records_enqueued=overrides.pop("records_enqueued", 2),
        drain=drain,
    )


class CycleLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / "cycles.db")
        self.log = SqliteCycleLog(self.path)

    def tearDown(self) -> None:
        self.log.close()

    def test_recent_returns_empty_before_any_cycle(self) -> None:
        self.assertEqual(self.log.recent(), [])

    def test_append_and_recent_roundtrip_newest_first(self) -> None:
        self.log.append(report("2026-08-22T10:00:00Z"))
        self.log.append(
            report(
                "2026-08-22T10:01:00Z",
                scrape_ok=False,
                scrape_error="AuthenticationError",
                records_detected=0,
                records_enqueued=0,
                drain_attempted=0,
                delivered=0,
                pending_left=0,
            )
        )
        rows = self.log.recent(limit=10)
        self.assertEqual([row["observed_at"] for row in rows][::-1], [
            "2026-08-22T10:00:00Z",
            "2026-08-22T10:01:00Z",
        ])
        first = rows[1]
        self.assertTrue(first["scrape_ok"])
        self.assertIsNone(first["scrape_error"])
        self.assertEqual(first["records_detected"], 2)
        self.assertEqual(first["delivered"], 1)
        second = rows[0]
        self.assertFalse(second["scrape_ok"])
        self.assertEqual(second["scrape_error"], "AuthenticationError")

    def test_backoff_and_parked_flags_survive_roundtrip(self) -> None:
        self.log.append(
            report(
                "2026-08-22T10:02:00Z",
                skipped_by_backoff=True,
                parked=1,
                transient_failures=1,
                drain_attempted=0,
                delivered=0,
                pending_left=3,
            )
        )
        row = self.log.recent(limit=1)[0]
        self.assertTrue(row["skipped_by_backoff"])
        self.assertEqual(row["parked"], 1)
        self.assertEqual(row["transient_failures"], 1)
        self.assertEqual(row["pending_left"], 3)

    def test_rows_persist_across_reopen(self) -> None:
        self.log.append(report("2026-08-22T10:00:00Z"))
        self.log.close()
        reopened = SqliteCycleLog(self.path)
        self.addCleanup(reopened.close)
        self.assertEqual(len(reopened.recent(limit=5)), 1)


if __name__ == "__main__":
    unittest.main()
