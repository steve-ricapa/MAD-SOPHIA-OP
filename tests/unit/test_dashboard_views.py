from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from dashboard import views
from txdx_etl.connectors.uptime_kuma.detector import ChangeDetector
from txdx_etl.connectors.uptime_kuma.parser import parse_metrics
from txdx_etl.connectors.uptime_kuma.state_store import SqliteStateStore
from txdx_etl.pipeline.cycle_log import SqliteCycleLog
from txdx_etl.pipeline.outbox import SqliteOutbox

T0 = "2026-08-22T10:00:00Z"

WEB_TEXT = (
    'monitor_status{monitor_name="web",monitor_type="http",monitor_url="null",'
    'monitor_hostname="null",monitor_port="null"} 1\n'
)


class DashboardViewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "spool.db")

    def seed_full_database(self) -> None:
        state = SqliteStateStore(self.db)
        detector = ChangeDetector(
            tenant_id="1", instance_id="kuma-lab", state_store=state
        )
        cycle = detector.process(parse_metrics(WEB_TEXT), T0)
        state.close()

        outbox = SqliteOutbox(self.db)
        outbox.enqueue(
            {
                "delivery_id": "did-1",
                "assets": cycle.assets,
                "records": cycle.records,
            },
            created_at=T0,
        )
        outbox.mark_delivered("did-1", delivered_at=T0)
        outbox.close()
        return cycle

    def test_missing_database_returns_empty_defaults(self) -> None:
        data = views.overview(str(Path(self.tmp.name) / "nope.db"))
        self.assertEqual(data["counts"], {"pending": 0, "delivered": 0, "failed": 0})
        self.assertEqual(data["tracked_monitors"], [])
        self.assertEqual(data["cycles"], [])
        self.assertEqual(data["events"], [])
        self.assertIsNone(data["latest_cycle"])
        self.assertEqual(data["detector_cycles"], 0)

    def test_overview_exposes_monitors_counts_cycles_and_events(self) -> None:
        cycle = self.seed_full_database()

        log = SqliteCycleLog(self.db)
        log.append(
            SimpleNamespace(
                observed_at=T0,
                scrape_ok=True,
                scrape_error=None,
                records_detected=1,
                records_enqueued=1,
                drain=SimpleNamespace(
                    attempted=1,
                    delivered=1,
                    parked=0,
                    transient_failures=0,
                    skipped_by_backoff=False,
                    pending_left=0,
                ),
            )
        )
        log.close()

        data = views.overview(self.db)
        self.assertEqual(data["counts"], {"pending": 0, "delivered": 1, "failed": 0})
        self.assertEqual(data["detector_cycles"], 1)
        self.assertEqual(len(data["tracked_monitors"]), 1)
        monitor = data["tracked_monitors"][0]
        self.assertEqual(monitor["monitor_name"], "web")
        self.assertEqual(monitor["canonical_status"], "up")
        self.assertEqual(len(data["cycles"]), 1)
        self.assertTrue(data["latest_cycle"]["scrape_ok"])

        events = data["events"]
        self.assertEqual(len(events), len(cycle.records))
        kinds = {event["observation_type"] for event in events}
        self.assertIn("availability", kinds)
        for event in events:
            self.assertEqual(event["delivery_status"], "delivered")

    def test_recent_events_sorted_newest_first_and_capped(self) -> None:
        self.seed_full_database()
        events = views.recent_events(self.db)
        observed = [event["observed_at"] for event in events]
        self.assertEqual(observed, sorted(observed, reverse=True))


if __name__ == "__main__":
    unittest.main()
