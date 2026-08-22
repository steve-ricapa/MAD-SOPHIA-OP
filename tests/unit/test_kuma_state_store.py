from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from txdx_etl.connectors.uptime_kuma.detector import ChangeDetector, TrackedMonitor
from txdx_etl.connectors.uptime_kuma.parser import parse_metrics
from txdx_etl.connectors.uptime_kuma.state_store import SqliteStateStore

T0 = "2026-08-22T10:00:00Z"

EMPTY_SUMMARY = {
    "initial": 0,
    "refresh": 0,
    "change": 0,
    "discovered": 0,
    "disappeared": 0,
}


def labels_for(name: str, mtype: str = "http") -> str:
    return (
        f'monitor_name="{name}",monitor_type="{mtype}",monitor_url="null",'
        f'monitor_hostname="null",monitor_port="null"'
    )


def web_text(status: int = 1) -> str:
    lab = labels_for("web")
    return (
        f"monitor_status{{{lab}}} {status}\n"
        f"monitor_response_time{{{lab}}} 100\n"
    )


def db_text(status: int = 1) -> str:
    lab = labels_for("db", mtype="keyword")
    return (
        f"monitor_status{{{lab}}} {status}\n"
        f"monitor_response_time{{{lab}}} 40\n"
    )


def make_detector(store) -> ChangeDetector:
    return ChangeDetector(
        tenant_id="1", instance_id="kuma-lab", state_store=store
    )


class StateStoreRoundtripTests(unittest.TestCase):
    def test_save_then_load_preserves_monitors_and_cycles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteStateStore(str(Path(tmp) / "state.db"))
            monitors = {
                "m1": TrackedMonitor(
                    source_asset_id="m1",
                    identity_quality="derived",
                    labels={"monitor_name": "web"},
                    canonical_status="up",
                    first_seen_at=T0,
                    last_seen_at=T0,
                    last_emitted_at=T0,
                    cert_is_valid=1,
                    missing_scrapes=2,
                )
            }
            store.save(cycles=7, monitors=monitors)
            cycles, loaded = store.load()
            store.close()
            self.assertEqual(cycles, 7)
            self.assertEqual(loaded["m1"], monitors["m1"])

    def test_fresh_database_loads_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SqliteStateStore(str(Path(tmp) / "state.db"))
            cycles, monitors = store.load()
            store.close()
            self.assertEqual((cycles, monitors), (0, {}))


class DetectorRestartTests(unittest.TestCase):
    def test_restart_continues_instead_of_reinitializing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "state.db")

            first = SqliteStateStore(path)
            d1 = make_detector(first)
            cycle1 = d1.process(parse_metrics(web_text() + db_text()), T0)
            self.assertEqual(cycle1.summary, dict(EMPTY_SUMMARY, initial=2))
            first.close()

            second = SqliteStateStore(path)
            d2 = make_detector(second)
            restart = d2.process(parse_metrics(web_text(status=0)), "2026-08-22T10:01:00Z")
            second.close()
            self.assertEqual(restart.summary, dict(EMPTY_SUMMARY, change=1))
            record = restart.records[0]
            self.assertEqual(record["kind"], "change")
            self.assertEqual(record["previous_status"], "up")
            self.assertEqual(record["status"], "down")

    def test_new_monitor_after_restart_is_discovered_not_initial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "state.db")

            first = SqliteStateStore(path)
            make_detector(first).process(parse_metrics(web_text()), T0)
            first.close()

            second = SqliteStateStore(path)
            cycle = make_detector(second).process(
                parse_metrics(web_text() + db_text()), "2026-08-22T10:01:00Z"
            )
            second.close()
            self.assertEqual(
                cycle.summary, dict(EMPTY_SUMMARY, discovered=1)
            )

    def test_heartbeat_is_not_duplicated_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "state.db")

            first = SqliteStateStore(path)
            make_detector(first).process(parse_metrics(web_text()), T0)
            first.close()

            second = SqliteStateStore(path)
            quiet = make_detector(second).process(
                parse_metrics(web_text()), "2026-08-22T10:01:00Z"
            )
            second.close()
            self.assertEqual(quiet.records, [])
            self.assertEqual(quiet.summary, EMPTY_SUMMARY)


if __name__ == "__main__":
    unittest.main()
