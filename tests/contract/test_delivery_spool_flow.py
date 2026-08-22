from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from txdx_etl.connectors.uptime_kuma.detector import ChangeDetector
from txdx_etl.connectors.uptime_kuma.parser import SOURCE_TYPE, parse_metrics
from txdx_etl.connectors.uptime_kuma.state_store import SqliteStateStore
from txdx_etl.pipeline import validation
from txdx_etl.pipeline.envelope import build_envelope
from txdx_etl.pipeline.outbox import SqliteOutbox

import schema_utils

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "connectors" / "uptime_kuma"
OBSERVED_AT = "2026-08-22T12:00:00Z"


def load_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class DeliverySpoolFlowTests(unittest.TestCase):
    def test_cycle_flows_through_spool_and_survives_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "spool.db")

            state_first = SqliteStateStore(db)
            detector = ChangeDetector(
                tenant_id="1", instance_id="kuma-lab", state_store=state_first
            )
            cycle = detector.process(
                parse_metrics(load_text("metrics-real-1.23.17-anonymized.txt")),
                OBSERVED_AT,
            )
            state_first.close()

            outbox_first = SqliteOutbox(db)
            fresh_records = outbox_first.filter_new(cycle.records)
            self.assertEqual(len(fresh_records), len(cycle.records))
            envelope = build_envelope(
                tenant_id="1",
                source_type=SOURCE_TYPE,
                instance_id="kuma-lab",
                display_name="Uptime Kuma laboratorio",
                generated_at=OBSERVED_AT,
                run_id="run:test-spool-0000000001",
                run_status="completed",
                started_at=OBSERVED_AT,
                ended_at=OBSERVED_AT,
                collection_window_start=OBSERVED_AT,
                collection_window_end=OBSERVED_AT,
                assets=cycle.assets,
                records=fresh_records,
            )
            outbox_first.enqueue(envelope, created_at=OBSERVED_AT)
            outbox_first.close()

            outbox_reopened = SqliteOutbox(db)
            batch = outbox_reopened.pending_batch()
            self.assertEqual(len(batch), 1)
            recovered = batch[0]["envelope"]
            self.assertEqual(recovered["delivery_id"], envelope["delivery_id"])
            schemas = schema_utils.load_schemas()
            schema_utils.validator_for(schemas, "envelope.schema.json").validate(recovered)
            self.assertEqual(validation.validate_envelope(recovered), [])

            outbox_reopened.mark_delivered(recovered["delivery_id"], delivered_at=OBSERVED_AT)
            leftovers = outbox_reopened.filter_new(fresh_records)
            self.assertEqual(leftovers, [])
            self.assertEqual(
                outbox_reopened.counts(),
                {"pending": 0, "delivered": 1, "failed": 0},
            )
            outbox_reopened.close()

            state_second = SqliteStateStore(db)
            detector_two = ChangeDetector(
                tenant_id="1", instance_id="kuma-lab", state_store=state_second
            )
            quiet = detector_two.process(
                parse_metrics(load_text("metrics-real-1.23.17-anonymized.txt")),
                "2026-08-22T12:00:30Z",
            )
            state_second.close()
            self.assertEqual(quiet.records, [])
            self.assertEqual(quiet.summary["initial"], 0)


if __name__ == "__main__":
    unittest.main()
