from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from txdx_etl.pipeline.outbox import SqliteOutbox

T = "2026-08-22T10:00:00Z"


def rid(seed: str) -> str:
    return f"record:sha256:{seed.zfill(64)}"


def did(seed: str) -> str:
    return f"delivery:sha256:{seed.zfill(64)}"


def envelope(delivery_id: str, seeds: list[str]) -> dict:
    return {
        "delivery_id": delivery_id,
        "records": [{"record_id": rid(seed)} for seed in seeds],
    }


class OutboxLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self._tmp.name) / "spool.db")
        self.addCleanup(self._tmp.cleanup)

    def open_outbox(self) -> SqliteOutbox:
        box = SqliteOutbox(self.path)
        self.addCleanup(box.close)
        return box

    def test_enqueue_then_pending_batch_roundtrips_envelope(self) -> None:
        box = self.open_outbox()
        payload = envelope(did("aa"), ["11", "22"])
        box.enqueue(payload, created_at=T)
        batch = box.pending_batch()
        self.assertEqual(len(batch), 1)
        self.assertEqual(batch[0]["delivery_id"], did("aa"))
        self.assertEqual(batch[0]["attempts"], 0)
        self.assertEqual(batch[0]["envelope"], payload)

    def test_duplicate_enqueue_is_idempotent(self) -> None:
        box = self.open_outbox()
        payload = envelope(did("bb"), ["33"])
        box.enqueue(payload, created_at=T)
        box.enqueue(payload, created_at="2026-08-22T10:05:00Z")
        self.assertEqual(len(box.pending_batch()), 1)

    def test_mark_delivered_populates_dedup_table(self) -> None:
        box = self.open_outbox()
        box.enqueue(envelope(did("cc"), ["44", "55"]), created_at=T)
        box.mark_delivered(did("cc"), delivered_at=T)
        self.assertEqual(box.pending_batch(), [])
        fresh = box.filter_new([{"record_id": rid(s)} for s in ("44", "55", "66")])
        self.assertEqual(
            [r["record_id"] for r in fresh], [rid("66")]
        )

    def test_filter_new_passes_unknown_records_before_delivery(self) -> None:
        box = self.open_outbox()
        records = [{"record_id": rid(s)} for s in ("77", "88")]
        self.assertEqual(len(box.filter_new(records)), 2)

    def test_mark_attempt_failed_keeps_pending_and_counts(self) -> None:
        box = self.open_outbox()
        box.enqueue(envelope(did("dd"), ["99"]), created_at=T)
        box.mark_attempt_failed(did("dd"), error="connection reset", attempted_at=T)
        batch = box.pending_batch()
        self.assertEqual(batch[0]["attempts"], 1)
        counts = box.counts()
        self.assertEqual(counts["pending"], 1)
        self.assertEqual(counts["delivered"], 0)

    def test_full_lifecycle_counts_and_persistence_across_reopen(self) -> None:
        first = self.open_outbox()
        first.enqueue(envelope(did("ee"), ["a1"]), created_at=T)
        first.enqueue(envelope(did("ff"), ["b2"]), created_at=T)
        first.mark_delivered(did("ee"), delivered_at=T)
        first.close()

        second = SqliteOutbox(self.path)
        self.addCleanup(second.close)
        self.assertEqual(
            second.counts(), {"pending": 1, "delivered": 1, "failed": 0}
        )
        batch = second.pending_batch()
        self.assertEqual(batch[0]["delivery_id"], did("ff"))
        second.mark_delivered(did("ff"), delivered_at=T)
        self.assertEqual(
            second.counts(), {"pending": 0, "delivered": 2, "failed": 0}
        )
        self.assertEqual(second.filter_new([{"record_id": rid("a1")}]), [])


if __name__ == "__main__":
    unittest.main()
