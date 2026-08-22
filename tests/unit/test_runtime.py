from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from txdx_etl.connectors.uptime_kuma.client import (
    AuthenticationError,
    FetchResult,
    TransientMetricsError,
)
from txdx_etl.connectors.uptime_kuma.detector import ChangeDetector
from txdx_etl.pipeline.outbox import SqliteOutbox
from txdx_etl.pipeline.runtime import (
    PermanentDeliveryError,
    PipelineRuntime,
    TransientDeliveryError,
)

T0 = "2026-08-22T10:00:00Z"


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


class FakeClient:
    def __init__(self, *outcomes) -> None:
        self._outcomes = list(outcomes)

    def fetch_metrics(self):
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def fetch(text: str) -> FetchResult:
    return FetchResult(
        text=text,
        status_code=200,
        content_type="text/plain; version=0.0.4; charset=utf-8",
        byte_size=len(text.encode("utf-8")),
        duration_ms=1,
    )


class FlakySink:
    def __init__(self, *behaviors) -> None:
        self._behaviors = list(behaviors)
        self.delivered: list[dict] = []

    def __call__(self, envelope: dict) -> None:
        if self._behaviors:
            behavior = self._behaviors.pop(0)
            if isinstance(behavior, Exception):
                raise behavior
        self.delivered.append(envelope)


class RuntimeHarness(unittest.TestCase):
    def make_runtime(self, client, sink, **detector_kwargs):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        outbox = SqliteOutbox(str(Path(tmp.name) / "spool.db"))
        self.addCleanup(outbox.close)
        detector = ChangeDetector(
            tenant_id="1", instance_id="kuma-lab", **detector_kwargs
        )
        runtime = PipelineRuntime(
            tenant_id="1",
            instance_id="kuma-lab",
            client=client,
            detector=detector,
            outbox=outbox,
            sink=sink,
        )
        return runtime, outbox


class HappyPathTests(RuntimeHarness):
    def test_cycle_detects_enqueues_and_delivers(self) -> None:
        sink = FlakySink()
        client = FakeClient(fetch(web_text() + db_text()))
        runtime, outbox = self.make_runtime(client, sink)
        report = runtime.run_cycle(observed_at=T0)
        self.assertTrue(report.scrape_ok)
        self.assertIsNone(report.scrape_error)
        self.assertEqual(report.records_detected, 2)
        self.assertEqual(report.records_enqueued, 2)
        self.assertEqual(report.drain.attempted, 1)
        self.assertEqual(report.drain.delivered, 1)
        self.assertEqual(len(sink.delivered), 1)
        self.assertEqual(len(sink.delivered[0]["records"]), 2)
        self.assertEqual(
            outbox.counts(), {"pending": 0, "delivered": 1, "failed": 0}
        )

    def test_quiet_cycle_sends_nothing_new(self) -> None:
        sink = FlakySink()
        client = FakeClient(fetch(web_text()), fetch(web_text()))
        runtime, _ = self.make_runtime(client, sink)
        first = runtime.run_cycle(observed_at=T0)
        second = runtime.run_cycle(observed_at="2026-08-22T10:00:30Z")
        self.assertEqual(first.records_detected, 1)
        self.assertEqual(second.records_detected, 0)
        self.assertEqual(second.records_enqueued, 0)
        self.assertEqual(second.drain.attempted, 0)
        self.assertEqual(len(sink.delivered), 1)


class SenderBackoffTests(RuntimeHarness):
    def test_transient_failure_pauses_then_recovers(self) -> None:
        sink = FlakySink(TransientDeliveryError("connection reset"))
        client = FakeClient(fetch(web_text()), fetch(web_text()), fetch(web_text()))
        runtime, outbox = self.make_runtime(client, sink)
        failed = runtime.run_cycle(observed_at=T0)
        self.assertEqual(failed.drain.transient_failures, 1)
        self.assertEqual(failed.drain.next_retry_wait_seconds, 15)
        self.assertEqual(failed.drain.pending_left, 1)
        batch = outbox.pending_batch()
        self.assertEqual(batch[0]["attempts"], 1)
        paused = runtime.run_cycle(observed_at="2026-08-22T10:00:10Z")
        self.assertTrue(paused.drain.skipped_by_backoff)
        self.assertEqual(paused.drain.paused_remaining_seconds, 5)
        recovered = runtime.run_cycle(observed_at="2026-08-22T10:00:15Z")
        self.assertEqual(recovered.drain.delivered, 1)
        self.assertEqual(recovered.drain.pending_left, 0)

    def test_backoff_doubles_until_cap(self) -> None:
        sink = FlakySink(
            TransientDeliveryError("down"),
            TransientDeliveryError("still down"),
            TransientDeliveryError("yet down"),
            TransientDeliveryError("again down"),
        )
        snapshots = [fetch(web_text()) for _ in range(5)]
        client = FakeClient(*snapshots)
        runtime, _ = self.make_runtime(client, sink)
        first = runtime.run_cycle(observed_at=T0)
        self.assertEqual(first.drain.next_retry_wait_seconds, 15)
        second = runtime.run_cycle(observed_at="2026-08-22T10:00:15Z")
        self.assertEqual(second.drain.next_retry_wait_seconds, 30)
        third = runtime.run_cycle(observed_at="2026-08-22T10:00:45Z")
        self.assertEqual(third.drain.next_retry_wait_seconds, 60)
        fourth = runtime.run_cycle(observed_at="2026-08-22T10:01:45Z")
        self.assertEqual(fourth.drain.next_retry_wait_seconds, 60)
        recovered = runtime.run_cycle(observed_at="2026-08-22T10:02:45Z")
        self.assertEqual(recovered.drain.delivered, 1)
        self.assertEqual(recovered.drain.pending_left, 0)

    def test_success_resets_backoff_to_initial(self) -> None:
        sink = FlakySink(
            TransientDeliveryError("blip"),
            "explicit-ok",
            TransientDeliveryError("blip again"),
        )
        client = FakeClient(*[fetch(web_text()) for _ in range(4)])
        runtime, outbox = self.make_runtime(
            client,
            sink,
            refresh_interval_seconds=60,
            bucket_seconds=60,
        )
        first = runtime.run_cycle(observed_at=T0)
        self.assertEqual(first.drain.next_retry_wait_seconds, 15)
        delivered = runtime.run_cycle(observed_at="2026-08-22T10:00:15Z")
        self.assertEqual(delivered.drain.delivered, 1)
        heartbeat = runtime.run_cycle(observed_at="2026-08-22T10:01:10Z")
        self.assertEqual(heartbeat.records_enqueued, 1)
        self.assertEqual(heartbeat.drain.next_retry_wait_seconds, 15)
        final = runtime.run_cycle(observed_at="2026-08-22T10:01:25Z")
        self.assertEqual(final.drain.delivered, 1)
        self.assertEqual(outbox.counts()["pending"], 0)


class PermanentFailureTests(RuntimeHarness):
    def test_poison_envelope_parks_but_drain_continues(self) -> None:
        sink = FlakySink(PermanentDeliveryError("contract rejected"))
        client = FakeClient(fetch(web_text()), fetch(db_text()))
        runtime, outbox = self.make_runtime(client, sink)
        first = runtime.run_cycle(observed_at=T0)
        self.assertEqual(first.drain.parked, 1)
        self.assertEqual(first.drain.delivered, 0)
        self.assertEqual(
            outbox.counts(), {"pending": 0, "delivered": 0, "failed": 1}
        )
        second = runtime.run_cycle(observed_at="2026-08-22T10:05:00Z")
        self.assertEqual(second.drain.parked, 0)
        self.assertEqual(second.drain.delivered, 1)
        self.assertEqual(outbox.counts()["pending"], 0)


class ScrapeFailureTests(RuntimeHarness):
    def test_auth_failure_reports_error_and_keeps_state(self) -> None:
        sink = FlakySink()
        client = FakeClient(
            fetch(web_text()),
            AuthenticationError("source rejected credentials"),
            fetch(web_text()),
        )
        runtime, outbox = self.make_runtime(client, sink)
        good = runtime.run_cycle(observed_at=T0)
        self.assertEqual(good.drain.delivered, 1)
        bad = runtime.run_cycle(observed_at="2026-08-22T10:01:00Z")
        self.assertFalse(bad.scrape_ok)
        self.assertEqual(bad.scrape_error, "AuthenticationError")
        self.assertEqual(bad.records_detected, 0)
        self.assertEqual(bad.drain.attempted, 0)
        steady = runtime.run_cycle(observed_at="2026-08-22T10:02:00Z")
        self.assertTrue(steady.scrape_ok)
        self.assertEqual(steady.records_detected, 0)
        self.assertEqual(runtime.detector.tracked_count, 1)
        self.assertEqual(outbox.counts()["delivered"], 1)

    def test_empty_snapshot_while_tracking_is_ignored(self) -> None:
        sink = FlakySink()
        client = FakeClient(
            fetch(web_text()),
            fetch(""),
            fetch(web_text()),
        )
        runtime, outbox = self.make_runtime(
            client, sink, disappear_after_scrapes=1
        )
        runtime.run_cycle(observed_at=T0)
        empty = runtime.run_cycle(observed_at="2026-08-22T10:01:00Z")
        self.assertFalse(empty.scrape_ok)
        self.assertEqual(empty.scrape_error, "empty_snapshot_while_tracking")
        self.assertEqual(empty.records_detected, 0)
        self.assertEqual(outbox.counts()["delivered"], 1)
        back = runtime.run_cycle(observed_at="2026-08-22T10:02:00Z")
        self.assertTrue(back.scrape_ok)
        self.assertEqual(back.records_detected, 0)
        self.assertEqual(runtime.detector.tracked_count, 1)
        self.assertEqual(runtime.detector.cycles, 2)

    def test_transient_scrape_failure_does_not_advance_detector(self) -> None:
        sink = FlakySink()
        client = FakeClient(
            fetch(web_text()),
            TransientMetricsError("transport failure"),
            fetch(web_text()),
        )
        runtime, _ = self.make_runtime(
            client, sink, disappear_after_scrapes=1
        )
        runtime.run_cycle(observed_at=T0)
        broken = runtime.run_cycle(observed_at="2026-08-22T10:01:00Z")
        self.assertFalse(broken.scrape_ok)
        self.assertEqual(broken.scrape_error, "TransientMetricsError")
        steady = runtime.run_cycle(observed_at="2026-08-22T10:02:00Z")
        self.assertTrue(steady.scrape_ok)
        self.assertEqual(steady.records_detected, 0)
        self.assertEqual(runtime.detector.tracked_count, 1)
        self.assertEqual(runtime.detector.cycles, 2)


if __name__ == "__main__":
    unittest.main()
