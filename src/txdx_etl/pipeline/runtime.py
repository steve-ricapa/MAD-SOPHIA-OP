from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from txdx_etl.connectors.uptime_kuma.client import MetricsClientError
from txdx_etl.connectors.uptime_kuma.detector import ChangeDetector
from txdx_etl.connectors.uptime_kuma.parser import SOURCE_TYPE, parse_metrics
from txdx_etl.pipeline.envelope import build_envelope
from txdx_etl.pipeline.outbox import SqliteOutbox

DEFAULT_RETRY_INITIAL_SECONDS = 15
DEFAULT_RETRY_MAX_SECONDS = 60


class DeliveryError(Exception):
    pass


class TransientDeliveryError(DeliveryError):
    pass


class PermanentDeliveryError(DeliveryError):
    pass


def _parse(moment: str) -> datetime:
    return datetime.fromisoformat(moment.replace("Z", "+00:00"))


def _seconds_between(start: str, end: str) -> int:
    return int((_parse(end) - _parse(start)).total_seconds())


def _shift(moment: str, seconds: int) -> str:
    return (
        (_parse(moment) + timedelta(seconds=seconds))
        .astimezone(timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


Sink = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class DrainReport:
    attempted: int
    delivered: int
    parked: int
    transient_failures: int
    skipped_by_backoff: bool
    paused_remaining_seconds: int | None
    next_retry_wait_seconds: int | None
    pending_left: int


class OutboxSender:
    def __init__(
        self,
        outbox: SqliteOutbox,
        *,
        deliver: Sink,
        initial_backoff_seconds: int = DEFAULT_RETRY_INITIAL_SECONDS,
        max_backoff_seconds: int = DEFAULT_RETRY_MAX_SECONDS,
    ) -> None:
        if initial_backoff_seconds < 1:
            raise ValueError("initial_backoff_seconds must be at least 1")
        if max_backoff_seconds < initial_backoff_seconds:
            raise ValueError("max_backoff_seconds must be >= initial_backoff_seconds")
        self._outbox = outbox
        self._deliver = deliver
        self._initial_backoff = initial_backoff_seconds
        self._max_backoff = max_backoff_seconds
        self._backoff = initial_backoff_seconds
        self._blocked_until: str | None = None

    @property
    def blocked_for_seconds(self) -> int | None:
        if self._blocked_until is None:
            return None
        return self._backoff

    def _drain_locked(self, now: str) -> DrainReport:
        batch = self._outbox.pending_batch()
        attempted = 0
        delivered = 0
        parked = 0
        transient_failures = 0
        next_retry_wait: int | None = None
        for item in batch:
            delivery_id = item["delivery_id"]
            try:
                self._deliver(item["envelope"])
            except PermanentDeliveryError as exc:
                self._outbox.park(delivery_id, reason=str(exc), at=now)
                attempted += 1
                parked += 1
                continue
            except DeliveryError as exc:
                self._outbox.mark_attempt_failed(
                    delivery_id, error=str(exc), attempted_at=now
                )
                attempted += 1
                transient_failures += 1
                next_retry_wait = self._backoff
                self._blocked_until = _shift(now, self._backoff)
                self._backoff = min(self._backoff * 2, self._max_backoff)
                break
            self._outbox.mark_delivered(delivery_id, delivered_at=now)
            attempted += 1
            delivered += 1
            self._reset_backoff()
        return DrainReport(
            attempted=attempted,
            delivered=delivered,
            parked=parked,
            transient_failures=transient_failures,
            skipped_by_backoff=False,
            paused_remaining_seconds=None,
            next_retry_wait_seconds=next_retry_wait,
            pending_left=self._outbox.counts()["pending"],
        )

    def _reset_backoff(self) -> None:
        self._backoff = self._initial_backoff
        self._blocked_until = None

    def drain(self, *, now: str) -> DrainReport:
        if (
            self._blocked_until is not None
            and _seconds_between(now, self._blocked_until) > 0
        ):
            remaining = _seconds_between(now, self._blocked_until)
            return DrainReport(
                attempted=0,
                delivered=0,
                parked=0,
                transient_failures=0,
                skipped_by_backoff=True,
                paused_remaining_seconds=remaining,
                next_retry_wait_seconds=None,
                pending_left=self._outbox.counts()["pending"],
            )
        self._blocked_until = None
        return self._drain_locked(now)


@dataclass(frozen=True)
class CycleReport:
    observed_at: str
    scrape_ok: bool
    scrape_error: str | None
    records_detected: int
    records_enqueued: int
    drain: DrainReport


class PipelineRuntime:
    def __init__(
        self,
        *,
        tenant_id: str,
        instance_id: str,
        client,
        detector: ChangeDetector,
        outbox: SqliteOutbox,
        sink: Sink,
        display_name: str = "Uptime Kuma",
        sender_initial_backoff_seconds: int = DEFAULT_RETRY_INITIAL_SECONDS,
        sender_max_backoff_seconds: int = DEFAULT_RETRY_MAX_SECONDS,
        cycle_log=None,
    ) -> None:
        self._tenant_id = tenant_id
        self._instance_id = instance_id
        self._client = client
        self._detector = detector
        self._outbox = outbox
        self._sender = OutboxSender(
            outbox,
            deliver=sink,
            initial_backoff_seconds=sender_initial_backoff_seconds,
            max_backoff_seconds=sender_max_backoff_seconds,
        )
        self._display_name = display_name
        self._cycle_log = cycle_log

    @property
    def detector(self) -> ChangeDetector:
        return self._detector

    def run_cycle(self, *, observed_at: str) -> CycleReport:
        records_detected = 0
        records_enqueued = 0
        scrape_ok = True
        scrape_error: str | None = None
        try:
            fetch_result = self._client.fetch_metrics()
        except MetricsClientError as exc:
            scrape_ok = False
            scrape_error = type(exc).__name__
        else:
            snapshot = parse_metrics(fetch_result.text)
            if len(snapshot.monitors) == 0 and self._detector.tracked_count > 0:
                scrape_ok = False
                scrape_error = "empty_snapshot_while_tracking"
            else:
                cycle = self._detector.process(snapshot, observed_at)
                records_detected = len(cycle.records)
                fresh = self._outbox.filter_new(cycle.records)
                if fresh:
                    referenced_ids = {record["asset_id"] for record in fresh}
                    assets = [
                        asset
                        for asset in cycle.assets
                        if asset["asset_id"] in referenced_ids
                    ]
                    envelope = build_envelope(
                        tenant_id=self._tenant_id,
                        source_type=SOURCE_TYPE,
                        instance_id=self._instance_id,
                        display_name=self._display_name,
                        generated_at=observed_at,
                        run_id=f"run:{uuid.uuid4().hex}",
                        run_status="completed",
                        started_at=observed_at,
                        ended_at=observed_at,
                        collection_window_start=observed_at,
                        collection_window_end=observed_at,
                        assets=assets,
                        records=fresh,
                    )
                    self._outbox.enqueue(envelope, created_at=observed_at)
                    records_enqueued = len(fresh)
        drain = self._sender.drain(now=observed_at)
        report = CycleReport(
            observed_at=observed_at,
            scrape_ok=scrape_ok,
            scrape_error=scrape_error,
            records_detected=records_detected,
            records_enqueued=records_enqueued,
            drain=drain,
        )
        if self._cycle_log is not None:
            self._cycle_log.append(report)
        return report


__all__ = [
    "DEFAULT_RETRY_INITIAL_SECONDS",
    "DEFAULT_RETRY_MAX_SECONDS",
    "CycleReport",
    "DrainReport",
    "DeliveryError",
    "OutboxSender",
    "PermanentDeliveryError",
    "PipelineRuntime",
    "TransientDeliveryError",
]
