from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from txdx_etl.connectors.uptime_kuma import mapper
from txdx_etl.connectors.uptime_kuma.mapper import MappingContext
from txdx_etl.connectors.uptime_kuma.parser import STATUS_MAP, MetricsSnapshot

DEFAULT_DISAPPEAR_AFTER_SCRAPES = 3
DEFAULT_REFRESH_INTERVAL_SECONDS = 300


class DetectorStateStore(Protocol):
    def load(self) -> tuple[int, dict[str, "TrackedMonitor"]]: ...

    def save(
        self, *, cycles: int, monitors: dict[str, "TrackedMonitor"]
    ) -> None: ...


def _seconds_between(start: str, end: str) -> int:
    begin = datetime.fromisoformat(start.replace("Z", "+00:00"))
    finish = datetime.fromisoformat(end.replace("Z", "+00:00"))
    return int((finish - begin).total_seconds())


@dataclass(frozen=True)
class TrackedMonitor:
    source_asset_id: str
    identity_quality: str
    labels: dict[str, str]
    canonical_status: str
    first_seen_at: str
    last_seen_at: str
    last_emitted_at: str
    cert_is_valid: int | None
    missing_scrapes: int


@dataclass(frozen=True)
class CycleResult:
    assets: list[dict[str, Any]]
    records: list[dict[str, Any]]
    summary: dict[str, int]


class ChangeDetector:
    def __init__(
        self,
        *,
        tenant_id: str,
        instance_id: str,
        disappear_after_scrapes: int = DEFAULT_DISAPPEAR_AFTER_SCRAPES,
        refresh_interval_seconds: int = DEFAULT_REFRESH_INTERVAL_SECONDS,
        connector_version: str = "0.1.0",
        mapping_version: str = "1.0.0",
        policy_version: str = "1.0.0",
        bucket_seconds: int = 300,
        state_store: DetectorStateStore | None = None,
    ) -> None:
        if disappear_after_scrapes < 1:
            raise ValueError("disappear_after_scrapes must be at least 1")
        if refresh_interval_seconds < 0:
            raise ValueError("refresh_interval_seconds must not be negative")
        self._tenant_id = tenant_id
        self._instance_id = instance_id
        self._disappear_after = disappear_after_scrapes
        self._refresh_interval = refresh_interval_seconds
        self._connector_version = connector_version
        self._mapping_version = mapping_version
        self._policy_version = policy_version
        self._bucket_seconds = bucket_seconds
        self._tracked: dict[str, TrackedMonitor] = {}
        self._cycles = 0
        self._state_store = state_store
        if state_store is not None:
            self._cycles, self._tracked = state_store.load()

    @property
    def cycles(self) -> int:
        return self._cycles

    @property
    def tracked_count(self) -> int:
        return len(self._tracked)

    def _context(self, observed_at: str) -> MappingContext:
        return MappingContext(
            tenant_id=self._tenant_id,
            instance_id=self._instance_id,
            observed_at=observed_at,
            connector_version=self._connector_version,
            mapping_version=self._mapping_version,
            policy_version=self._policy_version,
            bucket_seconds=self._bucket_seconds,
        )

    def process(self, snapshot: MetricsSnapshot, observed_at: str) -> CycleResult:
        self._cycles += 1
        ctx = self._context(observed_at)
        assets: list[dict[str, Any]] = []
        records: list[dict[str, Any]] = []
        summary: dict[str, int] = {
            "initial": 0,
            "refresh": 0,
            "change": 0,
            "discovered": 0,
            "disappeared": 0,
        }
        seen: set[str] = set()
        for sample in snapshot.monitors:
            key = sample.source_asset_id
            seen.add(key)
            tracked = self._tracked.get(key)
            canonical_status = STATUS_MAP[sample.status]
            if tracked is None:
                kind = "initial" if self._cycles == 1 else "discovered"
                previous_status = None
                emit = True
            elif tracked.canonical_status != canonical_status:
                kind = "change"
                previous_status = tracked.canonical_status
                emit = True
            else:
                kind = "refresh"
                previous_status = None
                cert_changed = (
                    sample.cert_is_valid is not None
                    and sample.cert_is_valid != tracked.cert_is_valid
                )
                elapsed = _seconds_between(tracked.last_emitted_at, observed_at)
                emit = cert_changed or elapsed >= self._refresh_interval
            if not emit:
                self._tracked[key] = TrackedMonitor(
                    source_asset_id=key,
                    identity_quality=sample.identity_quality,
                    labels=dict(sample.labels),
                    canonical_status=canonical_status,
                    first_seen_at=tracked.first_seen_at,
                    last_seen_at=observed_at,
                    last_emitted_at=tracked.last_emitted_at,
                    cert_is_valid=sample.cert_is_valid,
                    missing_scrapes=0,
                )
                continue
            asset, observations = mapper.map_monitor(
                sample, ctx, kind=kind, previous_status=previous_status
            )
            assets.append(asset)
            records.extend(observations)
            summary[kind] += 1
            self._tracked[key] = TrackedMonitor(
                source_asset_id=key,
                identity_quality=sample.identity_quality,
                labels=dict(sample.labels),
                canonical_status=canonical_status,
                first_seen_at=tracked.first_seen_at if tracked else observed_at,
                last_seen_at=observed_at,
                last_emitted_at=observed_at,
                cert_is_valid=sample.cert_is_valid,
                missing_scrapes=0,
            )
        for key in sorted(set(self._tracked) - seen):
            tracked = self._tracked[key]
            missing = tracked.missing_scrapes + 1
            if missing >= self._disappear_after:
                asset, observations = mapper.map_disappearance(
                    source_asset_id=key,
                    identity_quality=tracked.identity_quality,
                    labels=dict(tracked.labels),
                    previous_status=tracked.canonical_status,
                    first_seen_at=tracked.first_seen_at,
                    last_seen_at=tracked.last_seen_at,
                    ctx=ctx,
                )
                assets.append(asset)
                records.extend(observations)
                summary["disappeared"] += 1
                del self._tracked[key]
            else:
                self._tracked[key] = TrackedMonitor(
                    source_asset_id=key,
                    identity_quality=tracked.identity_quality,
                    labels=dict(tracked.labels),
                    canonical_status=tracked.canonical_status,
                    first_seen_at=tracked.first_seen_at,
                    last_seen_at=tracked.last_seen_at,
                    last_emitted_at=tracked.last_emitted_at,
                    cert_is_valid=tracked.cert_is_valid,
                    missing_scrapes=missing,
                )
        if self._state_store is not None:
            self._state_store.save(cycles=self._cycles, monitors=self._tracked)
        return CycleResult(assets=assets, records=records, summary=summary)


__all__ = [
    "DEFAULT_DISAPPEAR_AFTER_SCRAPES",
    "DEFAULT_REFRESH_INTERVAL_SECONDS",
    "ChangeDetector",
    "CycleResult",
    "TrackedMonitor",
]
