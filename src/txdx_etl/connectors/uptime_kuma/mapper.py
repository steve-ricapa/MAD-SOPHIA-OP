from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from txdx_etl.connectors.uptime_kuma.parser import (
    SOURCE_TYPE,
    STATUS_MAP,
    MonitorSample,
)
from txdx_etl.domain import identity


@dataclass(frozen=True)
class MappingContext:
    tenant_id: str
    instance_id: str
    observed_at: str
    connector_version: str = "0.1.0"
    mapping_version: str = "1.0.0"
    policy_version: str = "1.0.0"
    bucket_seconds: int = 300


def bucket(observed_at: str, seconds: int) -> str:
    moment = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    floored = int(moment.timestamp()) // seconds * seconds
    return datetime.fromtimestamp(floored, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _provenance(ctx: MappingContext, sanitized_raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "connector_version": ctx.connector_version,
        "mapping_version": ctx.mapping_version,
        "policy_version": ctx.policy_version,
        "collected_at": ctx.observed_at,
        "raw_record_hash": identity.raw_record_hash(sanitized_raw),
    }


def _decision(ctx: MappingContext, reason_code: str) -> dict[str, Any]:
    return {
        "outcome": "accepted",
        "reason_code": reason_code,
        "policy_version": ctx.policy_version,
        "decided_at": ctx.observed_at,
    }


def _endpoint(labels: dict[str, str]) -> dict[str, Any]:
    endpoint: dict[str, Any] = {}
    hostname = labels.get("monitor_hostname", "")
    url = labels.get("monitor_url", "")
    port_raw = labels.get("monitor_port", "")
    if hostname != "":
        endpoint["hostname"] = hostname
    if url != "":
        endpoint["url"] = url
    if port_raw.isdigit():
        endpoint["port"] = int(port_raw)
    scheme = urlparse(url).scheme.lower() if url != "" else ""
    if scheme != "":
        endpoint["protocol"] = scheme
    return endpoint


def _discriminators(
    ctx: MappingContext,
    kind: str,
    previous_status: str | None,
    current_status: str,
) -> dict[str, str]:
    if kind == "change":
        if previous_status is None or previous_status == "":
            raise ValueError("change observation requires previous_status")
        return {
            "current_status": current_status,
            "event_time": ctx.observed_at,
            "previous_status": previous_status,
        }
    return {
        "bucket": bucket(ctx.observed_at, ctx.bucket_seconds),
        "current_status": current_status,
    }


def _asset_id(sample: MonitorSample, ctx: MappingContext) -> str:
    return identity.asset_id(
        ctx.tenant_id, SOURCE_TYPE, ctx.instance_id, sample.source_asset_id
    )


def _base_record(
    sample: MonitorSample,
    ctx: MappingContext,
    record_type: str,
    observation_type: str,
    kind: str,
) -> dict[str, Any]:
    return {
        "record_type": record_type,
        "record_id": "",
        "asset_id": _asset_id(sample, ctx),
        "source_object_id": sample.source_asset_id,
        "observation_type": observation_type,
        "kind": kind,
        "observed_at": ctx.observed_at,
    }


def map_monitor(
    sample: MonitorSample,
    ctx: MappingContext,
    *,
    kind: str = "initial",
    previous_status: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    asset = _build_asset(sample, ctx)
    observations = [
        _availability_observation(sample, ctx, kind, previous_status)
    ]
    certificate = _certificate_observation(sample, ctx, kind)
    if certificate is not None:
        observations.append(certificate)
    return asset, observations


def _build_asset(sample: MonitorSample, ctx: MappingContext) -> dict[str, Any]:
    return _new_asset(
        sample.source_asset_id,
        sample.identity_quality,
        ctx.observed_at,
        ctx.observed_at,
        ctx,
        sample.labels,
    )


def _new_asset(
    source_asset_id: str,
    identity_quality: str,
    first_seen_at: str,
    last_seen_at: str,
    ctx: MappingContext,
    labels: dict[str, str],
) -> dict[str, Any]:
    asset: dict[str, Any] = {
        "asset_id": identity.asset_id(
            ctx.tenant_id, SOURCE_TYPE, ctx.instance_id, source_asset_id
        ),
        "source_asset_id": source_asset_id,
        "identity_quality": identity_quality,
        "first_observed_at": first_seen_at,
        "last_observed_at": last_seen_at,
        "endpoints": [],
        "attributes": {},
        "provenance": _provenance(ctx, {"labels": labels}),
    }
    display_name = labels.get("monitor_name", "")
    if display_name != "":
        asset["display_name"] = display_name
    hostname = labels.get("monitor_hostname", "")
    if hostname != "":
        asset["hostname"] = hostname
    url = labels.get("monitor_url", "")
    if url != "":
        asset["url"] = url
    endpoint = _endpoint(labels)
    if endpoint:
        asset["endpoints"].append(endpoint)
    monitor_type = labels.get("monitor_type", "")
    if monitor_type != "":
        asset["attributes"]["monitor_type"] = monitor_type
    if not asset["attributes"]:
        del asset["attributes"]
    if not asset["endpoints"]:
        del asset["endpoints"]
    return asset


def map_disappearance(
    *,
    source_asset_id: str,
    identity_quality: str,
    labels: dict[str, str],
    previous_status: str | None,
    first_seen_at: str,
    last_seen_at: str,
    ctx: MappingContext,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    probe = MonitorSample(
        source_asset_id=source_asset_id,
        identity_quality=identity_quality,
        labels=dict(labels),
    )
    asset = _new_asset(
        source_asset_id, identity_quality, first_seen_at, last_seen_at, ctx, probe.labels
    )
    discriminators = {
        "bucket": bucket(ctx.observed_at, ctx.bucket_seconds),
        "current_status": "absent",
    }
    record = _base_record(probe, ctx, "observation", "availability", "disappeared")
    record["status"] = "absent"
    record["record_id"] = identity.record_id(
        ctx.tenant_id,
        SOURCE_TYPE,
        ctx.instance_id,
        "observation",
        source_asset_id,
        discriminators,
    )
    if previous_status:
        record["previous_status"] = previous_status
    target = _endpoint(probe.labels)
    if target:
        record["target"] = target
    record["decision"] = _decision(ctx, f"{SOURCE_TYPE}.availability.disappeared")
    record["provenance"] = _provenance(
        ctx,
        {"labels": probe.labels, "series": "monitor_status", "event": "disappeared"},
    )
    return asset, [record]


def _availability_observation(
    sample: MonitorSample,
    ctx: MappingContext,
    kind: str,
    previous_status: str | None,
) -> dict[str, Any]:
    if sample.status is None:
        raise ValueError("monitor sample lacks a monitor_status series")
    current_status = STATUS_MAP[sample.status]
    discriminators = _discriminators(ctx, kind, previous_status, current_status)
    record = _base_record(
        sample, ctx, "observation", "availability", kind
    )
    record["status"] = current_status
    record["record_id"] = identity.record_id(
        ctx.tenant_id,
        SOURCE_TYPE,
        ctx.instance_id,
        "observation",
        sample.source_asset_id,
        discriminators,
    )
    if kind == "change":
        record["previous_status"] = discriminators["previous_status"]

    measurements: list[dict[str, Any]] = []
    response_time = sample.response_time_ms
    if response_time is not None and response_time >= 0:
        measurements.append(
            {"name": "response_time", "value": response_time, "unit": "ms"}
        )
    for window, value in sorted(sample.uptime_ratio.items()):
        measurements.append(
            {"name": "uptime_ratio", "value": value, "unit": "ratio", "window": window}
        )
    for window, value in sorted(sample.response_time_seconds_avg.items()):
        measurements.append(
            {
                "name": "response_time_avg",
                "value": value,
                "unit": "s",
                "window": window,
            }
        )
    if measurements:
        record["measurements"] = measurements

    target = _endpoint(sample.labels)
    if target:
        record["target"] = target

    record["decision"] = _decision(ctx, f"{SOURCE_TYPE}.availability.{kind}")
    record["provenance"] = _provenance(
        ctx,
        {"labels": sample.labels, "series": "monitor_status"},
    )
    return record


def _certificate_observation(
    sample: MonitorSample,
    ctx: MappingContext,
    kind: str,
) -> dict[str, Any] | None:
    if sample.cert_is_valid is None:
        return None
    current_status = "valid" if sample.cert_is_valid == 1 else "invalid"
    if kind == "change":
        discriminators = {
            "current_status": current_status,
            "event_time": ctx.observed_at,
        }
    else:
        discriminators = {
            "bucket": bucket(ctx.observed_at, ctx.bucket_seconds),
            "current_status": current_status,
        }
    record = _base_record(sample, ctx, "observation", "certificate", kind)
    record["status"] = current_status
    record["record_id"] = identity.record_id(
        ctx.tenant_id,
        SOURCE_TYPE,
        ctx.instance_id,
        "observation",
        sample.source_asset_id,
        discriminators,
    )

    measurements: list[dict[str, Any]] = []
    days = sample.cert_days_remaining
    if days is not None and days >= 0:
        measurements.append({"name": "cert_days_remaining", "value": days, "unit": "d"})
    if measurements:
        record["measurements"] = measurements

    record["decision"] = _decision(ctx, f"{SOURCE_TYPE}.certificate.{kind}")
    record["provenance"] = _provenance(
        ctx,
        {"labels": sample.labels, "series": "monitor_cert_is_valid"},
    )
    return record


__all__ = [
    "MappingContext",
    "SOURCE_TYPE",
    "bucket",
    "map_disappearance",
    "map_monitor",
]
