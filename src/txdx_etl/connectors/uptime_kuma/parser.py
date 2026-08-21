from __future__ import annotations

import re
from dataclasses import dataclass, field

SOURCE_TYPE = "uptime_kuma"

STATUS_MAP = {0: "down", 1: "up", 2: "pending", 3: "maintenance"}

KNOWN_FAMILIES = frozenset(
    {
        "monitor_status",
        "monitor_response_time",
        "monitor_uptime_ratio",
        "monitor_response_time_seconds",
        "monitor_cert_days_remaining",
        "monitor_cert_is_valid",
    }
)

_AGGREGATED_FAMILIES = frozenset(
    {
        "monitor_uptime_ratio",
        "monitor_response_time_seconds",
    }
)

_DERIVED_FIELDS = (
    "monitor_type",
    "monitor_hostname",
    "monitor_port",
    "monitor_url",
    "monitor_name",
)

_LINE_RE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)"
    r"(?:\{(?P<labels>.*)\})?"
    r"\s+(?P<value>[+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\s*$"
)
_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"')
_ESCAPE_RE = re.compile(r"\\(.)")
_ESCAPES = {"n": "\n", '"': '"', "\\": "\\"}


class ParseError(ValueError):
    pass


@dataclass
class MonitorSample:
    source_asset_id: str
    identity_quality: str
    labels: dict[str, str]
    status: int | None = None
    response_time_ms: float | None = None
    cert_days_remaining: float | None = None
    cert_is_valid: int | None = None
    uptime_ratio: dict[str, float] = field(default_factory=dict)
    response_time_seconds_avg: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class Capabilities:
    has_monitor_id: bool
    families: tuple[str, ...]
    windows: tuple[str, ...]
    monitor_count: int
    series_count: int


@dataclass(frozen=True)
class MetricsSnapshot:
    monitors: list[MonitorSample]
    capabilities: Capabilities


def _unescape(value: str) -> str:
    return _ESCAPE_RE.sub(
        lambda match: _ESCAPES.get(match.group(1), match.group(1)), value
    )


def _normalize(value: str) -> str:
    return "" if value == "null" else value


def _parse_labels(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    return {
        name: _normalize(_unescape(value))
        for name, value in _LABEL_RE.findall(raw)
    }


def _identity(labels: dict[str, str]) -> tuple[str, str]:
    monitor_id = labels.get("monitor_id", "").strip()
    if monitor_id != "":
        return monitor_id, "native"
    derived = "|".join(labels.get(name, "") for name in _DERIVED_FIELDS)
    return derived, "derived"


def parse_metrics(text: str) -> MetricsSnapshot:
    grouped: dict[str, MonitorSample] = {}
    families: set[str] = set()
    windows: set[str] = set()
    has_monitor_id = False
    series_count = 0

    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped == "" or stripped.startswith("#"):
            continue
        match = _LINE_RE.match(stripped)
        if match is None:
            raise ParseError(f"line {line_no}: malformed exposition syntax")
        name = match.group("name")
        if not name.startswith("monitor_"):
            continue
        labels = _parse_labels(match.group("labels"))
        value = float(match.group("value"))
        key, quality = _identity(labels)
        sample = grouped.get(key)
        if sample is None:
            sample = MonitorSample(
                source_asset_id=key,
                identity_quality=quality,
                labels=dict(labels),
            )
            grouped[key] = sample
        else:
            for name_, value_ in labels.items():
                if name_ != "window" and sample.labels.get(name_, "") == "":
                    sample.labels[name_] = value_
        if labels.get("monitor_id", "") != "":
            has_monitor_id = True
        window = labels.get("window", "")
        if name in _AGGREGATED_FAMILIES and window == "":
            raise ParseError(
                f"line {line_no}: {name} requires a non-empty window label"
            )
        if window != "":
            windows.add(window)
        families.add(name)
        series_count += 1

        if name == "monitor_status":
            status = int(value)
            if status not in STATUS_MAP:
                raise ParseError(
                    f"line {line_no}: unknown monitor_status value {status}"
                )
            sample.status = status
        elif name == "monitor_response_time":
            sample.response_time_ms = value
        elif name == "monitor_cert_days_remaining":
            sample.cert_days_remaining = value
        elif name == "monitor_cert_is_valid":
            sample.cert_is_valid = int(value)
        elif name == "monitor_uptime_ratio":
            sample.uptime_ratio[window] = value
        elif name == "monitor_response_time_seconds":
            sample.response_time_seconds_avg[window] = value

    unknown = sorted(families - KNOWN_FAMILIES)
    if unknown:
        raise ParseError(f"unknown monitor metric families: {', '.join(unknown)}")

    monitors = sorted(
        grouped.values(),
        key=lambda item: (item.identity_quality, item.source_asset_id),
    )
    capabilities = Capabilities(
        has_monitor_id=has_monitor_id,
        families=tuple(sorted(families)),
        windows=tuple(sorted(windows)),
        monitor_count=len(monitors),
        series_count=series_count,
    )
    return MetricsSnapshot(monitors=monitors, capabilities=capabilities)


__all__ = [
    "Capabilities",
    "KNOWN_FAMILIES",
    "MetricsSnapshot",
    "MonitorSample",
    "ParseError",
    "SOURCE_TYPE",
    "STATUS_MAP",
    "parse_metrics",
]
