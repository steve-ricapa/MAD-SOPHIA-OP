from datetime import datetime, timezone
from typing import Any, Dict, Tuple

from snapshot import _monitor_sort_key

STATUS_META = {
    0: ("down", "critical", 9.5),
    1: ("up", "info", 0.0),
    2: ("pending", "medium", 5.0),
    3: ("maintenance", "low", 2.0),
}


def _status_label(status: int) -> str:
    return STATUS_META.get(status, ("unknown", "info", 0.0))[0]


def _severity_and_cvss(status: int) -> Tuple[str, float]:
    _, severity, cvss = STATUS_META.get(status, ("unknown", "info", 0.0))
    return severity, cvss


def summarize_counts(monitors: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    counts = {"up": 0, "down": 0, "pending": 0, "maintenance": 0, "unknown": 0}
    for monitor in monitors.values():
        label = _status_label(int(monitor.get("status", -1)))
        counts[label] = counts.get(label, 0) + 1
    return counts


def _monitor_host(monitor: Dict[str, Any]) -> str:
    return (
        monitor.get("hostname")
        or monitor.get("url")
        or monitor.get("name")
        or f"monitor-{monitor.get('id', 'unknown')}"
    )


def _monitor_port(monitor: Dict[str, Any]) -> str:
    port = str(monitor.get("port") or "").strip()
    if port and port.lower() not in {"null", "none", "nan"}:
        return port
    return "0"


def _to_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _normalize_heartbeat_rows(rows: list[Any]) -> list[Dict[str, Any]]:
    out: list[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        # Support both DB-native keys (msg/ping/time/duration)
        # and collector-normalized keys (message/ping_ms/checked_at/duration_seconds).
        message = row.get("msg") if row.get("msg") is not None else row.get("message")
        ping = row.get("ping") if row.get("ping") is not None else row.get("ping_ms")
        checked_at = row.get("time") if row.get("time") is not None else row.get("checked_at")
        duration = row.get("duration") if row.get("duration") is not None else row.get("duration_seconds")
        out.append(
            {
                "status": _to_int(row.get("status"), 0),
                "message": _to_str(message, ""),
                "ping_ms": _to_float(ping, 0.0),
                "checked_at": _to_str(checked_at, ""),
                "duration_seconds": _to_float(duration, 0.0),
                "retries": _to_int(row.get("retries"), 0),
            }
        )
    return out


def _compact_tls_info(tls_info: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(tls_info, dict):
        return {}

    cert_info = tls_info.get("certInfo", {}) if isinstance(tls_info.get("certInfo"), dict) else {}
    issuer = cert_info.get("issuer", {}) if isinstance(cert_info.get("issuer"), dict) else {}
    subject = cert_info.get("subject", {}) if isinstance(cert_info.get("subject"), dict) else {}
    clean = {
        "valid": tls_info.get("valid"),
        "hostname_match_monitor_url": tls_info.get("hostnameMatchMonitorUrl"),
        "valid_to": cert_info.get("validTo"),
        "days_remaining": cert_info.get("daysRemaining"),
        "subject_cn": subject.get("CN"),
        "issuer_cn": issuer.get("CN"),
        "issuer_o": issuer.get("O"),
        "fingerprint_sha256": cert_info.get("fingerprint256"),
    }
    return {k: v for k, v in clean.items() if v is not None}


def build_findings(
    monitors: Dict[str, Dict[str, Any]],
    previous_statuses: Dict[str, int],
    include_ongoing_non_up: bool = False,
    include_all_monitors: bool = False,
    include_extended_fields: bool = False,
) -> Dict[str, Any]:
    findings = []
    next_statuses: Dict[str, int] = {}
    scanned_at = datetime.now(timezone.utc).isoformat()

    for monitor_id, monitor in sorted(monitors.items(), key=lambda item: _monitor_sort_key(item[0])):
        status = int(monitor.get("status", -1))
        prev_status = previous_statuses.get(monitor_id)
        next_statuses[monitor_id] = status

        changed = prev_status is None or int(prev_status) != status
        include = include_all_monitors or changed or (include_ongoing_non_up and status != 1)
        if not include:
            continue

        severity, _ = _severity_and_cvss(status)
        current_label = _status_label(status)
        prev_label = _status_label(int(prev_status)) if prev_status is not None else "unknown"
        transition = f"{prev_label} -> {current_label}" if prev_status is not None else f"initial -> {current_label}"

        response_time = monitor.get("response_time_ms")
        uptime_1d = monitor.get("uptime_1d")
        uptime_30d = monitor.get("uptime_30d")
        uptime_365d = monitor.get("uptime_365d")
        cert_days = monitor.get("cert_days_remaining")
        cert_valid = monitor.get("cert_is_valid")
        db_data = monitor.get("db") if isinstance(monitor.get("db"), dict) else {}
        latest_heartbeat = db_data.get("latest_heartbeat", {}) if isinstance(db_data.get("latest_heartbeat"), dict) else {}
        monitor_config = db_data.get("monitor_config", {}) if isinstance(db_data.get("monitor_config"), dict) else {}
        stats_24h = db_data.get("stats_24h", {}) if isinstance(db_data.get("stats_24h"), dict) else {}
        stats_30d = db_data.get("stats_30d", {}) if isinstance(db_data.get("stats_30d"), dict) else {}
        tags = db_data.get("tags", []) if isinstance(db_data.get("tags"), list) else []
        recent_heartbeats = db_data.get("recent_heartbeats", []) if isinstance(db_data.get("recent_heartbeats"), list) else []

        description_parts = [f"Monitor state transition: {transition}"]
        if response_time is not None and float(response_time) >= 0:
            description_parts.append(f"response_time_ms={float(response_time):.1f}")
        if uptime_1d is not None:
            description_parts.append(f"uptime_1d={(float(uptime_1d) * 100):.2f}%")
        if uptime_30d is not None:
            description_parts.append(f"uptime_30d={(float(uptime_30d) * 100):.2f}%")
        if uptime_365d is not None:
            description_parts.append(f"uptime_365d={(float(uptime_365d) * 100):.2f}%")
        if cert_days is not None:
            description_parts.append(f"cert_days_remaining={float(cert_days):.1f}")
        if cert_valid is not None:
            description_parts.append(f"cert_valid={bool(cert_valid)}")
        if latest_heartbeat.get("msg"):
            description_parts.append(f"last_msg={latest_heartbeat.get('msg')}")

        monitor_meta = {
            "monitor_type": monitor.get("type"),
            "monitor_url": monitor.get("url"),
            "monitor_hostname": monitor.get("hostname"),
            "monitor_port": _monitor_port(monitor),
            "interval_seconds": _to_int(monitor_config.get("interval"), 0),
            "timeout_seconds": _to_float(monitor_config.get("timeout"), 0.0),
            "max_retries": _to_int(monitor_config.get("maxretries"), 0),
            "retry_interval_seconds": _to_int(monitor_config.get("retry_interval"), 0),
            "method": _to_str(monitor_config.get("method"), ""),
            "ignore_tls": _to_int(monitor_config.get("ignore_tls"), 0),
            "upside_down": _to_int(monitor_config.get("upside_down"), 0),
            "active": _to_int(monitor_config.get("active"), 0),
            "parent_monitor_id": _to_int(monitor_config.get("parent"), 0),
            "description": _to_str(monitor_config.get("description"), ""),
            "tags": tags,
            "latest_heartbeat": {
                "status": _to_int(latest_heartbeat.get("status"), 0),
                "message": _to_str(latest_heartbeat.get("msg"), ""),
                "ping_ms": _to_float(latest_heartbeat.get("ping"), 0.0),
                "checked_at": _to_str(latest_heartbeat.get("time"), ""),
                "duration_seconds": _to_float(latest_heartbeat.get("duration"), 0.0),
                "retries": _to_int(latest_heartbeat.get("retries"), 0),
            },
            "recent_heartbeats": _normalize_heartbeat_rows(recent_heartbeats),
            "cert": {
                "is_valid_metric": _to_int(cert_valid, 0),
                "days_remaining_metric": _to_float(cert_days, 0.0),
                "details": _compact_tls_info(
                    db_data.get("latest_tls_info", {}) if isinstance(db_data.get("latest_tls_info"), dict) else {}
                ),
            },
            "stats_24h": {
                "up": _to_int(stats_24h.get("up_24h"), 0),
                "down": _to_int(stats_24h.get("down_24h"), 0),
                "avg_ping": _to_float(stats_24h.get("avg_ping_24h"), 0.0),
                "min_ping": _to_float(stats_24h.get("min_ping_24h"), 0.0),
                "max_ping": _to_float(stats_24h.get("max_ping_24h"), 0.0),
            },
            "stats_30d": {
                "up": _to_int(stats_30d.get("up_30d"), 0),
                "down": _to_int(stats_30d.get("down_30d"), 0),
                "avg_ping": _to_float(stats_30d.get("avg_ping_30d"), 0.0),
            },
        }

        finding = {
            "name": f"Uptime Kuma monitor '{monitor.get('name', monitor_id)}' is {current_label.upper()}",
            "severity": severity,
            "event_kind": "availability_change",
            "status": "active" if current_label == "down" else "resolved" if prev_status is not None and current_label == "up" else "unknown",
            "host": _monitor_host(monitor),
            "host_id": str(monitor_id),
            "service_name": None,
            "monitor_name": monitor.get("name", monitor_id),
            "monitor_id": str(monitor_id),
            "port": _monitor_port(monitor),
            "protocol": monitor.get("type") or "uptime-monitor",
            "metric_name": "response_time_ms",
            "metric_value": str(response_time) if response_time is not None else None,
            "threshold_value": None,
            "started_at": scanned_at,
            "ended_at": None,
            "duration_seconds": None,
            "acknowledged": False,
            "maintenance": current_label == "maintenance",
            "description": " | ".join(description_parts),
            "solution": "Check monitor target and service health in Uptime Kuma.",
            "impact": "Service availability degradation or monitoring disruption.",
            "raw": monitor_meta if include_extended_fields else {},
        }
        findings.append(finding)

    return {"findings": findings, "current_statuses": next_statuses}


def build_report(
    *,
    scan_id: str,
    company_id: int,
    api_key: str,
    scanner_type: str,
    event_type: str,
    idempotency_key: str,
    monitors: Dict[str, Dict[str, Any]],
    findings: list[Dict[str, Any]],
    snapshot_signature: str,
    snapshot_mode: str,
    send_reason: str,
    snapshot_changed: bool,
    mad_version: str = "2.3.0",
    integration_version: str = "1.0.0",
    source: str = "mad-collector",
) -> Dict[str, Any]:
    scanned_at = datetime.now(timezone.utc).isoformat()
    counts = summarize_counts(monitors)
    cvss_max = 9.5 if counts.get("down", 0) > 0 else 5.0 if counts.get("pending", 0) > 0 else 2.0 if counts.get("maintenance", 0) > 0 else 0.0
    total_hosts = len(monitors)

    response_times = [
        float(m["response_time_ms"])
        for m in monitors.values()
        if m.get("response_time_ms") is not None and float(m["response_time_ms"]) >= 0
    ]
    response_times_30d = [
        float(m["response_time_seconds_30d"]) * 1000.0
        for m in monitors.values()
        if m.get("response_time_seconds_30d") is not None and float(m["response_time_seconds_30d"]) >= 0
    ]
    response_times_365d = [
        float(m["response_time_seconds_365d"]) * 1000.0
        for m in monitors.values()
        if m.get("response_time_seconds_365d") is not None and float(m["response_time_seconds_365d"]) >= 0
    ]
    uptime_samples = [
        float(m["uptime_1d"])
        for m in monitors.values()
        if m.get("uptime_1d") is not None
    ]
    uptime_samples_30d = [
        float(m["uptime_30d"])
        for m in monitors.values()
        if m.get("uptime_30d") is not None
    ]
    uptime_samples_365d = [
        float(m["uptime_365d"])
        for m in monitors.values()
        if m.get("uptime_365d") is not None
    ]
    cert_expiring_30d = sum(
        1
        for m in monitors.values()
        if m.get("cert_days_remaining") is not None and float(m["cert_days_remaining"]) <= 30
    )
    invalid_cert_count = sum(1 for m in monitors.values() if m.get("cert_is_valid") is False)
    down_monitors = [m.get("name") for m in monitors.values() if int(m.get("status", -1)) == 0]

    scan_summary = {
        "scan_id": scan_id,
        "scan_name": "Uptime Kuma Real-time Sync",
        "status": "completed",
        "scanned_at": scanned_at,
        "scanner_type": scanner_type,
        "summary_type": "availability",
        "target": "uptime-kuma-monitors",
        "total_hosts": total_hosts,
        "total_monitors": total_hosts,
        "total_services": 0,
        "total_events": counts.get("down", 0) + counts.get("pending", 0),
        "total_findings": len(findings),
        "cvss_max": cvss_max,
        "results": {
            "critical": counts.get("down", 0),
            "high": counts.get("pending", 0),
            "medium": counts.get("maintenance", 0),
            "low": counts.get("up", 0),
            "info": counts.get("unknown", 0),
        },
        "health": {
            "health_score": round((sum(uptime_samples) / len(uptime_samples) * 100) if uptime_samples else 0.0, 1),
            "health_label": "critical" if counts.get("down", 0) > 0 else "degraded" if counts.get("pending", 0) > 0 else "healthy",
            "availability_percentage": round((counts.get("up", 0) / max(total_hosts, 1)) * 100, 1),
            "avg_response_time_ms": (sum(response_times) / len(response_times)) if response_times else 0.0,
        },
        "availability": {
            "hosts_up": counts.get("up", 0),
            "hosts_down": counts.get("down", 0),
            "monitors_up": counts.get("up", 0),
            "monitors_down": counts.get("down", 0),
            "monitors_degraded": counts.get("pending", 0) + counts.get("maintenance", 0),
        },
        "performance": {
            "avg_response_time_ms_30d": (sum(response_times_30d) / len(response_times_30d)) if response_times_30d else 0.0,
            "avg_response_time_ms_365d": (sum(response_times_365d) / len(response_times_365d)) if response_times_365d else 0.0,
            "avg_uptime_ratio_1d": (sum(uptime_samples) / len(uptime_samples)) if uptime_samples else 0.0,
            "avg_uptime_ratio_30d": (sum(uptime_samples_30d) / len(uptime_samples_30d)) if uptime_samples_30d else 0.0,
            "avg_uptime_ratio_365d": (sum(uptime_samples_365d) / len(uptime_samples_365d)) if uptime_samples_365d else 0.0,
        },
        "certificates": {
            "ssl_expiring_soon": cert_expiring_30d,
            "ssl_invalid": invalid_cert_count,
            "ssl_expired": 0,
        },
        "meta": {
            "schema_version": "1.2",
            "mad_version": mad_version,
            "integration_version": integration_version,
            "source": source,
            "raw_source": "uptime_kuma",
            "snapshot_signature": snapshot_signature,
            "snapshot_mode": snapshot_mode,
            "snapshot_changed": bool(snapshot_changed),
            "send_reason": send_reason,
            "down_monitors": down_monitors,
            "collection_window_start": scanned_at,
            "collection_window_end": scanned_at,
        },
    }

    return {
        "scan_id": scan_id,
        "company_id": company_id,
        "api_key": api_key,
        "idempotency_key": idempotency_key,
        "scanned_at": scanned_at,
        "event_type": event_type,
        "scanner_type": scanner_type,
        "scan_summary": scan_summary,
        "findings": findings,
    }
