from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SEVERITY_MAPPING = {
    5: "critical",
    4: "high",
    3: "medium",
    2: "low",
    1: "info",
    0: "info",
}

SEVERITY_CVSS = {
    5: 9.5,
    4: 8.0,
    3: 5.5,
    2: 2.5,
    1: 0.0,
    0: 0.0,
}


def _sev_label(sev_num: int) -> str:
    return SEVERITY_MAPPING.get(sev_num, "info")


def _sev_cvss(sev_num: int) -> float:
    return float(SEVERITY_CVSS.get(sev_num, 0.0))


def _health_label(counts: Dict[str, int]) -> str:
    if counts.get("critical", 0) > 0:
        return "critical"
    if counts.get("high", 0) > 0:
        return "high"
    if counts.get("medium", 0) > 0:
        return "degraded"
    return "healthy"


def summarize(
    scan_id: str,
    company_id: int,
    api_key: str,
    api_version: str,
    idempotency_key: str,
    problems: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    all_hosts: Optional[List[Dict[str, Any]]] = None,
    all_triggers: Optional[List[Dict[str, Any]]] = None,
    snapshot_signature: str = "",
    snapshot_mode: str = "delta_with_periodic_forced",
    send_reason: str = "no_change",
    snapshot_changed: bool = False,
    mad_version: str = "2.3.0",
    integration_version: str = "1.0.0",
    source: str = "mad-collector",
) -> tuple[Dict[str, Any], None]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings = []
    all_hosts = all_hosts or []
    all_triggers = all_triggers or []

    active_trigger_ids = {p.get("objectid") for p in problems}
    host_summary: dict[str, Any] = {}

    for t in all_triggers:
        hosts = t.get("hosts") or []
        host_name = hosts[0].get("name") if hosts else "Zabbix System"
        trigger_id = t.get("triggerid")
        is_active = trigger_id in active_trigger_ids

        tags = {tag.get("tag").lower(): tag.get("value") for tag in (t.get("tags") or [])}
        has_custom_info = any(k in tags for k in ["cve", "cvss", "solution", "impact"])

        if host_name not in host_summary:
            host_summary[host_name] = {
                "active_or_special": [],
                "healthy_count": 0,
                "ip": "N/A",
                "port": "0",
                "host_id": hosts[0].get("hostid", "") if hosts else "",
            }

        interfaces = t.get("interfaces") or []
        main_interface = next((i for i in interfaces if i.get("main") == "1"), interfaces[0]) if interfaces else {}
        host_summary[host_name]["ip"] = main_interface.get("ip", "N/A")
        host_summary[host_name]["port"] = main_interface.get("port", "0")

        if is_active or has_custom_info:
            host_summary[host_name]["active_or_special"].append(t)
        else:
            host_summary[host_name]["healthy_count"] += 1

    for host_name, data in host_summary.items():
        for t in data["active_or_special"]:
            trigger_id = t.get("triggerid")
            is_active = trigger_id in active_trigger_ids
            sev_num = int(t.get("priority", 0))
            sev_label = _sev_label(sev_num)

            if is_active:
                counts[sev_label] = counts.get(sev_label, 0) + 1

            tags = {tag.get("tag").lower(): tag.get("value") for tag in (t.get("tags") or [])}
            description = t.get("description", "").replace("{HOST.NAME}", host_name)

            findings.append({
                "name": description,
                "severity": sev_label,
                "event_kind": "problem" if is_active else "recovery",
                "status": "active" if is_active else "resolved",
                "host": f"{host_name} ({data['ip']})",
                "host_id": str(data.get("host_id", "")),
                "service_name": None,
                "monitor_name": None,
                "monitor_id": None,
                "port": tags.get("port", data["port"] if data["port"] != "0" else "161"),
                "protocol": tags.get("protocol", "snmp/agent"),
                "metric_name": t.get("expression", ""),
                "metric_value": "problem" if is_active else "ok",
                "threshold_value": None,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "ended_at": None,
                "duration_seconds": None,
                "acknowledged": False,
                "maintenance": False,
                "description": f"{'ALERTA ACTIVA' if is_active else 'ESTADO OK'}: {description}",
                "solution": tags.get("solution", "Accion requerida en consola Zabbix."),
                "impact": tags.get("impact", "Monitoreo activo o recurso afectado."),
                "raw": {
                    "triggerid": t.get("triggerid"),
                    "priority": sev_num,
                    "tags": t.get("tags") or [],
                },
            })

        displayed_ids = {t.get("triggerid") for t in data["active_or_special"]}
        trigger_by_sev = Counter([
            int(t.get("priority", 0)) for t in all_triggers
            if t.get("triggerid") not in displayed_ids
            and (t.get("hosts") or [{}])[0].get("name") == host_name
        ])

        for sev_num, count in trigger_by_sev.items():
            if count == 0:
                continue
            sev_label = _sev_label(sev_num)
            findings.append({
                "name": f"Rule Group ({sev_label}): {host_name}",
                "severity": sev_label,
                "event_kind": "health_summary",
                "status": "active",
                "host": f"{host_name} ({data['ip']})",
                "host_id": str(data.get("host_id", "")),
                "service_name": None,
                "monitor_name": None,
                "monitor_id": None,
                "port": data["port"] if data["port"] != "0" else "161",
                "protocol": "snmp/agent",
                "metric_name": "trigger_count",
                "metric_value": str(count),
                "threshold_value": None,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "ended_at": None,
                "duration_seconds": None,
                "acknowledged": False,
                "maintenance": False,
                "description": f"Monitoreando con exito {count} reglas de nivel {sev_label}.",
                "solution": "No se requiere accion, estado estable.",
                "impact": "Proteccion activa.",
                "raw": {"rule_count": count, "severity_num": sev_num},
            })

    scanned_at = datetime.now(timezone.utc).isoformat()
    cvss_max = 0.0
    if counts.get("critical", 0) > 0:
        cvss_max = _sev_cvss(5)
    elif counts.get("high", 0) > 0:
        cvss_max = _sev_cvss(4)
    elif counts.get("medium", 0) > 0:
        cvss_max = _sev_cvss(3)
    elif counts.get("low", 0) > 0:
        cvss_max = _sev_cvss(2)

    results = {
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
    }

    report = {
        "scan_id": scan_id,
        "company_id": int(company_id),
        "api_key": api_key,
        "idempotency_key": idempotency_key,
        "scanned_at": scanned_at,
        "event_type": "vuln_scan_report",
        "scanner_type": "zabbix",
        "scan_summary": {
            "scan_id": scan_id,
            "scan_name": f"Zabbix Real-time Sync (v{api_version})",
            "status": "completed",
            "scanned_at": scanned_at,
            "scanner_type": "zabbix",
            "summary_type": "noc_health",
            "target": "zabbix-monitoring",
            "total_hosts": len(all_hosts),
            "total_monitors": len(all_triggers),
            "total_services": 0,
            "total_events": len(problems),
            "total_findings": len(findings),
            "cvss_max": cvss_max,
            "results": results,
            "health": {
                "health_score": round(
                    100 - (counts.get("critical", 0) * 30 + counts.get("high", 0) * 15 + counts.get("medium", 0) * 5),
                    1,
                ),
                "health_label": _health_label(counts),
                "availability_percentage": round(
                    (len(all_hosts) - (counts.get("critical", 0) + counts.get("high", 0))) / max(len(all_hosts), 1) * 100,
                    1,
                ),
                "avg_response_time_ms": 0.0,
            },
            "availability": {
                "hosts_up": max(len(all_hosts) - (counts.get("critical", 0) + counts.get("high", 0)), 0),
                "hosts_down": min(counts.get("critical", 0) + counts.get("high", 0), len(all_hosts)),
            },
            "meta": {
                "schema_version": "1.2",
                "mad_version": mad_version,
                "integration_version": integration_version,
                "source": source,
                "raw_source": "zabbix",
                "snapshot_signature": snapshot_signature,
                "snapshot_mode": snapshot_mode,
                "send_reason": send_reason,
                "snapshot_changed": snapshot_changed,
                "collection_window_start": scanned_at,
                "collection_window_end": scanned_at,
            },
            "event_count": len(events),
        },
        "findings": findings,
    }

    return report, None
