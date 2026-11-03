from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from snapshot import _scan_sort_key

SEVERITY_MAP = {
    4: ("critical", 9.5),
    3: ("high", 8.0),
    2: ("medium", 5.5),
    1: ("low", 2.5),
    0: ("info", 0.0),
}


def _severity_from_nessus(sev: Any) -> Tuple[str, float]:
    try:
        key = int(sev)
    except (TypeError, ValueError):
        key = 0
    return SEVERITY_MAP.get(key, ("info", 0.0))


def _pick_cvss(vuln: Dict[str, Any], default_cvss: float) -> float:
    for key in ("cvss3_base_score", "cvss_base_score"):
        raw = vuln.get(key)
        if raw in (None, ""):
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            continue
    return default_cvss


def _pick_cve(vuln: Dict[str, Any]) -> str:
    raw = vuln.get("cve")
    if isinstance(raw, list):
        parts = [str(x).strip() for x in raw if str(x).strip()]
    else:
        parts = [x.strip() for x in str(raw or "").split(",") if x.strip()]
    return ", ".join(sorted(set(parts))) or "N/A"


def build_findings(
    scans: List[Dict[str, Any]],
    processed_scans: Dict[str, int],
    include_all_findings: bool,
) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    next_processed = dict(processed_scans)

    for scan in sorted(scans, key=_scan_sort_key):
        scan_id = int(scan.get("scan_id", 0) or 0)
        mod_ts = int(scan.get("last_modification_date", 0) or 0)
        key = str(scan_id)
        prev_ts = int(processed_scans.get(key, 0) or 0)
        scan_changed = mod_ts > prev_ts
        next_processed[key] = max(prev_ts, mod_ts)

        if not include_all_findings and not scan_changed:
            continue

        vulns = scan.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            vulns = []

        if not vulns:
            findings.append(
                {
                    "name": f"Nessus Scan '{scan.get('scan_name', scan_id)}' completed with no listed vulnerabilities",
                    "severity": "info",
                    "cvss": 0.0,
                    "cve": "N/A",
                    "oid": f"nessus-scan-{scan_id}",
                    "host": scan.get("targets") or "N/A",
                    "port": "0",
                    "protocol": "nessus",
                    "description": f"Scan status={scan.get('status')} | last_modification_date={mod_ts}",
                    "solution": "Review Nessus scan details to validate scan scope and plugin coverage.",
                    "impact": "No vulnerability rows returned in current API snapshot.",
                    "finding_type": "scan_summary",
                    "source_scan_id": scan_id,
                    "occurrence_count": 0,
                }
            )
            continue

        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            sev_label, default_cvss = _severity_from_nessus(vuln.get("severity"))
            plugin_id = vuln.get("plugin_id")
            plugin_name = vuln.get("plugin_name") or f"Plugin {plugin_id}"
            count = int(vuln.get("count", 1) or 1)
            cvss = _pick_cvss(vuln, default_cvss)
            cve = _pick_cve(vuln)
            host = str(vuln.get("host") or scan.get("targets") or "N/A")
            port = str(vuln.get("port") or "0")
            protocol = str(vuln.get("protocol") or "nessus")
            solution = str(vuln.get("solution") or "").strip() or (
                "Open the Nessus scan details and apply remediation guidance from the plugin output."
            )
            synopsis = str(vuln.get("synopsis") or "").strip()
            description = str(vuln.get("description") or "").strip() or (
                "Potential exposure identified by Nessus plugin checks."
            )
            plugin_output = str(vuln.get("plugin_output") or "").strip()

            description_parts = [
                f"Scan '{scan.get('scan_name', scan_id)}' status={scan.get('status')}",
                f"plugin_id={plugin_id}",
                f"host={host}",
                f"port={port}",
                f"affected_count={count}",
            ]
            if plugin_output:
                description_parts.append(f"plugin_output={plugin_output[:500]}")
            if synopsis:
                description_parts.append(f"synopsis={synopsis[:500]}")
            extra = " | ".join(description_parts)

            findings.append(
                {
                    "name": str(plugin_name),
                    "severity": sev_label,
                    "cvss": cvss,
                    "cve": cve,
                    "oid": f"nessus-plugin-{plugin_id}",
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "description": extra,
                    "solution": solution,
                    "impact": description,
                    "finding_type": "vulnerability_summary",
                    "source_scan_id": scan_id,
                    "occurrence_count": count,
                }
            )

    return {"findings": findings, "processed_scans": next_processed}


def build_report(
    *,
    scan_id: str,
    company_id: int,
    api_key: str,
    scanner_type: str,
    event_type: str,
    idempotency_key: str,
    scans: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    snapshot_signature: str = "",
    snapshot_mode: str = "delta_with_periodic_forced",
    send_reason: str = "no_change",
    snapshot_changed: bool = False,
    mad_version: str = "2.3.0",
    integration_version: str = "1.0.0",
    source: str = "mad-collector",
) -> Dict[str, Any]:
    scanned_at = datetime.now(timezone.utc).isoformat()

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0
    for finding in findings:
        count = int(finding.get("occurrence_count", 1) or 1)
        sev = str(finding.get("severity", "info"))
        if sev == "critical":
            critical_count += count
        elif sev == "high":
            high_count += count
        elif sev == "medium":
            medium_count += count
        elif sev == "low":
            low_count += count
        else:
            info_count += count

    cvss_max = max((float(f.get("cvss", 0.0)) for f in findings), default=0.0)
    total_hosts = sum(int(s.get("hosts_total", 0) or 0) for s in scans)

    scan_summary = {
        "summary_type": "vuln_scan_report",
        "scan_id": scan_id,
        "scan_name": "Nessus Real-time Sync",
        "status": "completed",
        "total_hosts": total_hosts,
        "scanned_at": scanned_at,
        "cvss_max": cvss_max,
        "scanner_type": scanner_type,
        "results": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "info": info_count,
        },
        "meta": {
            "schema_version": "1.0",
            "mad_version": mad_version,
            "integration_version": integration_version,
            "source": source,
            "snapshot_signature": snapshot_signature,
            "snapshot_mode": snapshot_mode,
            "send_reason": send_reason,
            "snapshot_changed": snapshot_changed,
            "scans_in_payload": len(scans),
            "findings_in_payload": len(findings),
            "completed_scans": sum(1 for s in scans if str(s.get("status", "")).lower() == "completed"),
            "targets_covered": [s.get("targets") for s in scans if s.get("targets")],
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
