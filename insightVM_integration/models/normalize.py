from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models.schemas import AgentError, Asset, Finding, Severity, SourceResult, UnifiedReport


def _sha1(*parts: str) -> str:
    s = "|".join([p.strip() for p in parts if p is not None and str(p).strip() != ""])
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, dict):
        if isinstance(x.get("resources"), list):
            return x["resources"]
        if isinstance(x.get("data"), list):
            return x["data"]
    return [x]


def _pick(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def normalize_severity(v: Any) -> Severity:
    if v is None:
        return "info"
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("info", "informational", "unknown"):
            return "info"
        if s == "low":
            return "low"
        if s in ("medium", "moderate"):
            return "medium"
        if s in ("high", "severe"):
            return "high"
        if s == "critical":
            return "critical"
        return "info"
    if isinstance(v, (int, float)):
        score = float(v)
        if score <= 0:
            return "info"
        if score < 4:
            return "low"
        if score < 7:
            return "medium"
        if score < 9:
            return "high"
        return "critical"
    return "info"


def _finding_to_dict(
    f: Finding,
    asset_ip_map: Dict[str, Optional[str]],
) -> Dict[str, Any]:
    raw = f.raw or {}
    desc_obj = raw.get("description", "No description available")
    sol_obj = raw.get("solution", "No solution available")

    description = desc_obj
    if isinstance(desc_obj, dict):
        description = desc_obj.get("text") or desc_obj.get("html") or str(desc_obj)

    solution = sol_obj
    if isinstance(sol_obj, dict):
        solution = sol_obj.get("text") or sol_obj.get("html") or str(sol_obj)

    return {
        "name": f.title or "Vulnerability",
        "severity": f.severity or "info",
        "cvss": f.cvss,
        "cve": f.cve,
        "host": asset_ip_map.get(f.asset_id),
        "description": str(description),
        "solution": str(solution),
        "impact": str(f.impact or "No impact information"),
    }


def build_insightvm_report(
    *,
    scan_id: str,
    company_id: int,
    api_key: str,
    idempotency_key: str,
    assets: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    asset_ip_map: Dict[str, Optional[str]],
    snapshot_signature: str = "",
    snapshot_mode: str = "delta_with_periodic_forced",
    send_reason: str = "no_change",
    snapshot_changed: bool = False,
    mad_version: str = "2.3.0",
    integration_version: str = "1.0.0",
    source: str = "mad-collector",
) -> Dict[str, Any]:
    scanned_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    flat_findings = []
    for f_conf in findings:
        title = f_conf.get("title") or "Vulnerability"
        severity = str(f_conf.get("severity", "info"))
        cvss = f_conf.get("cvss")
        cve = f_conf.get("cve")
        asset_id = f_conf.get("asset_id")
        raw = f_conf.get("raw") or {}

        desc_obj = raw.get("description", "No description available")
        sol_obj = raw.get("solution", "No solution available")

        description = desc_obj
        if isinstance(desc_obj, dict):
            description = desc_obj.get("text") or desc_obj.get("html") or str(desc_obj)

        solution = sol_obj
        if isinstance(sol_obj, dict):
            solution = sol_obj.get("text") or sol_obj.get("html") or str(sol_obj)

        flat_findings.append({
            "name": title,
            "severity": severity,
            "cvss": cvss,
            "cve": cve,
            "host": asset_ip_map.get(asset_id),
            "description": str(description),
            "solution": str(solution),
            "impact": str(f_conf.get("impact") or "No impact information"),
        })

    counts = {
        "critical": sum(1 for f in flat_findings if f["severity"] == "critical"),
        "high": sum(1 for f in flat_findings if f["severity"] == "high"),
        "medium": sum(1 for f in flat_findings if f["severity"] == "medium"),
        "low": sum(1 for f in flat_findings if f["severity"] == "low"),
        "info": sum(1 for f in flat_findings if f["severity"] == "info"),
    }

    cvss_max = max((float(f.get("cvss") or 0.0) for f in flat_findings), default=0.0)

    return {
        "scan_id": scan_id,
        "company_id": company_id,
        "api_key": api_key,
        "idempotency_key": idempotency_key,
        "scanned_at": scanned_at,
        "event_type": "vuln_scan_report",
        "scanner_type": "insightvm",
        "scan_summary": {
            "scanner_type": "insightvm",
            "status": "completed",
            "scanned_at": scanned_at,
            "scan_name": "InsightVM Snapshot",
            "cvss_max": cvss_max,
            "total_hosts": len(assets),
            "results": counts,
            "meta": {
                "schema_version": "1.0",
                "mad_version": mad_version,
                "integration_version": integration_version,
                "source": source,
                "snapshot_signature": snapshot_signature,
                "snapshot_mode": snapshot_mode,
                "send_reason": send_reason,
                "snapshot_changed": snapshot_changed,
            },
        },
        "findings": flat_findings,
    }


def normalize_insightvm_source(raw: Dict[str, Any]) -> SourceResult:
    res = SourceResult(source="insightvm")

    if not isinstance(raw, dict) or raw.get("error"):
        res.errors.append(AgentError(source="insightvm", message=str(raw.get("error", "Formato inválido"))))
        return res

    assets_raw = raw.get("assets")
    vulns_raw = raw.get("vulnerabilities")

    vuln_defs = {}
    for it in _as_list(vulns_raw):
        if isinstance(it, dict) and it.get("id"):
            vuln_defs[it["id"]] = it

    assets: List[Asset] = []
    findings: List[Finding] = []

    assets_resources = _as_list(assets_raw)
    for i, it in enumerate(assets_resources):
        if isinstance(it, dict):
            hostname = _pick(it, "host_name", "hostname", "name")
            ip = _pick(it, "ip", "ip_address", "address")
            
            if ip is None and isinstance(it.get("addresses"), list):
                for addr in it["addresses"]:
                    if isinstance(addr, dict):
                        ip = _pick(addr, "ip", "ip_address", "address")
                        if ip: break
                    elif isinstance(addr, str):
                        ip = addr; break

            os_name = _pick(it, "os", "operating_system", "os_name")
            key = (str(ip) or str(hostname) or f"asset-{i}").strip()
            aid = _sha1("asset", key.lower())

            asset_obj = Asset(
                id=aid,
                source="insightvm",
                hostname=str(hostname) if hostname else None,
                ip=str(ip) if ip else None,
                os=str(os_name) if os_name else None,
                raw=it,
            )
            assets.append(asset_obj)

            for v_id in it.get("vulnerabilities_ids", []):
                v_def = vuln_defs.get(v_id)
                if v_def:
                    title = str(_pick(v_def, "title", "name", "summary") or "Vulnerability")
                    
                    cve = _pick(v_def, "cve")
                    if not cve and isinstance(v_def.get("cves"), list) and v_def["cves"]:
                        cve = v_def["cves"][0]
                    
                    cvss = _pick(v_def, "cvss_score")
                    raw_cvss = v_def.get("cvss", {})
                    if not cvss and isinstance(raw_cvss, dict):
                        v3 = raw_cvss.get("v3", {})
                        v2 = raw_cvss.get("v2", {})
                        if isinstance(v3, dict): cvss = v3.get("score")
                        if not cvss and isinstance(v2, dict): cvss = v2.get("score")
                    
                    if not cvss:
                        cvss = v_def.get("severityScore")

                    risk_score = v_def.get("riskScore")
                    impact = v_def.get("impact") or ""

                    sev = normalize_severity(_pick(v_def, "severity") or cvss)
                    
                    fid = _sha1("finding", aid, v_id)
                    findings.append(
                        Finding(
                            id=fid,
                            source="insightvm",
                            asset_id=aid,
                            title=title,
                            cve=str(cve) if cve else None,
                            cvss=float(cvss) if isinstance(cvss, (int, float)) else None,
                            risk_score=float(risk_score) if isinstance(risk_score, (int, float)) else None,
                            severity=sev,
                            impact=str(impact),
                            raw=v_def,
                        )
                    )
        else:
            aid = _sha1("asset", f"asset-{i}")
            assets.append(Asset(id=aid, source="insightvm", raw={"value": it}))

    res.assets = assets
    res.findings = findings
    res.meta = {"assets_count": len(assets), "findings_count": len(findings)}
    return res


def normalize_unified(raw_unified: Dict[str, Any]) -> Dict[str, Any]:
    report = UnifiedReport()

    insight_raw = raw_unified.get("insightvm", {}) if isinstance(raw_unified, dict) else {}
    report.insightvm = normalize_insightvm_source(insight_raw if isinstance(insight_raw, dict) else {"error": "Formato inválido"})

    return report.as_dict()
