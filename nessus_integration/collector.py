import random
import time
from typing import Any, Dict, List, Optional

import requests

try:
    from defusedxml import ElementTree as _ET
except ImportError:
    import xml.etree.ElementTree as _ET

from config import Config

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


def _backoff_with_jitter(base_seconds: int, attempt: int, max_wait: int = 60) -> float:
    exp_wait = min(max_wait, max(1, base_seconds) * (2 ** max(0, attempt - 1)))
    return exp_wait + random.uniform(0, 0.5 * exp_wait)


def _child_text(elem, tag: str) -> str:
    child = elem.find(tag)
    if child is None:
        return ""
    return (child.text or "").strip()


def _collect_cves(item) -> List[str]:
    out: List[str] = []
    for child in item.findall("cve"):
        value = (child.text or "").strip()
        if value:
            out.append(value)
    return sorted(set(out))


def _optional_float(elem, tag: str) -> Optional[float]:
    raw = _child_text(elem, tag)
    if not raw:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _coerce_cve_list(value: Any) -> List[str]:
    out: List[str] = []
    if isinstance(value, str):
        tokens = value.split(",")
    elif isinstance(value, (list, tuple)):
        tokens = value
    else:
        tokens = []
    for token in tokens:
        text = str(token).strip()
        if text and text not in out:
            out.append(text)
    return out


def parse_plugin_detail(plugin_id: int, data: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = data.get("info") if isinstance(data, dict) else None
    if not isinstance(info, dict):
        info = {}
    entries = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        entries = []

    plugin_name = str(info.get("plugin_name") or "") or f"Plugin {plugin_id}"
    cves = _coerce_cve_list(info.get("cve"))
    cvss2 = _safe_float(info.get("cvss_base_score"))
    cvss3 = _safe_float(info.get("cvss3_base_score"))
    solution = str(info.get("solution") or "").strip()
    synopsis = str(info.get("synopsis") or "").strip()
    description = str(info.get("description") or "").strip()

    findings: List[Dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        hostname = str(entry.get("hostname") or "").strip()
        ip = str(entry.get("ip") or "").strip()
        host = hostname or ip or "N/A"
        port = str(entry.get("port") or "0")
        protocol = str(entry.get("protocol") or "").strip()
        svc_name = str(entry.get("svc_name") or "").strip()
        sev_raw = entry.get("severity")
        if sev_raw is None:
            sev_raw = info.get("severity")
        findings.append(
            {
                "plugin_id": plugin_id,
                "plugin_name": plugin_name,
                "severity": int(sev_raw or 0),
                "count": 1,
                "host": host,
                "hostname": hostname,
                "ip": ip,
                "port": port,
                "protocol": protocol,
                "svc_name": svc_name,
                "cve": ", ".join(cves),
                "cves": cves,
                "cvss_base_score": cvss2,
                "cvss_vector": str(info.get("cvss_vector") or "").strip(),
                "cvss3_base_score": cvss3,
                "cvss3_vector": str(info.get("cvss3_vector") or "").strip(),
                "solution": solution,
                "synopsis": synopsis,
                "description": description,
                "plugin_output": str(entry.get("plugin_output") or "").strip(),
            }
        )

    if not findings:
        findings.append(
            {
                "plugin_id": plugin_id,
                "plugin_name": plugin_name,
                "severity": int(info.get("severity") or 0),
                "count": 1,
                "host": "N/A",
                "hostname": "",
                "ip": "",
                "port": "0",
                "protocol": "",
                "svc_name": "",
                "cve": ", ".join(cves),
                "cves": cves,
                "cvss_base_score": cvss2,
                "cvss_vector": str(info.get("cvss_vector") or "").strip(),
                "cvss3_base_score": cvss3,
                "cvss3_vector": str(info.get("cvss3_vector") or "").strip(),
                "solution": solution,
                "synopsis": synopsis,
                "description": description,
                "plugin_output": str(info.get("plugin_output") or "").strip(),
            }
        )
    return findings


def parse_nessus_export(xml_text: str) -> List[Dict[str, Any]]:
    root = _ET.fromstring(xml_text)
    findings: List[Dict[str, Any]] = []

    for host_elem in root.iter("ReportHost"):
        hostname = (host_elem.get("name") or "").strip()
        ip = ""
        for tag in host_elem.iter("tag"):
            tag_name = (tag.get("name") or "").strip().lower()
            if tag_name in {"host-ip", "host_ip"}:
                ip = (tag.text or "").strip()
                if ip:
                    break

        for item in host_elem.iter("ReportItem"):
            try:
                plugin_id = int(item.get("pluginID"))
            except (TypeError, ValueError):
                continue
            severity = int(item.get("severity", "0") or "0")
            port = str(item.get("port", "0") or "0")
            protocol = str(item.get("protocol", "") or "")
            svc_name = str(item.get("svc_name", "") or "")
            cves = _collect_cves(item)

            findings.append(
                {
                    "plugin_id": plugin_id,
                    "plugin_name": str(item.get("pluginName", "") or ""),
                    "severity": severity,
                    "count": 1,
                    "host": hostname,
                    "hostname": hostname,
                    "ip": ip,
                    "port": port,
                    "protocol": protocol,
                    "svc_name": svc_name,
                    "cve": ", ".join(cves),
                    "cves": cves,
                    "cvss_base_score": _optional_float(item, "cvss_base_score"),
                    "cvss_vector": _child_text(item, "cvss_vector"),
                    "cvss3_base_score": _optional_float(item, "cvss3_base_score"),
                    "cvss3_vector": _child_text(item, "cvss3_vector"),
                    "solution": _child_text(item, "solution"),
                    "synopsis": _child_text(item, "synopsis"),
                    "description": _child_text(item, "description"),
                    "plugin_output": _child_text(item, "plugin_output"),
                }
            )

    return findings


class NessusCollector:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-ApiKeys": f"accessKey={cfg.nessus_access_key}; secretKey={cfg.nessus_secret_key}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

    def _request(
        self,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        raw: bool = False,
    ) -> Any:
        url = f"{self.cfg.api_root}{path}"
        last_error: Optional[Exception] = None
        max_attempts = max(self.cfg.http_retries, 1)

        for attempt in range(1, max_attempts + 1):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    json=json,
                    timeout=self.cfg.request_timeout,
                    verify=self.cfg.verify_ssl,
                )

                if 200 <= response.status_code < 300:
                    if raw:
                        return response.content
                    data = response.json()
                    if isinstance(data, dict):
                        return data
                    raise RuntimeError("Respuesta Nessus no es objeto JSON.")

                body = (response.text or "")[:300]
                if response.status_code in RETRYABLE_STATUS_CODES and attempt < max_attempts:
                    wait_for = _backoff_with_jitter(self.cfg.backoff_seconds, attempt)
                    print(
                        f"[WARN] Nessus request {path} retriable HTTP {response.status_code}. "
                        f"retry in {wait_for:.1f}s"
                    )
                    time.sleep(wait_for)
                    continue
                raise RuntimeError(f"Nessus request failed HTTP {response.status_code}: {body}")
            except requests.RequestException as exc:
                last_error = exc
                if attempt < max_attempts:
                    wait_for = _backoff_with_jitter(self.cfg.backoff_seconds, attempt)
                    print(f"[WARN] Nessus request {path} network error: {exc}. retry in {wait_for:.1f}s")
                    time.sleep(wait_for)
                    continue
                raise RuntimeError(f"Nessus request failed: {last_error}") from exc

        raise RuntimeError(f"Nessus request failed: {last_error}")

    def list_scans(self) -> List[Dict[str, Any]]:
        data = self._request("GET", "/scans")
        scans = data.get("scans", [])
        if not isinstance(scans, list):
            return []
        return [s for s in scans if isinstance(s, dict)]

    def get_scan_details(self, scan_id: int) -> Dict[str, Any]:
        return self._request("GET", f"/scans/{scan_id}")

    def export_scan(self, scan_id: int, fmt: str = "nessus") -> Any:
        data = self._request("POST", f"/scans/{scan_id}/export", json={"format": fmt})
        file_id = data.get("file")
        if file_id is None:
            raise RuntimeError("Respuesta export Nessus no incluye 'file'.")
        return file_id

    def export_status(self, scan_id: int, file_id: Any) -> Dict[str, Any]:
        return self._request("GET", f"/scans/{scan_id}/export/{file_id}/status")

    def download_export(self, scan_id: int, file_id: Any) -> str:
        content = self._request("GET", f"/scans/{scan_id}/export/{file_id}/download", raw=True)
        if isinstance(content, bytes):
            return content.decode("utf-8", errors="replace")
        return str(content)

    def _enrich_scan_vulns(self, scan_id: int, vulns: List[Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
        if not vulns:
            return None
        if not getattr(self.cfg, "nessus_export", True):
            return None
        try:
            file_id = self.export_scan(scan_id)
            attempts = int(getattr(self.cfg, "nessus_export_poll_attempts", 24) or 1)
            poll_wait = float(getattr(self.cfg, "nessus_export_poll_seconds", 5) or 1)
            ready = False
            for _ in range(attempts):
                status = str(self.export_status(scan_id, file_id).get("status", "")).strip().lower()
                if status in {"ready", "complete", "completed"}:
                    ready = True
                    break
                time.sleep(poll_wait)
            if not ready:
                print(f"[WARN] Nessus export {scan_id} no listo tras {attempts} intentos. fallback resumen.")
                return None
            parsed = parse_nessus_export(self.download_export(scan_id, file_id))
            if not parsed:
                print(f"[WARN] Nessus export {scan_id} sin items parseables. fallback resumen.")
                return None
            return parsed
        except Exception as exc:
            print(f"[WARN] Nessus export {scan_id} fallo: {exc}. fallback resumen.")
            return None

    def get_plugin_vulns(self, scan_id: int, plugin_id: int) -> Dict[str, Any]:
        return self._request("GET", f"/scans/{scan_id}/vulnerabilities/{plugin_id}")

    def _enrich_scan_vulns_detail(self, scan_id: int, vulns: List[Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
        if not vulns:
            return None
        if not getattr(self.cfg, "nessus_plugin_detail", True):
            return None
        enriched: List[Dict[str, Any]] = []
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            plugin_id = vuln.get("plugin_id")
            if isinstance(plugin_id, str) and plugin_id.isdigit():
                plugin_id = int(plugin_id)
            if not isinstance(plugin_id, int):
                continue
            try:
                data = self.get_plugin_vulns(scan_id, plugin_id)
            except Exception as exc:
                print(f"[WARN] Nessus plugin detail {scan_id}/{plugin_id} fallo: {exc}. fallback resumen.")
                return None
            parsed = parse_plugin_detail(plugin_id, data)
            if parsed:
                enriched.extend(parsed)
            else:
                enriched.append(vuln)
        return enriched or None

    def _status_allowed(self, status: str) -> bool:
        # Sync only completed/imported scans to avoid partial/inconsistent findings.
        allowed = {"completed", "imported"}
        return status.strip().lower() in allowed

    def _is_in_scope(self, scan: Dict[str, Any]) -> bool:
        scan_id = scan.get("id")
        if not isinstance(scan_id, int):
            return False

        if self.cfg.scan_ids_filter and scan_id not in self.cfg.scan_ids_filter:
            return False

        if self.cfg.folder_id_filter is not None:
            folder_id = scan.get("folder_id")
            if folder_id != self.cfg.folder_id_filter:
                return False

        status = str(scan.get("status", ""))
        return self._status_allowed(status)

    def collect(self) -> List[Dict[str, Any]]:
        scans = [s for s in self.list_scans() if self._is_in_scope(s)]
        scans.sort(key=lambda s: int(s.get("last_modification_date", 0) or 0), reverse=True)
        scans = scans[: self.cfg.max_scans_per_cycle]

        collected: List[Dict[str, Any]] = []
        for scan in scans:
            scan_id = scan.get("id")
            if not isinstance(scan_id, int):
                continue
            details = self.get_scan_details(scan_id)
            info = details.get("info", {}) if isinstance(details.get("info"), dict) else {}
            vulnerabilities = details.get("vulnerabilities", []) if isinstance(details.get("vulnerabilities"), list) else []
            hosts = details.get("hosts", []) if isinstance(details.get("hosts"), list) else []

            enriched = self._enrich_scan_vulns(scan_id, vulnerabilities)
            if enriched is not None:
                vulnerabilities = enriched
            else:
                detail = self._enrich_scan_vulns_detail(scan_id, vulnerabilities)
                if detail is not None:
                    vulnerabilities = detail
                    print(
                        f"[INFO] Nessus scan {scan_id}: enriquecido via plugin detail "
                        f"({len(detail)} hallazgos, export no disponible)."
                    )

            collected.append(
                {
                    "scan_id": scan_id,
                    "scan_name": scan.get("name") or info.get("name") or f"Nessus Scan {scan_id}",
                    "status": str(scan.get("status", info.get("status", ""))),
                    "last_modification_date": int(scan.get("last_modification_date", 0) or 0),
                    "creation_date": int(scan.get("creation_date", 0) or 0),
                    "folder_id": scan.get("folder_id"),
                    "owner": scan.get("owner"),
                    "targets": info.get("targets", ""),
                    "scan_start": info.get("scan_start"),
                    "scan_end": info.get("scan_end"),
                    "hosts_total": scan.get("total_targets")
                    or scan.get("hostcount")
                    or len(hosts),
                    "severity_summary": {
                        "critical": int(scan.get("critical", 0) or 0),
                        "high": int(scan.get("high", 0) or 0),
                        "medium": int(scan.get("medium", 0) or 0),
                        "low": int(scan.get("low", 0) or 0),
                        "info": int(scan.get("info", 0) or 0),
                    },
                    "vulnerabilities": vulnerabilities,
                    "hosts": hosts,
                }
            )

        return collected
