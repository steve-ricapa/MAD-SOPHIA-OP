import random
import time
from typing import Any, Dict, List, Optional

import requests

from config import Config

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


def _backoff_with_jitter(base_seconds: int, attempt: int, max_wait: int = 60) -> float:
    exp_wait = min(max_wait, max(1, base_seconds) * (2 ** max(0, attempt - 1)))
    return exp_wait + random.uniform(0, 0.5 * exp_wait)


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

    def _request(self, method: str, path: str) -> Dict[str, Any]:
        url = f"{self.cfg.api_root}{path}"
        last_error: Optional[Exception] = None
        max_attempts = max(self.cfg.http_retries, 1)

        for attempt in range(1, max_attempts + 1):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=self.cfg.request_timeout,
                    verify=self.cfg.verify_ssl,
                )

                if 200 <= response.status_code < 300:
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
