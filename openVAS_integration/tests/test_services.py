import sys
from pathlib import Path


for _module_name in ("services", "snapshot", "gvm_client", "config"):
    sys.modules.pop(_module_name, None)

OPENVAS_DIR = Path(__file__).resolve().parents[1]
if str(OPENVAS_DIR) not in sys.path:
    sys.path.insert(0, str(OPENVAS_DIR))

from services import emit_payload, extract_findings, extract_report_stats, map_status

def test_status():
    assert map_status("Running") == "running"
    assert map_status("Pending") == "pending"
    assert map_status("Done") == "completed"
    assert map_status("Completed") == "completed"


class _Response:
    def __init__(self, status_code, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_emit_payload_requests_upload_url_then_puts_snapshot(monkeypatch):
    calls = {"post": None, "put": None}

    def _post(url, json, headers, timeout, verify):
        calls["post"] = {
            "url": url,
            "json": json,
            "headers": headers,
            "timeout": timeout,
            "verify": verify,
        }
        return _Response(200, payload={"upload_url": "https://s3.example/upload"})

    def _put(url, data, headers, timeout, verify):
        calls["put"] = {
            "url": url,
            "data": data,
            "headers": headers,
            "timeout": timeout,
            "verify": verify,
        }
        return _Response(200)

    monkeypatch.setattr("services.requests.post", _post)
    monkeypatch.setattr("services.requests.put", _put)
    monkeypatch.setenv("BACKEND_TLS_VERIFY", "false")

    ok = emit_payload(
        output_mode="http",
        url="https://api.example/scans/upload-url",
        api_key="agent-key",
        tenant_id=9,
        company_id=4,
        payload={"scan_id": "OV-1", "scanner_type": "openvas", "idempotency_key": "sha256:abc", "findings": []},
        timeout=12,
    )

    assert ok is True
    assert calls["post"]["url"] == "https://api.example/scans/upload-url"
    assert calls["post"]["json"] == {
        "tenant_id": 9,
        "api_key": "agent-key",
        "scanner_type": "openvas",
        "idempotency_key": "sha256:abc",
    }
    assert calls["put"]["url"] == "https://s3.example/upload"
    assert calls["put"]["headers"] == {"Content-Type": "application/json"}
    assert b'"scan_id":"OV-1"' in calls["put"]["data"]


_ONE_REPORT_XML = (
    '<get_reports_response status="200" status_text="OK">'
    '<report id="r-1"><hosts><count>2</count></hosts><vulns><count>3</count></vulns>'
    "<results>"
    '<result><name>A</name><severity>9.2</severity><host>10.0.0.1</host></result>'
    '<result><name>B</name><severity>7.1</severity><host>10.0.0.2</host></result>'
    '<result><name>C</name><severity>5.0</severity><host>10.0.0.3</host></result>'
    "</results></report>"
    "</get_reports_response>"
)


def test_extract_report_stats_include_results_in_xml():
    stats = extract_report_stats(_ONE_REPORT_XML)
    assert stats["hosts_count"] == 2
    assert stats["vulns_count"] == 3
    assert stats["results_in_xml"] == 3


def test_extract_findings_top_n_zero_returns_all():
    out = extract_findings(_ONE_REPORT_XML, top_n=0)
    assert len(out) == 3
    assert out[0]["cvss"] == 9.2


def test_extract_findings_top_n_caps_results():
    out = extract_findings(_ONE_REPORT_XML, top_n=2)
    assert len(out) == 2
    assert out[0]["cvss"] == 9.2
    assert out[1]["cvss"] == 7.1


def test_extract_findings_preserves_all_cves_and_uses_null_without_cve():
    xml = (
        '<get_reports_response><report><results>'
        '<result><name>Multi CVE</name><severity>8.0</severity><host>10.0.0.1</host>'
        '<nvt><ref type="cve" id="CVE-2024-0001"/><ref type="cve" id="CVE-2024-0002"/>'
        '<cve>CVE-2024-0002, CVE-2024-0003</cve></nvt></result>'
        '<result><name>No CVE</name><severity>2.0</severity><host>10.0.0.2</host>'
        '<nvt><cve>No CVE assigned</cve></nvt></result>'
        '</results></report></get_reports_response>'
    )
    diagnostics = []
    out = extract_findings(xml, top_n=0, diagnostics=diagnostics)
    multi = next(item for item in out if item["name"] == "Multi CVE")
    no_cve = next(item for item in out if item["name"] == "No CVE")
    assert multi["cve"] == "CVE-2024-0001"
    assert multi["cves"] == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
    assert no_cve["cve"] is None
    assert no_cve["cves"] == []
    assert diagnostics == []
