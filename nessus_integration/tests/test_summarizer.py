import sys
from pathlib import Path


for _module_name in ("summarizer", "collector", "agent", "deliver", "config", "snapshot"):
    sys.modules.pop(_module_name, None)


NESSUS_DIR = Path(__file__).resolve().parents[1]
if str(NESSUS_DIR) not in sys.path:
    sys.path.insert(0, str(NESSUS_DIR))

from snapshot import build_snapshot_signature
from summarizer import build_findings, build_report


def test_build_snapshot_signature_stable():
    scans_a = [
        {"scan_id": 2, "last_modification_date": 20, "status": "completed"},
        {"scan_id": 1, "last_modification_date": 10, "status": "completed"},
    ]
    scans_b = [
        {"scan_id": 1, "last_modification_date": 10, "status": "completed"},
        {"scan_id": 2, "last_modification_date": 20, "status": "completed"},
    ]
    assert build_snapshot_signature(scans_a) == build_snapshot_signature(scans_b)


def test_build_findings_maps_nessus_severity():
    scans = [
        {
            "scan_id": 55,
            "scan_name": "test",
            "status": "completed",
            "last_modification_date": 123,
            "targets": "10.0.0.1",
            "vulnerabilities": [
                {"plugin_id": 1001, "plugin_name": "Critical test", "severity": 4, "count": 2},
                {"plugin_id": 1002, "plugin_name": "Low test", "severity": 1, "count": 1},
            ],
        }
    ]

    result = build_findings(scans=scans, processed_scans={}, include_all_findings=True)
    findings = result["findings"]
    assert len(findings) == 2
    assert findings[0]["severity"] == "critical"
    assert findings[0]["cvss"] == 9.5
    assert findings[1]["severity"] == "low"


def test_build_report_counts_occurrences():
    findings = [
        {"severity": "critical", "cvss": 9.5, "occurrence_count": 2},
        {"severity": "high", "cvss": 8.0, "occurrence_count": 3},
        {"severity": "info", "cvss": 0.0, "occurrence_count": 1},
    ]
    scans = [{"hosts_total": 10, "status": "completed", "targets": "10.0.0.0/24"}]

    report = build_report(
        scan_id="NE-test",
        company_id=3,
        api_key="key",
        scanner_type="nessus",
        event_type="vuln_scan_report",
        idempotency_key="idempo",
        scans=scans,
        findings=findings,
        mad_version="2.3.0",
        integration_version="1.0.0",
        source="mad-collector",
    )

    summary = report["scan_summary"]
    assert summary["results"]["critical"] == 2
    assert summary["results"]["high"] == 3
    assert summary["results"]["info"] == 1
    assert summary["total_hosts"] == 10
    assert summary["scanner_type"] == "nessus"
    assert summary["meta"]["schema_version"] == "1.0"
    assert summary["meta"]["mad_version"] == "2.3.0"
