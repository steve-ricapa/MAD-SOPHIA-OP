import unittest
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from src.aggregator import Aggregator


class TestAggregator(unittest.TestCase):
    def setUp(self):
        self.agg = Aggregator(tenant_id="1")

    def test_severity_mapping(self):
        high_raw = {
            "_id": "evt-1",
            "timestamp": "2026-04-01T00:00:00Z",
            "rule": {"id": "100", "level": 13, "description": "High test", "groups": []},
            "agent": {"id": "001", "name": "host1", "ip": "10.0.0.1"},
        }
        finding = self.agg.normalize_alert(high_raw)
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["dedup_id"], "wazuh-evt-1")

    def test_report_envelope(self):
        report = self.agg.create_report(
            processed_alerts=[],
            agent_summary={"total": 5},
            config={"scan_id": "scan-1", "company_id": 1, "api_key": "k"},
        )
        self.assertEqual(report["event_type"], "vuln_scan_report")
        self.assertEqual(report["scanner_type"], "wazuh")
        self.assertEqual(report["scan_summary"]["total_hosts"], 5)


if __name__ == "__main__":
    unittest.main()
