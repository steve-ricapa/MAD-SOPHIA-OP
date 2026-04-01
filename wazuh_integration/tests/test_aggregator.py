import unittest
from src.aggregator import Aggregator


class TestAggregator(unittest.TestCase):
    def setUp(self):
        self.aggregator = Aggregator(tenant_id="9")

    def test_normalize_alert_basic(self):
        """Test basic normalization with minimal Wazuh alert."""
        raw = {
            "timestamp": "2024-03-20T12:00:00Z",
            "rule": {"id": "5710", "level": 7, "description": "SSH Login Failed"},
            "agent": {"id": "001", "name": "web-01"}
        }
        normalized = self.aggregator.normalize_alert(raw)
        self.assertEqual(normalized['severity'], 'medium')  # level 7 = medium
        self.assertEqual(normalized['agent']['name'], 'web-01')
        self.assertEqual(normalized['agent']['id'], '001')
        self.assertEqual(normalized['rule']['id'], '5710')
        self.assertEqual(normalized['rule']['level'], 7)
        self.assertTrue(normalized['dedup_id'].startswith("wazuh-"))

    def test_normalize_alert_high_severity(self):
        """Test high severity mapping (level 12-14)."""
        raw = {
            "timestamp": "2024-03-20T12:00:00Z",
            "rule": {"id": "100", "level": 13, "description": "Brute force"},
            "agent": {"id": "002", "name": "db-01"}
        }
        normalized = self.aggregator.normalize_alert(raw)
        self.assertEqual(normalized['severity'], 'high')

    def test_normalize_alert_critical_severity(self):
        """Test critical severity mapping (level 15+)."""
        raw = {
            "rule": {"id": "200", "level": 15, "description": "Rootkit found"},
            "agent": {"id": "003", "name": "prod-01"}
        }
        normalized = self.aggregator.normalize_alert(raw)
        self.assertEqual(normalized['severity'], 'critical')

    def test_normalize_alert_mitre_enrichment(self):
        """Test that MITRE ATT&CK data is fully preserved."""
        raw = {
            "timestamp": "2024-03-20T12:00:00Z",
            "rule": {
                "id": "5501", "level": 3,
                "description": "PAM: Login session opened.",
                "mitre": {
                    "id": ["T1078"],
                    "technique": ["Valid Accounts"],
                    "tactic": ["Defense Evasion", "Persistence"]
                }
            },
            "agent": {"id": "000", "name": "wazuh"}
        }
        normalized = self.aggregator.normalize_alert(raw)
        self.assertEqual(normalized['mitre']['ids'], ['T1078'])
        self.assertEqual(normalized['mitre']['techniques'], ['Valid Accounts'])
        self.assertIn('Defense Evasion', normalized['mitre']['tactics'])
        self.assertIn('Persistence', normalized['mitre']['tactics'])

    def test_normalize_alert_compliance(self):
        """Test that compliance frameworks are forwarded."""
        raw = {
            "timestamp": "2024-03-20T12:00:00Z",
            "rule": {
                "id": "5501", "level": 3,
                "description": "Test",
                "pci_dss": ["10.2.5"],
                "hipaa": ["164.312.b"],
                "nist_800_53": ["AU.14", "AC.7"],
                "gdpr": ["IV_32.2"]
            },
            "agent": {"id": "000", "name": "wazuh"}
        }
        normalized = self.aggregator.normalize_alert(raw)
        self.assertEqual(normalized['compliance']['pci_dss'], ['10.2.5'])
        self.assertEqual(normalized['compliance']['hipaa'], ['164.312.b'])
        self.assertEqual(normalized['compliance']['nist_800_53'], ['AU.14', 'AC.7'])
        self.assertEqual(normalized['compliance']['gdpr'], ['IV_32.2'])

    def test_normalize_alert_agent_ip(self):
        """Test that agent IP is preserved when available."""
        raw = {
            "rule": {"id": "60227", "level": 8, "description": "New device"},
            "agent": {"id": "001", "name": "Jarvis-PC", "ip": "192.168.18.172"}
        }
        normalized = self.aggregator.normalize_alert(raw)
        self.assertEqual(normalized['agent']['ip'], '192.168.18.172')

    def test_normalize_alert_no_ip(self):
        """Test that missing IP defaults to empty string."""
        raw = {
            "rule": {"id": "510", "level": 7, "description": "Rootcheck"},
            "agent": {"id": "005", "name": "kumita"}
        }
        normalized = self.aggregator.normalize_alert(raw)
        self.assertEqual(normalized['agent']['ip'], '')

    def test_calculate_trends(self):
        """Test severity aggregation."""
        alerts = [
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "critical"}
        ]
        trends = self.aggregator.calculate_trends(alerts)
        self.assertEqual(trends['severity_levels']['high'], 2)
        self.assertEqual(trends['severity_levels']['critical'], 1)
        self.assertEqual(trends['severity_levels']['medium'], 1)

    def test_calculate_tops(self):
        """Test top rules and agents calculation with nested structure."""
        alerts = [
            {"rule": {"id": "510", "description": "Rootcheck"}, "agent": {"name": "web-01"}},
            {"rule": {"id": "510", "description": "Rootcheck"}, "agent": {"name": "web-01"}},
            {"rule": {"id": "5501", "description": "PAM Login"}, "agent": {"name": "db-01"}},
        ]
        tops = self.aggregator.calculate_tops(alerts)
        self.assertEqual(tops['top_rules'][0]['desc'], 'Rootcheck')
        self.assertEqual(tops['top_rules'][0]['count'], 2)
        self.assertEqual(tops['top_agents'][0]['name'], 'web-01')
        self.assertEqual(tops['top_agents'][0]['count'], 2)

    def test_detect_agent_changes(self):
        """Test detection of agent status transitions."""
        prev_map = {
            "001": {"id": "001", "status": "active", "name": "web-01"}
        }
        current = [
            {"id": "001", "status": "disconnected", "name": "web-01", "lastKeepAlive": "some-time"}
        ]
        changes, current_map = self.aggregator.detect_agent_changes(current, prev_map)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]['new_status'], 'disconnected')
        self.assertEqual(changes[0]['old_status'], 'active')

    def test_detect_agent_no_changes(self):
        """Test that no changes are reported when status is the same."""
        prev_map = {
            "001": {"id": "001", "status": "active", "name": "web-01"}
        }
        current = [
            {"id": "001", "status": "active", "name": "web-01"}
        ]
        changes, _ = self.aggregator.detect_agent_changes(current, prev_map)
        self.assertEqual(len(changes), 0)

    def test_create_report_structure(self):
        """Test the overall report envelope structure."""
        processed = [
            {
                "dedup_id": "wazuh-abc",
                "severity": "medium",
                "rule": {"id": "510", "level": 7, "description": "Test"},
                "agent": {"id": "005", "name": "kumita"},
                "mitre": {"ids": [], "techniques": [], "tactics": []},
                "compliance": {}
            }
        ]
        config = {"scan_id": "test-123", "company_id": 9, "api_key": "key"}
        report = self.aggregator.create_report(processed, {"total": 5}, config)

        self.assertEqual(report['scan_id'], 'test-123')
        self.assertEqual(report['company_id'], 9)
        self.assertEqual(report['event_type'], 'wazuh_alerts_report')
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['scan_summary']['total_hosts'], 5)
        self.assertEqual(report['scan_summary']['average_count'], 1)  # 1 medium


if __name__ == "__main__":
    unittest.main()
