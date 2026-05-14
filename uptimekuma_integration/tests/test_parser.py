import unittest
import sys
from pathlib import Path


for _module_name in ("collector", "summarizer", "agent", "deliver", "config"):
    sys.modules.pop(_module_name, None)


UPTIME_DIR = Path(__file__).resolve().parents[1]
if str(UPTIME_DIR) not in sys.path:
    sys.path.insert(0, str(UPTIME_DIR))

from collector import parse_metrics


SAMPLE_METRICS = """
# HELP monitor_status Monitor Status (1 = UP, 0= DOWN, 2= PENDING, 3= MAINTENANCE)
# TYPE monitor_status gauge
monitor_status{monitor_id="1",monitor_name="web-api",monitor_type="http",monitor_url="https://api.example.com",monitor_hostname="api.example.com",monitor_port="443"} 1
monitor_status{monitor_id="2",monitor_name="db-tcp",monitor_type="tcp",monitor_url="",monitor_hostname="db.local",monitor_port="5432"} 0
monitor_response_time{monitor_id="1",monitor_name="web-api",monitor_type="http",monitor_url="https://api.example.com",monitor_hostname="api.example.com",monitor_port="443"} 123.45
monitor_uptime_ratio{monitor_id="1",monitor_name="web-api",monitor_type="http",monitor_url="https://api.example.com",monitor_hostname="api.example.com",monitor_port="443",window="1d"} 0.999
monitor_uptime_ratio{monitor_id="2",monitor_name="db-tcp",monitor_type="tcp",monitor_url="",monitor_hostname="db.local",monitor_port="5432",window="1d"} 0.85
"""


class ParseMetricsTests(unittest.TestCase):
    def test_parse_prometheus_payload(self) -> None:
        monitors = parse_metrics(SAMPLE_METRICS)
        self.assertEqual(len(monitors), 2)

        self.assertEqual(monitors["1"]["status"], 1)
        self.assertAlmostEqual(monitors["1"]["response_time_ms"], 123.45, places=2)
        self.assertAlmostEqual(monitors["1"]["uptime_1d"], 0.999, places=3)

        self.assertEqual(monitors["2"]["status"], 0)
        self.assertAlmostEqual(monitors["2"]["uptime_1d"], 0.85, places=2)


if __name__ == "__main__":
    unittest.main()
