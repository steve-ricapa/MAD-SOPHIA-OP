from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from txdx_etl.connectors.uptime_kuma import parser
from txdx_etl.connectors.uptime_kuma.parser import (
    KNOWN_FAMILIES,
    ParseError,
    parse_metrics,
)

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "connectors" / "uptime_kuma"


def load_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class ParserV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.snapshot = parse_metrics(load_text("metrics-v2.txt"))

    def test_two_monitors_grouped_by_monitor_id(self) -> None:
        self.assertEqual(self.snapshot.capabilities.monitor_count, 2)
        ids = {sample.source_asset_id for sample in self.snapshot.monitors}
        self.assertEqual(ids, {"42", "43"})

    def test_native_identity_quality(self) -> None:
        for sample in self.snapshot.monitors:
            self.assertEqual(sample.identity_quality, "native")

    def test_http_monitor_fields(self) -> None:
        sample = next(s for s in self.snapshot.monitors if s.source_asset_id == "42")
        self.assertEqual(parser.STATUS_MAP[sample.status], "up")
        self.assertEqual(sample.response_time_ms, 123)
        self.assertEqual(sample.cert_is_valid, 1)
        self.assertEqual(sample.cert_days_remaining, 45)
        self.assertEqual(sample.uptime_ratio, {"1d": 0.999, "30d": 0.997})
        self.assertEqual(sample.response_time_seconds_avg, {"1d": 0.1234})
        self.assertEqual(sample.labels["monitor_name"], "Public API")
        self.assertEqual(sample.labels.get("monitor_port", ""), "")

    def test_tcp_monitor_without_certificate(self) -> None:
        sample = next(s for s in self.snapshot.monitors if s.source_asset_id == "43")
        self.assertEqual(parser.STATUS_MAP[sample.status], "maintenance")
        self.assertIsNone(sample.cert_is_valid)
        self.assertIsNone(sample.response_time_ms)

    def test_capabilities_profile(self) -> None:
        caps = self.snapshot.capabilities
        self.assertTrue(caps.has_monitor_id)
        self.assertEqual(set(caps.families), set(KNOWN_FAMILIES))
        self.assertEqual(caps.windows, ("1d", "30d"))

    def test_non_monitor_series_are_ignored(self) -> None:
        text = load_text("metrics-v2.txt")
        self.assertIn("process_cpu_seconds_total", text)
        expected_series = sum(
            1
            for line in text.splitlines()
            if line.strip().startswith("monitor_")
        )
        self.assertEqual(self.snapshot.capabilities.series_count, expected_series)


class ParserV123Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.snapshot = parse_metrics(load_text("metrics-v123.txt"))

    def test_derived_identity_when_no_monitor_id(self) -> None:
        sample = self.snapshot.monitors[0]
        self.assertFalse(self.snapshot.capabilities.has_monitor_id)
        self.assertEqual(sample.identity_quality, "derived")
        expected = "|".join(
            [
                sample.labels["monitor_type"],
                sample.labels.get("monitor_hostname", ""),
                sample.labels.get("monitor_port", ""),
                sample.labels["monitor_url"],
                sample.labels["monitor_name"],
            ]
        )
        self.assertEqual(sample.source_asset_id, expected)

    def test_base_families_only(self) -> None:
        caps = self.snapshot.capabilities
        self.assertNotIn("monitor_uptime_ratio", caps.families)
        self.assertNotIn("monitor_response_time_seconds", caps.families)
        self.assertEqual(caps.windows, ())
        self.assertIsNone(self.snapshot.monitors[0].cert_is_valid)


class ParserEdgeCaseTests(unittest.TestCase):
    def test_unknown_status_value_raises(self) -> None:
        with self.assertRaises(ParseError):
            parse_metrics('monitor_status{monitor_id="1"} 9\n')

    def test_unknown_family_raises(self) -> None:
        with self.assertRaises(ParseError):
            parse_metrics('monitor_brand_new{monitor_id="1"} 1\n')

    def test_aggregated_family_requires_window(self) -> None:
        with self.assertRaises(ParseError):
            parse_metrics('monitor_uptime_ratio{monitor_id="1"} 0.5\n')

    def test_malformed_line_raises(self) -> None:
        with self.assertRaises(ParseError):
            parse_metrics("this is not exposition\n")

    def test_label_escapes_are_unescaped(self) -> None:
        snapshot = parse_metrics(
            'monitor_status{monitor_id="7",'
            'monitor_name="Quote \\"and\\" backslash \\\\"} 1\n'
        )
        sample = snapshot.monitors[0]
        self.assertEqual(sample.labels["monitor_name"], 'Quote "and" backslash \\')

    def test_empty_snapshot_yields_zero_monitors(self) -> None:
        snapshot = parse_metrics("# only comments\n\nprocess_uptime 1\n")
        self.assertEqual(snapshot.capabilities.monitor_count, 0)
        self.assertEqual(snapshot.capabilities.series_count, 0)

    def test_literal_null_labels_are_normalized_to_absence(self) -> None:
        snapshot = parse_metrics(
            'monitor_status{monitor_name="Gateway",monitor_type="ping",'
            'monitor_url="null",monitor_hostname="gw.example.lan",'
            'monitor_port="null"} 1\n'
            "monitor_response_time{monitor_name=\"Gateway\",monitor_type=\"ping\","
            'monitor_url="null",monitor_hostname="gw.example.lan",'
            'monitor_port="null"} 98.1\n'
        )
        sample = snapshot.monitors[0]
        self.assertEqual(sample.labels["monitor_url"], "")
        self.assertEqual(sample.labels["monitor_port"], "")
        self.assertNotIn("null", set(sample.labels.values()))
        self.assertEqual(
            sample.source_asset_id,
            "ping|gw.example.lan|||Gateway",
        )


if __name__ == "__main__":
    unittest.main()
