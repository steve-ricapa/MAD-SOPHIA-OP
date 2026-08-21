from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from txdx_etl.connectors.uptime_kuma.mapper import MappingContext, map_monitor
from txdx_etl.connectors.uptime_kuma.parser import parse_metrics
from txdx_etl.pipeline import validation
from txdx_etl.pipeline.envelope import build_envelope

import schema_utils

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "connectors" / "uptime_kuma"
OBSERVED_AT = "2026-08-21T22:30:00Z"


def load_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def context() -> MappingContext:
    return MappingContext(
        tenant_id="1",
        instance_id="kuma-lab",
        observed_at=OBSERVED_AT,
    )


class RealShapeCapabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = load_text("metrics-real-1.23.17-anonymized.txt")
        cls.snapshot = parse_metrics(cls.raw)

    def test_capability_profile_matches_123x_deployment(self) -> None:
        caps = self.snapshot.capabilities
        self.assertFalse(caps.has_monitor_id)
        self.assertEqual(
            caps.families,
            (
                "monitor_cert_days_remaining",
                "monitor_cert_is_valid",
                "monitor_response_time",
                "monitor_status",
            ),
        )
        self.assertEqual(caps.windows, ())
        self.assertEqual(caps.monitor_count, 10)
        self.assertEqual(caps.series_count, 28)

    def test_app_version_and_noise_are_ignored(self) -> None:
        self.assertIn('app_version{version="1.23.17"', self.raw)
        self.assertNotIn("app_version", self.snapshot.capabilities.families)

    def test_all_monitors_use_derived_identity(self) -> None:
        for sample in self.snapshot.monitors:
            self.assertEqual(sample.identity_quality, "derived")

    def test_no_label_value_contains_literal_null(self) -> None:
        for sample in self.snapshot.monitors:
            self.assertNotIn("null", set(sample.labels.values()))

    def test_push_monitor_is_down_without_latency(self) -> None:
        push = next(
            s for s in self.snapshot.monitors if s.labels["monitor_type"] == "push"
        )
        self.assertEqual(push.status, 0)
        self.assertEqual(push.response_time_ms, -1)


class RealShapeMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = schema_utils.load_schemas()
        cls.snapshot = parse_metrics(
            load_text("metrics-real-1.23.17-anonymized.txt")
        )
        cls.assets: list[dict] = []
        cls.records: list[dict] = []
        for sample in cls.snapshot.monitors:
            asset, observations = map_monitor(sample, context())
            cls.assets.append(asset)
            cls.records.extend(observations)

    def test_ten_assets_and_fourteen_observations(self) -> None:
        self.assertEqual(len(self.assets), 10)
        availability = [
            r for r in self.records if r["observation_type"] == "availability"
        ]
        certificates = [
            r for r in self.records if r["observation_type"] == "certificate"
        ]
        self.assertEqual(len(availability), 10)
        self.assertEqual(len(certificates), 4)

    def test_entities_match_canonical_schemas(self) -> None:
        validator_asset = schema_utils.validator_for(self.schemas, "asset.schema.json")
        validator_obs = schema_utils.validator_for(
            self.schemas, "observation.schema.json"
        )
        for asset in self.assets:
            validator_asset.validate(asset)
        for record in self.records:
            validator_obs.validate(record)

    def test_push_availability_has_no_measurements(self) -> None:
        push_record = next(
            r
            for r in self.records
            if r["observation_type"] == "availability"
            and r["status"] == "down"
        )
        self.assertNotIn("measurements", push_record)
        self.assertNotIn("target", push_record)
        self.assertEqual(push_record["kind"], "initial")

    def test_dns_and_port_endpoints_carry_port_53(self) -> None:
        for asset in self.assets:
            monitor_type = asset.get("attributes", {}).get("monitor_type")
            if monitor_type in ("dns", "port"):
                endpoint = asset["endpoints"][0]
                self.assertEqual(endpoint["port"], 53)
                self.assertNotIn("url", endpoint)

    def test_ping_endpoints_are_hostname_only(self) -> None:
        pings = [
            a
            for a in self.assets
            if a.get("attributes", {}).get("monitor_type") == "ping"
        ]
        self.assertEqual(len(pings), 2)
        for asset in pings:
            self.assertEqual(set(asset["endpoints"][0].keys()), {"hostname"})


class RealShapeEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = schema_utils.load_schemas()
        snapshot = parse_metrics(load_text("metrics-real-1.23.17-anonymized.txt"))
        assets: list[dict] = []
        records: list[dict] = []
        for sample in snapshot.monitors:
            asset, observations = map_monitor(sample, context())
            assets.append(asset)
            records.extend(observations)
        cls.envelope = build_envelope(
            tenant_id="1",
            source_type="uptime_kuma",
            instance_id="kuma-lab",
            display_name="Uptime Kuma laboratorio",
            generated_at="2026-08-21T22:30:02Z",
            run_id="run:test-000000000002",
            run_status="completed",
            started_at="2026-08-21T22:30:00Z",
            ended_at="2026-08-21T22:30:02Z",
            collection_window_start="2026-08-21T22:30:00Z",
            collection_window_end="2026-08-21T22:30:02Z",
            assets=assets,
            records=records,
        )

    def test_envelope_matches_schema(self) -> None:
        schema_utils.validator_for(self.schemas, "envelope.schema.json").validate(
            self.envelope
        )

    def test_envelope_passes_cross_record_validation(self) -> None:
        self.assertEqual(validation.validate_envelope(self.envelope), [])

    def test_canonical_payload_never_contains_literal_null(self) -> None:
        serialized = json.dumps(self.envelope, ensure_ascii=False)
        self.assertNotIn('"null"', serialized)
        self.assertNotIn(": null", serialized)


if __name__ == "__main__":
    unittest.main()
