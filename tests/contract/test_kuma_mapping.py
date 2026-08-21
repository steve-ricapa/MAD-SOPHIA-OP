from __future__ import annotations

import copy
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

OBSERVED_AT = "2026-08-21T15:00:00Z"
RUN_ID = "run:test-000000000001"


def load_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def build_context(instance_id: str = "kuma-main") -> MappingContext:
    return MappingContext(
        tenant_id="1",
        instance_id=instance_id,
        observed_at=OBSERVED_AT,
    )


def map_snapshot(text: str, ctx: MappingContext) -> tuple[list[dict], list[dict]]:
    snapshot = parse_metrics(text)
    assets: list[dict] = []
    records: list[dict] = []
    for sample in snapshot.monitors:
        asset, observations = map_monitor(sample, ctx)
        assets.append(asset)
        records.extend(observations)
    return assets, records


class KumaMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = schema_utils.load_schemas()
        cls.assets_v2, cls.records_v2 = map_snapshot(
            load_text("metrics-v2.txt"), build_context()
        )

    def _validate_entity(self, record: dict, schema_name: str) -> None:
        schema_utils.validator_for(self.schemas, schema_name).validate(record)

    def test_entities_match_canonical_schemas(self) -> None:
        for asset in self.assets_v2:
            self._validate_entity(asset, "asset.schema.json")
        for record in self.records_v2:
            self._validate_entity(record, "observation.schema.json")

    def test_availability_observation_semantics(self) -> None:
        availability = [
            r for r in self.records_v2 if r["observation_type"] == "availability"
        ]
        self.assertEqual(len(availability), 2)
        public_api = next(
            r for r in availability if r["source_object_id"] == "42"
        )
        self.assertEqual(public_api["status"], "up")
        self.assertEqual(public_api["kind"], "initial")
        self.assertNotIn("source_event_time", public_api)
        names = [m["name"] for m in public_api["measurements"]]
        self.assertEqual(
            names,
            ["response_time", "uptime_ratio", "uptime_ratio", "response_time_avg"],
        )

    def test_certificate_observation_only_for_tls_monitors(self) -> None:
        certificates = [
            r for r in self.records_v2 if r["observation_type"] == "certificate"
        ]
        self.assertEqual(len(certificates), 1)
        self.assertEqual(certificates[0]["status"], "valid")
        self.assertEqual(certificates[0]["measurements"][0]["unit"], "d")

    def test_negative_response_time_is_omitted_not_zeroed(self) -> None:
        text = (
            'monitor_status{monitor_id="9",monitor_name="Broken"} 1\n'
            'monitor_response_time{monitor_id="9",monitor_name="Broken"} -1\n'
        )
        _, records = map_snapshot(text, build_context())
        availability = next(
            r for r in records if r["observation_type"] == "availability"
        )
        self.assertNotIn("measurements", availability)

    def test_change_observation_requires_previous_status(self) -> None:
        snapshot = parse_metrics(load_text("metrics-v123.txt"))
        with self.assertRaises(ValueError):
            map_monitor(snapshot.monitors[0], build_context(), kind="change")

    def test_change_observation_uses_event_time_discriminator(self) -> None:
        snapshot = parse_metrics(load_text("metrics-v123.txt"))
        sample = snapshot.monitors[0]
        ctx = build_context()
        _, initial_records = map_monitor(sample, ctx, kind="initial")
        _, change_records = map_monitor(
            sample,
            ctx,
            kind="change",
            previous_status="up",
        )
        self.assertNotEqual(initial_records[0]["record_id"], change_records[0]["record_id"])
        self.assertEqual(change_records[0]["previous_status"], "up")


class KumaEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = schema_utils.load_schemas()
        cls.assets, cls.records = map_snapshot(
            load_text("metrics-v2.txt"), build_context()
        )
        cls.envelope = build_envelope(
            tenant_id="1",
            source_type="uptime_kuma",
            instance_id="kuma-main",
            display_name="Uptime Kuma principal",
            generated_at="2026-08-21T15:00:02Z",
            run_id=RUN_ID,
            run_status="completed",
            started_at="2026-08-21T15:00:00Z",
            ended_at="2026-08-21T15:00:02Z",
            collection_window_start="2026-08-21T15:00:00Z",
            collection_window_end="2026-08-21T15:00:02Z",
            assets=cls.assets,
            records=cls.records,
        )

    def test_envelope_matches_schema(self) -> None:
        schema_utils.validator_for(self.schemas, "envelope.schema.json").validate(
            self.envelope
        )

    def test_envelope_passes_cross_record_validation(self) -> None:
        self.assertEqual(validation.validate_envelope(self.envelope), [])

    def test_counts_reflect_mapped_records(self) -> None:
        counts = self.envelope["run"]["record_counts"]
        self.assertEqual(counts["assets"], 2)
        self.assertEqual(counts["observations"], len(self.records))
        self.assertEqual(counts["accepted"], len(self.records))
        self.assertEqual(counts["findings"], 0)
        self.assertEqual(counts["detections"], 0)

    def test_delivery_id_survives_record_reordering(self) -> None:
        reordered = copy.deepcopy(self.envelope)
        reordered["records"] = list(reversed(reordered["records"]))
        self.assertEqual(validation.validate_envelope(reordered), [])

    def test_derived_instance_produces_distinct_assets(self) -> None:
        other_assets, other_records = map_snapshot(
            load_text("metrics-v123.txt"),
            build_context(instance_id="kuma-legacy"),
        )
        native_ids = {a["asset_id"] for a in self.assets}
        for asset in other_assets:
            self.assertIn(asset["identity_quality"], {"derived"})
            self.assertNotIn(asset["asset_id"], native_ids)
        legacy_envelope = build_envelope(
            tenant_id="1",
            source_type="uptime_kuma",
            instance_id="kuma-legacy",
            generated_at="2026-08-21T15:00:02Z",
            run_id=RUN_ID,
            run_status="completed",
            started_at="2026-08-21T15:00:00Z",
            ended_at="2026-08-21T15:00:02Z",
            collection_window_start="2026-08-21T15:00:00Z",
            collection_window_end="2026-08-21T15:00:02Z",
            assets=other_assets,
            records=other_records,
        )
        schema_utils.validator_for(self.schemas, "envelope.schema.json").validate(
            legacy_envelope
        )
        self.assertEqual(validation.validate_envelope(legacy_envelope), [])


if __name__ == "__main__":
    unittest.main()
