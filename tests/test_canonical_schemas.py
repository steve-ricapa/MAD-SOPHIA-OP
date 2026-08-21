import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas" / "v1"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "canonical" / "v1"


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


class CanonicalSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = {
            path.name: load_json(path)
            for path in SCHEMA_DIR.glob("*.schema.json")
        }
        resources = [
            (schema["$id"], Resource.from_contents(schema))
            for schema in cls.schemas.values()
        ]
        cls.registry = Registry().with_resources(resources)
        cls.format_checker = FormatChecker()

    def validator(self, schema_name: str) -> Draft202012Validator:
        return Draft202012Validator(
            self.schemas[schema_name],
            registry=self.registry,
            format_checker=self.format_checker,
        )

    def test_all_schemas_are_valid_draft_2020_12(self) -> None:
        for name, schema in self.schemas.items():
            with self.subTest(schema=name):
                Draft202012Validator.check_schema(schema)

    def test_uptime_kuma_envelope_is_valid(self) -> None:
        envelope = load_json(FIXTURE_DIR / "uptime-kuma-envelope.json")
        self.validator("envelope.schema.json").validate(envelope)

    def test_finding_and_detection_are_valid(self) -> None:
        cases = (
            ("finding.schema.json", "finding.json"),
            ("detection.schema.json", "detection.json"),
        )
        for schema_name, fixture_name in cases:
            with self.subTest(schema=schema_name):
                self.validator(schema_name).validate(load_json(FIXTURE_DIR / fixture_name))

    def test_envelope_rejects_transport_credentials(self) -> None:
        envelope = load_json(FIXTURE_DIR / "uptime-kuma-envelope.json")
        envelope["api_key"] = "must-not-enter-business-payload"

        with self.assertRaises(ValidationError):
            self.validator("envelope.schema.json").validate(envelope)

    def test_observation_rejects_null_source_event_time(self) -> None:
        envelope = load_json(FIXTURE_DIR / "uptime-kuma-envelope.json")
        observation = copy.deepcopy(envelope["records"][0])
        observation["source_event_time"] = None

        with self.assertRaises(ValidationError):
            self.validator("observation.schema.json").validate(observation)

    def test_zero_measurement_is_distinct_from_absence(self) -> None:
        envelope = load_json(FIXTURE_DIR / "uptime-kuma-envelope.json")
        observation = copy.deepcopy(envelope["records"][0])
        observation["measurements"] = [
            {"name": "response_time", "value": 0, "unit": "ms"}
        ]
        self.validator("observation.schema.json").validate(observation)

        del observation["measurements"]
        self.validator("observation.schema.json").validate(observation)

    def test_unknown_observation_property_is_rejected(self) -> None:
        envelope = load_json(FIXTURE_DIR / "uptime-kuma-envelope.json")
        observation = copy.deepcopy(envelope["records"][0])
        observation["raw"] = {"unbounded": True}

        with self.assertRaises(ValidationError):
            self.validator("observation.schema.json").validate(observation)


if __name__ == "__main__":
    unittest.main()
