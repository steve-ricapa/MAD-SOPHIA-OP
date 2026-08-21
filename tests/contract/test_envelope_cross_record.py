from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from txdx_etl.pipeline import validation

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "canonical" / "v1" / "uptime-kuma-envelope.json"


def load_envelope() -> dict:
    with FIXTURE.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def codes(violations: list[validation.Violation]) -> set[str]:
    return {violation.code for violation in violations}


class CrossRecordValidationTests(unittest.TestCase):
    def test_self_consistent_fixture_has_no_violations(self) -> None:
        envelope = load_envelope()
        self.assertEqual(validation.validate_envelope(envelope), [])

    def test_tampered_delivery_id_is_detected(self) -> None:
        envelope = load_envelope()
        envelope["delivery_id"] = "delivery:sha256:" + "0" * 64
        found = codes(validation.validate_envelope(envelope))
        self.assertIn("delivery.id_mismatch", found)

    def test_dangling_asset_reference_is_detected(self) -> None:
        envelope = load_envelope()
        envelope["records"][0]["asset_id"] = "asset:sha256:" + "f" * 64
        envelope.pop("delivery_id")
        found = codes(validation.validate_envelope(envelope))
        self.assertIn("record.asset_reference_missing", found)

    def test_non_accepted_record_violates_delivery_boundary(self) -> None:
        envelope = load_envelope()
        envelope["records"][0]["decision"]["outcome"] = "rejected"
        envelope["run"]["record_counts"]["accepted"] = 0
        envelope["run"]["record_counts"]["rejected"] = 1
        envelope.pop("delivery_id")
        found = codes(validation.validate_envelope(envelope))
        self.assertIn("boundary.record_not_accepted", found)

    def test_wrong_observation_count_is_detected(self) -> None:
        envelope = load_envelope()
        envelope["run"]["record_counts"]["observations"] = 2
        envelope.pop("delivery_id")
        found = codes(validation.validate_envelope(envelope))
        self.assertIn("counts.observations_mismatch", found)

    def test_wrong_decision_totals_are_detected(self) -> None:
        envelope = load_envelope()
        envelope["run"]["record_counts"]["accepted"] = 2
        envelope.pop("delivery_id")
        found = codes(validation.validate_envelope(envelope))
        self.assertIn("counts.accepted_mismatch", found)
        self.assertIn("counts.total_mismatch", found)

    def test_duplicate_record_id_is_detected(self) -> None:
        envelope = load_envelope()
        duplicate = copy.deepcopy(envelope["records"][0])
        envelope["records"].append(duplicate)
        envelope["run"]["record_counts"]["observations"] = 2
        envelope["run"]["record_counts"]["accepted"] = 2
        envelope.pop("delivery_id")
        found = codes(validation.validate_envelope(envelope))
        self.assertIn("record.duplicate_id", found)

    def test_inverted_run_times_are_detected(self) -> None:
        envelope = load_envelope()
        envelope["run"]["ended_at"] = "2026-08-21T14:59:00Z"
        envelope.pop("delivery_id")
        found = codes(validation.validate_envelope(envelope))
        self.assertIn("run.time_order", found)

    def test_empty_envelope_reports_identity_mismatch(self) -> None:
        envelope: dict = {}
        found = codes(validation.validate_envelope(envelope))
        self.assertIn("delivery.id_mismatch", found)
        self.assertIn("counts.missing", found)


if __name__ == "__main__":
    unittest.main()
