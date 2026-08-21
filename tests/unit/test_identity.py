from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from txdx_etl.domain import identity


class AssetIdentityTests(unittest.TestCase):
    def test_format_matches_identifier_pattern(self) -> None:
        value = identity.asset_id("1", "uptime_kuma", "kuma-main", "42")
        self.assertRegex(value, identity.IDENTIFIER_PATTERN)

    def test_golden_vector(self) -> None:
        value = identity.asset_id("1", "uptime_kuma", "kuma-main", "42")
        self.assertEqual(
            value,
            "asset:sha256:acd98f5334adccad627c4a8e38512e4243b8d49350b14ef9e7d2df562f899d82",
        )

    def test_different_tenant_changes_identity(self) -> None:
        base = identity.asset_id("1", "uptime_kuma", "kuma-main", "42")
        other = identity.asset_id("2", "uptime_kuma", "kuma-main", "42")
        self.assertNotEqual(base, other)

    def test_different_instance_changes_identity(self) -> None:
        base = identity.asset_id("1", "uptime_kuma", "kuma-main", "42")
        other = identity.asset_id("1", "uptime_kuma", "kuma-backup", "42")
        self.assertNotEqual(base, other)

    def test_empty_component_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            identity.asset_id("", "uptime_kuma", "kuma-main", "42")


class RecordIdentityTests(unittest.TestCase):
    def test_initial_observation_golden_vector(self) -> None:
        value = identity.record_id(
            "1",
            "uptime_kuma",
            "kuma-main",
            "observation",
            "42",
            {"current_status": "up", "bucket": "2026-08-21T15:00:00Z"},
        )
        self.assertEqual(
            value,
            "record:sha256:c1dca6fef7eefe1e7ae46a4efb02f73734e1042ea5561dd435acd9e30a23494f",
        )

    def test_change_observation_golden_vector(self) -> None:
        value = identity.record_id(
            "1",
            "uptime_kuma",
            "kuma-main",
            "observation",
            "42",
            {
                "previous_status": "down",
                "current_status": "up",
                "event_time": "2026-08-21T14:59:45Z",
            },
        )
        self.assertEqual(
            value,
            "record:sha256:c427ce6017c664338458151001dc93c956186a1714a0f33eee7161d1152c6695",
        )

    def test_same_fact_reextraction_keeps_record_id(self) -> None:
        discriminators = {"current_status": "up", "bucket": "2026-08-21T15:00:00Z"}
        first = identity.record_id(
            "1", "uptime_kuma", "kuma-main", "observation", "42", discriminators
        )
        second = identity.record_id(
            "1", "uptime_kuma", "kuma-main", "observation", "42", dict(discriminators)
        )
        self.assertEqual(first, second)

    def test_status_change_produces_new_record_id(self) -> None:
        up = identity.record_id(
            "1",
            "uptime_kuma",
            "kuma-main",
            "observation",
            "42",
            {"current_status": "up", "bucket": "2026-08-21T15:00:00Z"},
        )
        down = identity.record_id(
            "1",
            "uptime_kuma",
            "kuma-main",
            "observation",
            "42",
            {"current_status": "down", "bucket": "2026-08-21T15:05:00Z"},
        )
        self.assertNotEqual(up, down)

    def test_none_discriminators_are_omitted(self) -> None:
        without = identity.record_id(
            "1",
            "uptime_kuma",
            "kuma-main",
            "observation",
            "42",
            {"previous_status": None},
        )
        plain = identity.record_id(
            "1", "uptime_kuma", "kuma-main", "observation", "42"
        )
        self.assertEqual(without, plain)

    def test_non_string_discriminator_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            identity.record_id(
                "1",
                "uptime_kuma",
                "kuma-main",
                "observation",
                "42",
                {"current_status": 1},
            )


class DeliveryIdentityTests(unittest.TestCase):
    RECORD_IDS = [
        "record:sha256:c1dca6fef7eefe1e7ae46a4efb02f73734e1042ea5561dd435acd9e30a23494f",
        "record:sha256:c427ce6017c664338458151001dc93c956186a1714a0f33eee7161d1152c6695",
    ]

    def test_format_matches_identifier_pattern(self) -> None:
        value = identity.delivery_id(
            "1.0.0", "1", "uptime_kuma", "kuma-main", self.RECORD_IDS
        )
        self.assertRegex(value, identity.IDENTIFIER_PATTERN)
        self.assertTrue(value.startswith(f"{identity.DELIVERY_PREFIX}:"))

    def test_order_is_irrelevant(self) -> None:
        first = identity.delivery_id(
            "1.0.0", "1", "uptime_kuma", "kuma-main", self.RECORD_IDS
        )
        second = identity.delivery_id(
            "1.0.0", "1", "uptime_kuma", "kuma-main", list(reversed(self.RECORD_IDS))
        )
        self.assertEqual(first, second)

    def test_different_records_change_delivery(self) -> None:
        base = identity.delivery_id(
            "1.0.0", "1", "uptime_kuma", "kuma-main", self.RECORD_IDS
        )
        extended = identity.delivery_id(
            "1.0.0",
            "1",
            "uptime_kuma",
            "kuma-main",
            self.RECORD_IDS + ["record:sha256:" + "0" * 64],
        )
        self.assertNotEqual(base, extended)


class RawRecordHashTests(unittest.TestCase):
    def test_format_and_stability(self) -> None:
        payload = {"monitor_id": 42, "status": 1}
        first = identity.raw_record_hash(payload)
        second = identity.raw_record_hash(dict(payload))
        self.assertRegex(first, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(first, second)

    def test_key_order_does_not_matter(self) -> None:
        first = identity.raw_record_hash({"monitor_id": 42, "status": 1})
        second = identity.raw_record_hash({"status": 1, "monitor_id": 42})
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
