from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from txdx_etl.connectors.uptime_kuma.detector import ChangeDetector
from txdx_etl.connectors.uptime_kuma.parser import parse_metrics
from txdx_etl.pipeline import validation
from txdx_etl.pipeline.envelope import build_envelope

import schema_utils

T0 = "2026-08-21T22:00:00Z"

EMPTY_SUMMARY = {
    "initial": 0,
    "refresh": 0,
    "change": 0,
    "discovered": 0,
    "disappeared": 0,
}


def labels_for(
    name: str,
    mtype: str = "http",
    url: str = '"null"',
    host: str = '"null"',
    port: str = '"null"',
) -> str:
    return (
        f'monitor_name="{name}",monitor_type="{mtype}",monitor_url={url},'
        f'monitor_hostname={host},monitor_port={port}'
    )


def series(family: str, labels: str, value: int) -> str:
    return f"{family}{{{labels}}} {value}\n"


def web_text(status: int = 1) -> str:
    lab = labels_for("web")
    return series("monitor_status", lab, status) + series(
        "monitor_response_time", lab, 120
    )


def db_text(status: int = 1) -> str:
    lab = labels_for("db", mtype="keyword")
    return series("monitor_status", lab, status) + series(
        "monitor_response_time", lab, 40
    )


def https_text(status: int, valid: int, days: int) -> str:
    lab = labels_for("web")
    return (
        series("monitor_status", lab, status)
        + series("monitor_response_time", lab, 100)
        + series("monitor_cert_is_valid", lab, valid)
        + series("monitor_cert_days_remaining", lab, days)
    )


def make_detector(**kwargs) -> ChangeDetector:
    return ChangeDetector(tenant_id="1", instance_id="kuma-lab", **kwargs)


def build_cycle_envelope(run_id: str, cycle, moment: str) -> dict:
    return build_envelope(
        tenant_id="1",
        source_type="uptime_kuma",
        instance_id="kuma-lab",
        display_name="Uptime Kuma laboratorio",
        generated_at=moment,
        run_id=run_id,
        run_status="completed",
        started_at=moment,
        ended_at=moment,
        collection_window_start=moment,
        collection_window_end=moment,
        assets=cycle.assets,
        records=cycle.records,
    )


class DetectorKindTests(unittest.TestCase):
    def test_first_cycle_marks_every_monitor_initial(self) -> None:
        detector = make_detector()
        cycle = detector.process(parse_metrics(web_text() + db_text()), T0)
        expected = dict(EMPTY_SUMMARY, initial=2)
        self.assertEqual(cycle.summary, expected)
        self.assertEqual({r["kind"] for r in cycle.records}, {"initial"})
        self.assertEqual(detector.tracked_count, 2)

    def test_quiet_cycle_within_interval_emits_nothing(self) -> None:
        detector = make_detector()
        detector.process(parse_metrics(web_text()), T0)
        quiet = detector.process(parse_metrics(web_text()), "2026-08-21T22:00:30Z")
        self.assertEqual(quiet.summary, EMPTY_SUMMARY)
        self.assertEqual(quiet.records, [])
        self.assertEqual(quiet.assets, [])

    def test_refresh_after_interval_in_same_bucket_keeps_record_id(self) -> None:
        detector = make_detector(refresh_interval_seconds=60)
        first = detector.process(parse_metrics(web_text()), T0)
        second = detector.process(parse_metrics(web_text()), "2026-08-21T22:01:10Z")
        self.assertEqual(second.summary, dict(EMPTY_SUMMARY, refresh=1))
        self.assertEqual(first.records[0]["record_id"], second.records[0]["record_id"])

    def test_refresh_in_new_bucket_gets_new_record_id(self) -> None:
        detector = make_detector(refresh_interval_seconds=60)
        detector.process(parse_metrics(web_text()), T0)
        second = detector.process(parse_metrics(web_text()), "2026-08-21T22:01:10Z")
        third = detector.process(parse_metrics(web_text()), "2026-08-21T22:05:00Z")
        self.assertNotEqual(
            second.records[0]["record_id"], third.records[0]["record_id"]
        )

    def test_status_change_carries_previous_status(self) -> None:
        detector = make_detector()
        detector.process(parse_metrics(web_text()), T0)
        change = detector.process(parse_metrics(web_text(status=0)), "2026-08-21T22:01:00Z")
        record = change.records[0]
        self.assertEqual(change.summary, dict(EMPTY_SUMMARY, change=1))
        self.assertEqual(record["kind"], "change")
        self.assertEqual(record["status"], "down")
        self.assertEqual(record["previous_status"], "up")


class DetectorCertificateTests(unittest.TestCase):
    def test_change_cycle_with_certificate_series_stays_schema_valid(self) -> None:
        detector = make_detector()
        detector.process(parse_metrics(https_text(1, 1, 90)), T0)
        change = detector.process(parse_metrics(https_text(0, 1, 90)), "2026-08-21T22:01:00Z")
        self.assertEqual(change.summary, dict(EMPTY_SUMMARY, change=1))
        validator = schema_utils.validator_for(
            schema_utils.load_schemas(), "observation.schema.json"
        )
        for record in change.records:
            validator.validate(record)

    def test_certificate_only_change_keeps_availability_as_refresh(self) -> None:
        detector = make_detector()
        detector.process(parse_metrics(https_text(1, 1, 90)), T0)
        cycle = detector.process(parse_metrics(https_text(1, 0, 12)), "2026-08-21T22:01:00Z")
        self.assertEqual(cycle.summary, dict(EMPTY_SUMMARY, refresh=1))
        certificate = next(
            r for r in cycle.records if r["observation_type"] == "certificate"
        )
        self.assertEqual(certificate["status"], "invalid")
        self.assertEqual(certificate["kind"], "refresh")

    def test_quiet_cycle_with_certificate_stays_silent(self) -> None:
        detector = make_detector()
        detector.process(parse_metrics(https_text(1, 1, 90)), T0)
        quiet = detector.process(parse_metrics(https_text(1, 1, 90)), "2026-08-21T22:00:30Z")
        self.assertEqual(quiet.records, [])
        self.assertEqual(quiet.summary, EMPTY_SUMMARY)


class DetectorDisappearanceTests(unittest.TestCase):
    def test_disappearance_requires_three_consecutive_absences(self) -> None:
        detector = make_detector()
        detector.process(parse_metrics(web_text() + db_text()), T0)
        for offset in (1, 2):
            cycle = detector.process(
                parse_metrics(db_text()), f"2026-08-21T22:0{offset}:00Z"
            )
            self.assertEqual(cycle.summary, EMPTY_SUMMARY)
            self.assertEqual(cycle.records, [])
        self.assertEqual(detector.tracked_count, 2)
        gone = detector.process(parse_metrics(db_text()), "2026-08-21T22:03:00Z")
        self.assertEqual(gone.summary, dict(EMPTY_SUMMARY, disappeared=1))
        record = next(
            r
            for r in gone.records
            if r["observation_type"] == "availability" and r["status"] == "absent"
        )
        self.assertEqual(record["kind"], "disappeared")
        self.assertEqual(record["previous_status"], "up")
        self.assertEqual(detector.tracked_count, 1)
        after = detector.process(parse_metrics(db_text()), "2026-08-21T22:04:00Z")
        self.assertEqual(after.summary, EMPTY_SUMMARY)

    def test_reappearance_resets_missing_counter(self) -> None:
        detector = make_detector()
        detector.process(parse_metrics(web_text() + db_text()), T0)
        detector.process(parse_metrics(db_text()), "2026-08-21T22:01:00Z")
        back = detector.process(parse_metrics(web_text() + db_text()), "2026-08-21T22:02:00Z")
        self.assertEqual(back.summary, EMPTY_SUMMARY)
        late = detector.process(parse_metrics(db_text()), "2026-08-21T22:03:00Z")
        self.assertEqual(late.summary, EMPTY_SUMMARY)
        self.assertEqual(late.records, [])

    def test_rediscovery_after_disappearance_uses_discovered_kind(self) -> None:
        detector = make_detector(disappear_after_scrapes=1)
        first = detector.process(parse_metrics(web_text()), T0)
        web_key = first.records[0]["source_object_id"]
        gone = detector.process(parse_metrics(db_text()), "2026-08-21T22:01:00Z")
        self.assertEqual(
            gone.summary, dict(EMPTY_SUMMARY, discovered=1, disappeared=1)
        )
        asset = next(a for a in gone.assets if a["source_asset_id"] == web_key)
        self.assertEqual(asset["first_observed_at"], T0)
        self.assertEqual(asset["last_observed_at"], T0)
        back = detector.process(parse_metrics(web_text() + db_text()), "2026-08-21T22:02:00Z")
        self.assertEqual(back.summary, dict(EMPTY_SUMMARY, discovered=1))
        rediscovered = [
            r
            for r in back.records
            if r["kind"] == "discovered" and r["source_object_id"] == web_key
        ]
        self.assertEqual(len(rediscovered), 1)


class DetectorEnvelopeTests(unittest.TestCase):
    def test_quiet_change_disappearance_heartbeat_validate_end_to_end(self) -> None:
        schemas = schema_utils.load_schemas()
        envelope_validator = schema_utils.validator_for(schemas, "envelope.schema.json")

        def validate(run_id: str, cycle, moment: str, expected_kinds: set[str]) -> dict:
            self.assertEqual({r["kind"] for r in cycle.records}, expected_kinds)
            envelope = build_cycle_envelope(run_id, cycle, moment)
            envelope_validator.validate(envelope)
            self.assertEqual(validation.validate_envelope(envelope), [])
            return envelope

        detector = make_detector(
            disappear_after_scrapes=2, refresh_interval_seconds=300
        )
        envelopes: list[dict] = []

        first = detector.process(parse_metrics(web_text() + db_text()), "2026-08-21T22:00:00Z")
        envelopes.append(
            validate("run:test-det-000000000001", first, "2026-08-21T22:00:00Z", {"initial"})
        )

        quiet = detector.process(parse_metrics(web_text() + db_text()), "2026-08-21T22:01:00Z")
        self.assertEqual(quiet.records, [])
        self.assertEqual(quiet.summary, EMPTY_SUMMARY)

        change = detector.process(parse_metrics(web_text(status=0)), "2026-08-21T22:06:00Z")
        self.assertEqual(change.summary, dict(EMPTY_SUMMARY, change=1))
        envelopes.append(
            validate("run:test-det-000000000002", change, "2026-08-21T22:06:00Z", {"change"})
        )

        gone = detector.process(parse_metrics(web_text(status=0)), "2026-08-21T22:07:00Z")
        self.assertEqual(gone.summary, dict(EMPTY_SUMMARY, disappeared=1))
        envelopes.append(
            validate("run:test-det-000000000003", gone, "2026-08-21T22:07:00Z", {"disappeared"})
        )

        heartbeat = detector.process(parse_metrics(web_text(status=0)), "2026-08-21T22:11:00Z")
        self.assertEqual(heartbeat.summary, dict(EMPTY_SUMMARY, refresh=1))
        last_envelope = validate(
            "run:test-det-000000000004", heartbeat, "2026-08-21T22:11:00Z", {"refresh"}
        )
        envelopes.append(last_envelope)

        serialized = json.dumps(last_envelope, ensure_ascii=False)
        self.assertNotIn('"null"', serialized)
        self.assertNotIn(": null", serialized)
        self.assertEqual(len(envelopes), 4)


if __name__ == "__main__":
    unittest.main()
