from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parents[1]
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("mad_check_deliveries", SCRIPTS / "check_deliveries.py")
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


@pytest.fixture
def successful_records(tmp_path):
    now = datetime(2026, 11, 2, 16, tzinfo=timezone.utc)
    cfg = {"NESSUS_ARTIFACTS_DIR": "runtime/nessus", "UPTIME_ARTIFACTS_DIR": "runtime/uptimekuma",
           "ZABBIX_ARTIFACTS_DIR": "runtime/zabbix", "OPENVAS_OUTPUT_MODE": "http"}
    paths = checks.resolve_paths(tmp_path, cfg)
    for name, entry in paths.items():
        target = entry["delivery_meta"]
        target.parent.mkdir(parents=True, exist_ok=True)
        data = {"saved_at_utc": now.isoformat(), "scan_id": name + "-scan", "sent": True,
                "queued": False, "delivery_success": True, "status_code": 200,
                "output_mode": "http", "collector": "gmp",
                "delivery_result": {"sent": True, "queued": False}}
        target.write_text(json.dumps(data), encoding="utf-8")
    return tmp_path, cfg, paths, now


def _replace(paths, name, **changes):
    target = paths[name]["delivery_meta"]
    data = json.loads(target.read_text(encoding="utf-8"))
    data.update(changes)
    target.write_text(json.dumps(data), encoding="utf-8")


def _result(fixture, name):
    repo, cfg, paths, now = fixture
    return next(row for row in checks.verify_deliveries(repo, cfg, now - timedelta(minutes=1), now) if row["integration"] == name)


def test_all_six_require_fresh_successful_evidence(successful_records):
    repo, cfg, paths, now = successful_records
    results = checks.verify_deliveries(repo, cfg, now - timedelta(minutes=1), now)
    assert len(results) == 6
    assert all(row["status"] == "PASS" for row in results)


def test_v2_receipt_requires_matching_integration_and_explicit_ack(successful_records):
    _, _, paths, _ = successful_records
    _replace(paths, "nessus", schema_version=2, integration="nessus", mode="webhook",
             sent=True, queued=False, idempotency_key="sha256:abc")
    assert _result(successful_records, "nessus")["status"] == "PASS"

    _replace(paths, "nessus", integration="zabbix")
    assert _result(successful_records, "nessus")["status"] == "FAIL"

    _replace(paths, "nessus", integration="nessus", sent=1)
    assert _result(successful_records, "nessus")["status"] == "FAIL"

    _replace(paths, "nessus", sent=True, queued=True)
    assert _result(successful_records, "nessus")["status"] == "FAIL"


def test_success_receipts_do_not_claim_a_new_upload(successful_records):
    repo, cfg, _, now = successful_records
    results = checks.verify_deliveries(repo, cfg, now - timedelta(minutes=1), now)

    assert all(row["detail"] == "fresh_delivery_or_deduplication_recorded" for row in results)
    assert "fresh_successful_upload" not in json.dumps(results)


def test_cli_discloses_deduplication_and_separate_aws_processing(
    successful_records, monkeypatch, capsys
):
    repo, cfg, _, now = successful_records
    results = checks.verify_deliveries(repo, cfg, now - timedelta(minutes=1), now)
    env = repo / "test.env"
    env.write_text("OUTPUT_MODE=all\n", encoding="utf-8")
    since = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    monkeypatch.setattr(checks, "verify_deliveries", lambda *args: results)
    monkeypatch.setattr(sys, "argv", ["check_deliveries.py", "--env", str(env), "--since", since])

    assert checks.main() == 0
    output = capsys.readouterr().out
    assert "do not distinguish a fresh S3 PUT from HTTP 409 deduplication" in output
    assert "AWS processing must be confirmed separately" in output
    assert "fresh_successful_upload" not in output


def test_old_success_is_not_current_upload(successful_records):
    repo, cfg, paths, now = successful_records
    _replace(paths, "nessus", saved_at_utc=(now - timedelta(days=20)).isoformat())
    assert _result(successful_records, "nessus")["detail"] == "no_delivery_evidence_since_validation_started"


def test_queued_insightvm_is_not_successful_upload(successful_records):
    _, _, paths, _ = successful_records
    _replace(paths, "insightvm", delivery_result={"sent": False, "queued": True})
    assert _result(successful_records, "insightvm")["status"] == "FAIL"


@pytest.mark.parametrize("name,settings,metadata", [
    ("wazuh", {"DRY_RUN": "true"}, {}),
    ("wazuh", {}, {"status_code": None}),
    ("openvas", {"OPENVAS_OUTPUT_MODE": "console"}, {}),
    ("openvas", {}, {"output_mode": "console"}),
    ("openvas", {}, {"collector": "simulated"}),
    ("uptimekuma", {"UPTIME_OUTPUT_MODE": "stdout"}, {}),
])
def test_simulated_success_does_not_prove_delivery(successful_records, name, settings, metadata):
    _, cfg, paths, _ = successful_records
    cfg.update(settings)
    _replace(paths, name, **metadata)
    assert _result(successful_records, name)["status"] == "FAIL"


def test_metadata_contents_are_never_returned_on_error(successful_records):
    _, _, paths, _ = successful_records
    _replace(paths, "zabbix", sent=False, error_body="SECRET-MUST-NOT-APPEAR")
    result = _result(successful_records, "zabbix")
    assert result["status"] == "FAIL"
    assert "SECRET-MUST-NOT-APPEAR" not in json.dumps(result)


def test_shared_metadata_cannot_validate_three_integrations(tmp_path):
    cfg = {"ARTIFACTS_DIR": "artifacts"}
    now = datetime.now(timezone.utc)
    results = checks.verify_deliveries(tmp_path, cfg, now)
    affected = [row for row in results if row["integration"] in {"nessus", "uptimekuma", "zabbix"}]
    assert len(affected) == 3
    assert all(row["detail"] == "shared_delivery_metadata_path" for row in affected)


def test_naive_timestamp_is_rejected():
    with pytest.raises(ValueError):
        checks.timestamp("2026-11-02T16:00:00")
