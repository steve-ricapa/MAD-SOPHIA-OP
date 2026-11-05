import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "audit_storage.py"
spec = importlib.util.spec_from_file_location("mad_readonly_storage_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def test_inventory_classifies_protected_and_historical_files_without_reading_contents(tmp_path, monkeypatch):
    now = 100 * 86400
    samples = {
        "runtime/nessus/queue/delivery-v2/nessus.json": ("protected_delivery_or_queue", True),
        "runtime/nessus/queue/dead-letter/pending.json": ("protected_delivery_or_queue", True),
        "runtime/nessus/state.json": ("protected_state", True),
        "state/agent_state.db": ("protected_state", False),
        "state/agent_state.db-wal": ("protected_state", False),
        "runtime/wazuh/artifacts/raw_batches/raw_old.json": ("legacy_wazuh_history_review_only", True),
        "runtime/openvas/artifacts/reports/old/payload.json": ("legacy_openvas_history_review_only", True),
        "runtime/nessus/.mad-archive-v1/nessus/entry/payload.json": ("managed_diagnostics", False),
        "runtime/payload_debug/nessus/payload_old.json": ("legacy_debug_history_review_only", True),
        "runtime/logs/zabbix.log.2": ("rotated_logs_review_only", True),
        "runtime/logs/nessus.log": ("current_logs", False),
        "runtime/uptimekuma/last_payload_sent.json": ("latest_diagnostic_copy", False),
    }
    expected_bytes = {}; expected_old = {}
    before = {}
    for index, (relative, (category, old)) in enumerate(samples.items()):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        value = ("DO-NOT-PRINT-CONTENT-" + str(index)).encode()
        path.write_bytes(value)
        os.utime(path, (now - (31 if old else 1) * 86400,) * 2)
        expected_bytes[category] = expected_bytes.get(category, 0) + len(value)
        expected_old[category] = expected_old.get(category, 0) + (len(value) if old else 0)
        before[path] = (value, path.stat().st_mtime_ns)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Inventory must not open payload contents")

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_text", forbidden)
        patch.setattr(Path, "read_bytes", forbidden)
        report = audit.inventory(tmp_path, older_than_days=30, now=now)
    assert report["read_only"] is True
    assert report["skipped"] == 0
    assert sum(group["files"] for group in report["groups"]) == len(samples)
    for category, count in expected_bytes.items():
        assert sum(group["bytes"] for group in report["groups"] if group["category"] == category) == count
        assert sum(group["older_than_days_bytes"] for group in report["groups"] if group["category"] == category) == expected_old[category]
    assert all(group["safe_to_delete"] is False for group in report["groups"])
    assert "DO-NOT-PRINT-CONTENT" not in json.dumps(report)
    assert {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in before} == before


@pytest.mark.parametrize("days", [0, -1])
def test_invalid_age_is_rejected(tmp_path, days):
    with pytest.raises(ValueError, match="positive"):
        audit.inventory(tmp_path, older_than_days=days)


def test_inventory_does_not_follow_symlink_files_or_directories(tmp_path):
    repo = tmp_path / "repo"
    runtime = repo / "runtime"
    runtime.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    valuable = outside / "valuable.json"
    valuable.write_text("important", encoding="utf-8")
    try:
        (runtime / "linked-file.json").symlink_to(valuable)
        (runtime / "linked-dir").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation unavailable")
    before = valuable.read_bytes()
    report = audit.inventory(repo)
    assert report["groups"] == []
    assert report["skipped"] >= 1
    assert valuable.read_bytes() == before


def test_cli_prints_read_only_inventory_without_mutation(tmp_path, monkeypatch, capsys):
    path = tmp_path / "runtime" / "state.json"
    path.parent.mkdir()
    path.write_text('{"pending": true}', encoding="utf-8")
    before = path.read_bytes()
    monkeypatch.setattr(sys, "argv", ["audit_storage.py", "--repo", str(tmp_path), "--older-than-days", "7"])
    audit.main()
    result = json.loads(capsys.readouterr().out)
    assert result["read_only"] is True
    assert result["older_than_days"] == 7
    assert result["groups"][0]["category"] == "protected_state"
    assert path.read_bytes() == before
