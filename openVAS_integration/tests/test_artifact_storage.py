"""Controlled artifact storage uses fake GMP and backend, never external I/O."""
import hashlib
import json
from pathlib import Path
import sys

from openVAS_integration.tests.test_delivery_policy import delivery_agent  # noqa: F401


def entries(root):
    return sorted((Path(root) / ".mad-archive-v1" / "openvas").glob("entry-*"))


def test_default_disables_history_but_keeps_latest_and_receipts(delivery_agent, monkeypatch):
    agent = delivery_agent
    monkeypatch.setenv("MAD_ARCHIVE_ENABLED", "false")
    monkeypatch.setenv("OPENVAS_PAYLOAD_DEBUG", "false")
    assert agent.run() == 0
    assert not Path(agent.config.REPORT_ARTIFACTS_DIR).exists()
    for target in [agent.config.LAST_TASKS_XML_PATH, agent.config.LAST_REPORT_XML_PATH,
                   agent.config.LAST_REPORT_JSON_PATH, agent.config.LAST_PAYLOAD_PATH,
                   agent.config.LAST_DELIVERY_META_PATH]:
        assert Path(target).is_file()
    assert agent.journal("report-1")["last_delivered_at"] is not None
    assert agent.journal("report-1")["pending"] == []
    assert agent.state()["has_sent_once"] is True


def test_enabled_report_bundles_are_bounded_and_legacy_dirs_untouched(delivery_agent, monkeypatch):
    agent = delivery_agent
    monkeypatch.setenv("MAD_ARCHIVE_ENABLED", "true")
    monkeypatch.setenv("MAD_ARCHIVE_MAX_ENTRIES", "1")
    root = Path(agent.config.REPORT_ARTIFACTS_DIR)
    legacy = root / "historical-report" / "report.xml"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("old report evidence", encoding="utf-8")
    assert agent.run() == 0
    bundles = entries(root)
    assert len(bundles) == 1
    bundle = bundles[0]
    assert {p.name for p in bundle.iterdir()} == {"report.xml", "payload.json", "metadata.json", ".entry.json"}
    report_xml = (bundle / "report.xml").read_bytes()
    metadata = json.loads((bundle / "metadata.json").read_text())
    assert metadata["xml_bytes"] == len(report_xml)
    assert metadata["xml_sha256"] == hashlib.sha256(report_xml).hexdigest()
    assert json.loads((bundle / "payload.json").read_text())["scan_id"] == "report-2"
    assert agent.run() == 0  # unchanged source still keeps only one optional diagnostic bundle
    assert len(entries(root)) == 1
    assert entries(root)[0] != bundle
    assert legacy.read_text() == "old report evidence"
    assert len(agent.attempts) == 2


def test_cycle_maintenance_prunes_owned_history_with_no_new_reports(delivery_agent, monkeypatch):
    agent = delivery_agent
    monkeypatch.setenv("MAD_ARCHIVE_ENABLED", "true")
    assert agent.run() == 0
    root = Path(agent.config.REPORT_ARTIFACTS_DIR)
    assert len(entries(root)) == 2
    for bundle in entries(root):
        manifest = bundle / ".entry.json"
        data = json.loads(manifest.read_text())
        data["created_at"] = 0
        manifest.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setenv("MAD_ARCHIVE_ENABLED", "false")
    agent.reports = {}
    assert agent.run() == 0
    assert not entries(root)
    assert agent.journal("report-1")["last_delivered_at"] is not None


def test_explicit_payload_debug_uses_same_bounds_when_normal_history_disabled(delivery_agent, monkeypatch):
    root = delivery_agent.root / "payload-debug"
    monkeypatch.setenv("MAD_ARCHIVE_ENABLED", "false")
    monkeypatch.setenv("MAD_ARCHIVE_MAX_ENTRIES", "1")
    monkeypatch.setenv("OPENVAS_PAYLOAD_DEBUG", "true")
    monkeypatch.setenv("OPENVAS_PAYLOAD_DEBUG_DIR", str(root))
    services = sys.modules["services"]
    services._save_payload_debug({"scan_id": "first"}, 400, "bad input")
    services._save_payload_debug({"scan_id": "second"}, 200, "accepted")
    assert len(entries(root)) == 1
    bundle = entries(root)[0]
    assert json.loads((bundle / "payload.json").read_text())["scan_id"] == "second"
    assert json.loads((bundle / "metadata.json").read_text())["status_code"] == 200
    monkeypatch.setenv("OPENVAS_PAYLOAD_DEBUG", "false")
    services._save_payload_debug({"scan_id": "third"}, 200, "accepted")
    assert entries(root) == [bundle]
