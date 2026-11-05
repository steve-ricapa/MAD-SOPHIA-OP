"""Offline checks for durable OpenVAS delivery across independent process runs."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import runpy
import sys
import types

import pytest

from mad_common.delivery import DeliveryPolicy

OPENVAS_DIR = Path(__file__).resolve().parents[1]


def _load(monkeypatch, name, filename):
    spec = importlib.util.spec_from_file_location(name, OPENVAS_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def delivery_agent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(str(OPENVAS_DIR))
    for name in ("FORCE_SEND_EVERY_CYCLES", "SNAPSHOT_ALWAYS_SEND", "OPENVAS_FORCE_SEND_EVERY_CYCLES", "OPENVAS_SNAPSHOT_ALWAYS_SEND"):
        monkeypatch.delenv(name, raising=False)
    for name, value in {
        "OPENVAS_COLLECTOR": "gmp", "OPENVAS_OUTPUT_MODE": "http",
        "OPENVAS_ARTIFACTS_DIR": str(tmp_path / "reports"),
        "OPENVAS_STATE_PATH": str(tmp_path / "state.json"),
        "OPENVAS_DELIVERY_MODE": "on_change", "GVM_HOST": "offline.test",
        "GVM_PASSWORD": "test-only", "TXDXAI_COMPANY_ID": "123",
        "TXDXAI_TENANT_ID": "123", "TXDXAI_API_KEY_OPENVAS": "test-only",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *args, **kwargs: False)
    config = _load(monkeypatch, "config", "config.py")
    config.DELIVERY_POLICY = DeliveryPolicy("on_change")
    config.DETAIL_LEVEL = "findings"
    config.DEBUG = False
    config.GVM_TRANSPORT = "tls"
    services = _load(monkeypatch, "services", "services.py")
    _load(monkeypatch, "snapshot", "snapshot.py")

    agent = types.SimpleNamespace(config=config, attempts=[], order=[], outcomes=[], source_failure=False,
                                  reports={"report-1": 7.5, "report-2": 3.0}, root=tmp_path)

    class GVMClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get_tasks(self):
            agent.order.append("tasks")
            if agent.source_failure:
                raise RuntimeError("source unavailable")
            return "<get_tasks_response><tasks>" + "".join(
                f'<task id="task-{report_id}"><name>{report_id}</name><status>Done</status>'
                f'<last_report><report id="{report_id}"/></last_report></task>'
                for report_id in agent.reports
            ) + "</tasks></get_tasks_response>"

        def get_report(self, report_id):
            agent.order.append("report:" + report_id)
            return (f'<get_report_response><report id="{report_id}"><hosts><count>1</count></hosts>'
                    f'<results><result><name>Finding</name><severity>{agent.reports[report_id]}</severity>'
                    '<host>192.0.2.1</host><port>443/tcp</port><nvt oid="1.2.3"/>'
                    '</result></results></report></get_report_response>')

    monkeypatch.setitem(sys.modules, "gvm_client", types.SimpleNamespace(GVMClient=GVMClient))

    def emit(**kwargs):
        payload = json.loads(json.dumps(kwargs["payload"]))
        agent.attempts.append(payload)
        agent.order.append("send:" + payload["scan_id"])
        outcome = agent.outcomes.pop(0) if agent.outcomes else True
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(services, "emit_payload", emit)

    def run():
        monkeypatch.setattr(sys, "argv", ["main.py", "--once"])
        with pytest.raises(SystemExit) as result:
            runpy.run_path(str(OPENVAS_DIR / "main.py"), run_name="__main__")
        return result.value.code

    def state():
        path = tmp_path / "state.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    def journal(report_id):
        directory = hashlib.sha256(report_id.encode()).hexdigest()
        path = tmp_path / "reports" / "delivery-v2" / directory / "openvas.json"
        return json.loads(path.read_text(encoding="utf-8"))

    agent.run, agent.state, agent.journal = run, state, journal
    return agent


def test_pending_is_acknowledged_before_source_failure(delivery_agent):
    agent = delivery_agent
    agent.outcomes = [False, True]
    assert agent.run() == 1
    failed = agent.attempts[0]
    agent.order.clear()
    agent.source_failure = True
    assert agent.run() == 1
    assert agent.order == ["send:report-1", "tasks"]
    assert agent.attempts[-1] == failed
    assert agent.journal("report-1")["pending"] == []
    assert agent.state()["last_idempotency_key"] == failed["idempotency_key"]


def test_partial_failure_preserves_snapshot_and_retries_exact_failed_event(delivery_agent):
    agent = delivery_agent
    (agent.root / "state.json").write_text(json.dumps({"snapshot_signature": "acknowledged-before"}), encoding="utf-8")
    agent.outcomes = [True, False]
    assert agent.run() == 1
    assert agent.state()["snapshot_signature"] == "acknowledged-before"
    assert agent.journal("report-1")["last_delivered_signature"]
    assert agent.journal("report-2")["last_delivered_signature"] is None
    failed = copy.deepcopy(agent.attempts[-1])
    assert agent.run() == 0
    assert len(agent.attempts) == 3
    assert agent.attempts[-1] == failed
    assert agent.state()["snapshot_signature"] != "acknowledged-before"
    assert agent.journal("report-2")["pending"] == []


def test_unchanged_contents_do_not_send_again(delivery_agent):
    agent = delivery_agent
    assert agent.run() == 0
    first = copy.deepcopy(agent.attempts)
    assert agent.run() == 0
    assert agent.attempts == first


def test_sixth_cycle_backup_failure_and_recovery_keep_correct_count(delivery_agent):
    agent = delivery_agent
    agent.config.DELIVERY_POLICY = DeliveryPolicy()
    agent.reports = {"report-1": 7.5}
    assert agent.run() == 0
    for count in range(1, 6):
        assert agent.run() == 0
        assert agent.journal("report-1")["unchanged_cycles"] == count
    agent.source_failure = True
    assert agent.run() == 1
    assert agent.journal("report-1")["unchanged_cycles"] == 5
    agent.source_failure = False
    agent.outcomes = [False]
    assert agent.run() == 1
    assert len(agent.attempts) == 2
    assert agent.attempts[-1]["scan_summary"]["meta"]["send_reason"] == "backup_cycle"
    assert agent.journal("report-1")["unchanged_cycles"] == 6
    assert agent.run() == 0
    assert len(agent.attempts) == 3
    assert agent.attempts[-1] == agent.attempts[-2]
    assert agent.journal("report-1")["unchanged_cycles"] == 0
    assert agent.run() == 0
    assert agent.journal("report-1")["unchanged_cycles"] == 1


def test_same_report_id_with_changed_material_fields_creates_event(delivery_agent):
    agent = delivery_agent
    assert agent.run() == 0
    first = copy.deepcopy(agent.attempts[0])
    agent.reports["report-1"] = 10.0
    assert agent.run() == 0
    assert len(agent.attempts) == 3
    changed = agent.attempts[-1]
    assert changed["scan_id"] == first["scan_id"]
    assert changed["idempotency_key"] != first["idempotency_key"]
    assert changed["scan_summary"]["results"] != first["scan_summary"]["results"]


@pytest.mark.parametrize("collector,output_mode", [("gmp", "console"), ("simulated", "http")])
def test_preview_modes_do_not_create_acknowledged_journal(delivery_agent, collector, output_mode):
    agent = delivery_agent
    agent.config.COLLECTOR = collector
    agent.config.OUTPUT_MODE = output_mode
    assert agent.run() == 0
    state = agent.state()
    assert not state.get("has_sent_once")
    assert not state.get("snapshot_signature")
    assert not state.get("last_sent_at")
    assert not list((agent.root / "reports" / "delivery-v2").glob("*/openvas.json"))
