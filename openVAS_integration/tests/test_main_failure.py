import importlib.util
import json
from pathlib import Path
import runpy
import sys

import pytest


OPENVAS_DIR = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("first_result,expected_code", [(False, 1), (RuntimeError("first report failed"), 1), (True, 0)])
def test_one_failed_report_cannot_be_hidden_by_later_success(tmp_path, monkeypatch, first_result, expected_code):
    monkeypatch.syspath_prepend(str(OPENVAS_DIR))
    monkeypatch.chdir(tmp_path)
    for name, value in {
        "OPENVAS_COLLECTOR": "simulated",
        "OPENVAS_OUTPUT_MODE": "console",
        "OPENVAS_ARTIFACTS_DIR": str(tmp_path / "reports"),
        "OPENVAS_STATE_PATH": str(tmp_path / "state.json"),
        "OPENVAS_SNAPSHOT_ALWAYS_SEND": "true",
        "OPENVAS_DEBUG": "false",
    }.items():
        monkeypatch.setenv(name, value)
    # Load the real config under the controlled test environment. No .env or network.
    from dotenv import load_dotenv
    monkeypatch.setattr("dotenv.load_dotenv", lambda *args, **kwargs: False)
    config_spec = importlib.util.spec_from_file_location("config", OPENVAS_DIR / "config.py")
    config = importlib.util.module_from_spec(config_spec)
    monkeypatch.setitem(sys.modules, "config", config)
    config_spec.loader.exec_module(config)

    import services
    calls = []

    def emit(**kwargs):
        calls.append(kwargs["payload"]["scan_id"])
        if len(calls) == 1:
            if isinstance(first_result, Exception):
                raise first_result
            return first_result
        return True

    monkeypatch.setattr(services, "emit_payload", emit)
    monkeypatch.setattr(sys, "argv", ["main.py", "--once"])
    with pytest.raises(SystemExit) as exit_status:
        runpy.run_path(str(OPENVAS_DIR / "main.py"), run_name="__main__")

    assert calls == ["sim-report-1", "sim-report-2"]
    assert exit_status.value.code == expected_code
    # The final receipt succeeds, so the process exit must retain the earlier failure.
    meta = json.loads((tmp_path / "reports" / "last_delivery_meta.json").read_text(encoding="utf-8"))
    assert meta["delivery_success"] is True
    assert meta["collector"] == "simulated"
