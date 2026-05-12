import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app  # noqa: E402


def test_detect_critical_execution_error_cycle_task():
    output = "ERROR @ cycle.task[3].process\nTipo: RuntimeError"
    is_critical, code = app._detect_critical_execution_error(output)
    assert is_critical is True
    assert code == "cycle_task_error"


def test_normalize_openvas_transport_alias_tcp_to_plain():
    transport = app._normalize_openvas_transport("tcp", "")
    assert transport == "plain"


def test_normalize_openvas_transport_default_unix_when_socket_present():
    transport = app._normalize_openvas_transport("", "/run/gvmd/gvmd.sock")
    assert transport == "unix"
