import sys
from pathlib import Path

import pytest


OPENVAS_DIR = Path(__file__).resolve().parents[1]
if str(OPENVAS_DIR) not in sys.path:
    sys.path.insert(0, str(OPENVAS_DIR))

from gvm_client import GVMClient  # noqa: E402


class _FakePlainSocket:
    def __init__(self):
        self._recv_buffer = b""
        self.sent_payloads: list[str] = []

    def settimeout(self, timeout):
        _ = timeout

    def sendall(self, payload: bytes):
        text = payload.decode("utf-8")
        self.sent_payloads.append(text)
        if "<get_version/>" in text:
            self._recv_buffer = b'<get_version_response status="200" status_text="OK"><version>22.7</version></get_version_response>'
        elif "<authenticate>" in text:
            self._recv_buffer = b'<authenticate_response status="200" status_text="OK"/>'
        elif "<get_tasks/>" in text:
            self._recv_buffer = b'<get_tasks_response status="200" status_text="OK"><task id="t-1"/></get_tasks_response>'
        elif "<get_report" in text:
            self._recv_buffer = b'<get_report_response status="200" status_text="OK"><report id="r-1"/></get_report_response>'
        else:
            self._recv_buffer = b'<error_response status="400" status_text="BAD"/>'

    def recv(self, size: int) -> bytes:
        _ = size
        if not self._recv_buffer:
            return b""
        data = self._recv_buffer
        self._recv_buffer = b""
        return data

    def close(self):
        pass


def test_plain_transport_happy_path(monkeypatch):
    fake_socket = _FakePlainSocket()
    monkeypatch.setenv("GVM_ALLOW_PLAIN_TCP", "true")

    def _fake_create_connection(addr, timeout=0):
        _ = addr, timeout
        return fake_socket

    monkeypatch.setattr("socket.create_connection", _fake_create_connection)

    with GVMClient("10.0.0.1", 41000, "admin", "secret", transport="plain", timeout=10) as client:
        tasks_xml = client.get_tasks()
        report_xml = client.get_report("r-1")

    assert "get_tasks_response" in tasks_xml
    assert "get_report_response" in report_xml
    assert any("<authenticate>" in payload for payload in fake_socket.sent_payloads)


def test_plain_transport_requires_explicit_allow_flag(monkeypatch):
    monkeypatch.delenv("GVM_ALLOW_PLAIN_TCP", raising=False)

    with pytest.raises(RuntimeError, match="GVM_ALLOW_PLAIN_TCP=true"):
        with GVMClient("10.0.0.1", 41000, "admin", "secret", transport="plain", timeout=10):
            pass
