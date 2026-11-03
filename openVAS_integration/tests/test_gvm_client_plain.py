import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


OPENVAS_DIR = Path(__file__).resolve().parents[1]
if str(OPENVAS_DIR) not in sys.path:
    sys.path.insert(0, str(OPENVAS_DIR))

from gvm_client import GVMClient, _merge_report_pages  # noqa: E402


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
        elif "<get_reports" in text:
            self._recv_buffer = b'<get_reports_response status="200" status_text="OK"><report id="r-1"/></get_reports_response>'
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
    assert "get_reports_response" in report_xml
    assert any("<authenticate>" in payload for payload in fake_socket.sent_payloads)
    assert any("<get_reports " in payload for payload in fake_socket.sent_payloads)


class _FakePlainSocketLegacyFallback(_FakePlainSocket):
    def sendall(self, payload: bytes):
        text = payload.decode("utf-8")
        self.sent_payloads.append(text)
        if "<get_version/>" in text:
            self._recv_buffer = b'<get_version_response status="200" status_text="OK"><version>22.7</version></get_version_response>'
        elif "<authenticate>" in text:
            self._recv_buffer = b'<authenticate_response status="200" status_text="OK"/>'
        elif "<get_tasks/>" in text:
            self._recv_buffer = b'<get_tasks_response status="200" status_text="OK"><task id="t-1"/></get_tasks_response>'
        elif "<get_reports" in text:
            self._recv_buffer = b'<gmp_response status="400" status_text="Bogus command name"/>'
        elif "<get_report" in text:
            self._recv_buffer = b'<get_report_response status="200" status_text="OK"><report id="r-1"/></get_report_response>'
        else:
            self._recv_buffer = b'<error_response status="400" status_text="BAD"/>'


def test_plain_transport_falls_back_to_legacy_get_report(monkeypatch):
    fake_socket = _FakePlainSocketLegacyFallback()
    monkeypatch.setenv("GVM_ALLOW_PLAIN_TCP", "true")

    def _fake_create_connection(addr, timeout=0):
        _ = addr, timeout
        return fake_socket

    monkeypatch.setattr("socket.create_connection", _fake_create_connection)

    with GVMClient("10.0.0.1", 41000, "admin", "secret", transport="plain", timeout=10) as client:
        report_xml = client.get_report("r-1")

    assert "get_report_response" in report_xml
    assert any("<get_reports " in payload for payload in fake_socket.sent_payloads)
    assert any("<get_report " in payload for payload in fake_socket.sent_payloads)


def test_plain_transport_requires_explicit_allow_flag(monkeypatch):
    monkeypatch.delenv("GVM_ALLOW_PLAIN_TCP", raising=False)

    with pytest.raises(RuntimeError, match="GVM_ALLOW_PLAIN_TCP=true"):
        with GVMClient("10.0.0.1", 41000, "admin", "secret", transport="plain", timeout=10):
            pass


class _FakePagedSocket(_FakePlainSocket):
    """Responde <get_reports> paginado según rows/first del filtro.

    total_results: cantidad global de resultados que "existen" en GVM.
    """

    def __init__(self, total_results=73, page_size=25):
        super().__init__()
        self.total_results = total_results
        self.report_requests = []
        self.report_page_size = page_size

    def sendall(self, payload: bytes):
        text = payload.decode("utf-8")
        self.sent_payloads.append(text)
        if "<get_version/>" in text:
            self._recv_buffer = b'<get_version_response status="200" status_text="OK"><version>22.7</version></get_version_response>'
        elif "<authenticate>" in text:
            self._recv_buffer = b'<authenticate_response status="200" status_text="OK"/>'
        elif "<get_tasks/>" in text:
            self._recv_buffer = b'<get_tasks_response status="200" status_text="OK"><task id="t-1"/></get_tasks_response>'
        elif "<get_reports" in text:
            self.report_requests.append(text)
            m_first = re.search(r"filter=[\"']rows=\d+ first=(\d+)", text)
            m_rows = re.search(r"filter=[\"']rows=(\d+) first=", text)
            first = int(m_first.group(1)) if m_first else 1
            rows = int(m_rows.group(1)) if m_rows else self.report_page_size

            start = first - 1
            if start >= self.total_results:
                on_page = 0
            else:
                on_page = min(rows, self.total_results - start)

            results_xml = ""
            for i in range(on_page):
                idx = start + i
                results_xml += (
                    f"<result id=\"r-{idx}\">"
                    f"<name>Vuln {idx}</name>"
                    f"<severity>{(10 - (idx % 10))}.0</severity>"
                    f"<host>10.0.0.{idx % 250}</host>"
                    "<nvt oid=\"1.3.6.1.4.1.25623.1.0.1\">"
                    f"<ref type=\"cve\" id=\"CVE-2024-{idx + 1000}\"/>"
                    "</nvt>"
                    "</result>"
                )
            self._recv_buffer = (
                f'<get_reports_response status="200" status_text="OK">'
                f'<report id="r-1"><results>{results_xml}</results></report>'
                f"</get_reports_response>"
            ).encode("utf-8")
        elif "<get_report" in text:
            self._recv_buffer = b'<get_report_response status="200" status_text="OK"><report id="r-1"/></get_report_response>'
        else:
            self._recv_buffer = b'<error_response status="400" status_text="BAD"/>'


def _client_with_paged_socket(monkeypatch, fake_socket):
    monkeypatch.setenv("GVM_ALLOW_PLAIN_TCP", "true")

    def _fake_create_connection(addr, timeout=0):
        _ = addr, timeout
        return fake_socket

    monkeypatch.setattr("socket.create_connection", _fake_create_connection)
    return fake_socket


def test_plain_pagination_merges_all_pages(monkeypatch):
    fake_socket = _FakePagedSocket(total_results=73)
    _client_with_paged_socket(monkeypatch, fake_socket)
    monkeypatch.setenv("GVM_PAGINATE_REPORT", "true")
    monkeypatch.setenv("GVM_REPORT_PAGE_SIZE", "25")

    with GVMClient("10.0.0.1", 41000, "admin", "secret", transport="plain", timeout=10) as client:
        report_xml = client.get_report("r-1")

    # 73 resultados en páginas de 25 -> first=1, 26, 51 (última incompleta) => 3 peticiones
    assert len(fake_socket.report_requests) == 3
    assert "first=1 " in fake_socket.report_requests[0]
    assert "first=26 " in fake_socket.report_requests[1]
    assert "first=51 " in fake_socket.report_requests[2]

    assert report_xml.count("<result ") == 73
    assert "Vuln 0" in report_xml
    assert "Vuln 72" in report_xml
    assert client.pagination_stats["enabled"] is True
    assert client.pagination_stats["pages"] == 3
    assert client.pagination_stats["results_fetched"] == 73


def test_plain_pagination_off_single_request(monkeypatch):
    fake_socket = _FakePagedSocket(total_results=500)
    _client_with_paged_socket(monkeypatch, fake_socket)
    monkeypatch.delenv("GVM_PAGINATE_REPORT", raising=False)

    with GVMClient("10.0.0.1", 41000, "admin", "secret", transport="plain", timeout=10) as client:
        report_xml = client.get_report("r-1")

    assert len(fake_socket.report_requests) == 1
    assert client.pagination_stats["enabled"] is False
    assert client.pagination_stats["pages"] == 1
    # sin paginar: una sola página (rows efectivo = top_n*5 >= 250) de 500
    assert report_xml.count("<result ") == 250
    assert client.pagination_stats["results_fetched"] == 250


def test_plain_pagination_stops_when_page_incomplete(monkeypatch):
    fake_socket = _FakePagedSocket(total_results=62)
    _client_with_paged_socket(monkeypatch, fake_socket)
    monkeypatch.setenv("GVM_PAGINATE_REPORT", "true")
    monkeypatch.setenv("GVM_REPORT_PAGE_SIZE", "25")

    with GVMClient("10.0.0.1", 41000, "admin", "secret", transport="plain", timeout=10) as client:
        report_xml = client.get_report("r-1")

    # 62 = 25 + 25 + 12 -> 3 peticiones, no más
    assert len(fake_socket.report_requests) == 3
    assert report_xml.count("<result ") == 62
    assert client.pagination_stats["results_fetched"] == 62


def test_plain_pagination_max_pages_guard(monkeypatch):
    fake_socket = _FakePagedSocket(total_results=5000)
    _client_with_paged_socket(monkeypatch, fake_socket)
    monkeypatch.setenv("GVM_PAGINATE_REPORT", "true")
    monkeypatch.setenv("GVM_REPORT_PAGE_SIZE", "25")
    monkeypatch.setenv("GVM_MAX_PAGES", "3")

    with GVMClient("10.0.0.1", 41000, "admin", "secret", transport="plain", timeout=10) as client:
        with pytest.raises(RuntimeError, match="GVM_MAX_PAGES=3"):
            client.get_report("r-1")

    assert len(fake_socket.report_requests) == 3
    assert client.pagination_stats["results_fetched"] == 75


def test_merge_report_pages_namespaced_variants():
    page1 = (
        '<get_report_response xmlns="urn:gmp">'
        '<report id="r-1"><results>'
        '<result id="r-0"><name>A</name></result>'
        "</results></report>"
        "</get_report_response>"
    )
    page2 = (
        '<get_reports_response xmlns="urn:gmp">'
        '<report id="r-1"><results>'
        '<result id="r-1"><name>B</name></result>'
        "</results></report>"
        "</get_reports_response>"
    )
    merged = _merge_report_pages([page1, page2])
    # namespace preservado; ambos resultados conservados en el XML final
    assert "urn:gmp" in merged
    assert "<name>A</name>" in merged
    assert "<name>B</name>" in merged
    # sin namespace: ET serializa elementos anexados con el prefijo declarado
    root = ET.fromstring(merged)
    names = [el.text for el in root.iter() if el.tag in {"name", "}name"} or el.tag.endswith("}name")]
    assert sorted(names) == ["A", "B"]


def test_merge_report_pages_empty_and_single():
    assert _merge_report_pages([]) == ""
    single = "<x><results><result/></results></x>"
    assert _merge_report_pages([single]) == single
