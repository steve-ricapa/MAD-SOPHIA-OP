import json
import pytest
import sys
from pathlib import Path
from urllib3.exceptions import ReadTimeoutError


for _module_name in ("services", "snapshot", "gvm_client", "config"):
    sys.modules.pop(_module_name, None)

OPENVAS_DIR = Path(__file__).resolve().parents[1]
if str(OPENVAS_DIR) not in sys.path:
    sys.path.insert(0, str(OPENVAS_DIR))

import services
from services import emit_payload, extract_findings, extract_report_stats, map_status

def test_status():
    assert map_status("Running") == "running"
    assert map_status("Pending") == "pending"
    assert map_status("Done") == "completed"
    assert map_status("Completed") == "completed"


class _Response:
    def __init__(self, status_code, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_emit_payload_requests_upload_url_then_puts_snapshot(monkeypatch):
    calls = {"post": None, "put": None}

    def _post(url, json, headers, timeout, verify):
        calls["post"] = {
            "url": url,
            "json": json,
            "headers": headers,
            "timeout": timeout,
            "verify": verify,
        }
        return _Response(200, payload={"upload_url": "https://s3.example/upload"})

    def _put(url, data, headers, timeout, verify):
        calls["put"] = {
            "url": url,
            "data": data,
            "headers": headers,
            "timeout": timeout,
            "verify": verify,
        }
        return _Response(200)

    monkeypatch.setattr("services.requests.post", _post)
    monkeypatch.setattr("services.requests.put", _put)
    monkeypatch.setenv("BACKEND_TLS_VERIFY", "false")

    ok = emit_payload(
        output_mode="http",
        url="https://api.example/scans/upload-url",
        api_key="agent-key",
        tenant_id=9,
        company_id=4,
        payload={"scan_id": "OV-1", "scanner_type": "openvas", "idempotency_key": "sha256:abc", "findings": []},
        timeout=12,
    )

    assert ok is True
    assert calls["post"]["url"] == "https://api.example/scans/upload-url"
    assert calls["post"]["json"] == {
        "tenant_id": 9,
        "api_key": "agent-key",
        "scanner_type": "openvas",
        "idempotency_key": "sha256:abc",
    }
    assert calls["put"]["url"] == "https://s3.example/upload"
    assert calls["put"]["headers"] == {"Content-Type": "application/json"}
    assert b'"scan_id":"OV-1"' in calls["put"]["data"]


_ONE_REPORT_XML = (
    '<get_reports_response status="200" status_text="OK">'
    '<report id="r-1"><hosts><count>2</count></hosts><vulns><count>3</count></vulns>'
    "<results>"
    '<result><name>A</name><severity>9.2</severity><host>10.0.0.1</host></result>'
    '<result><name>B</name><severity>7.1</severity><host>10.0.0.2</host></result>'
    '<result><name>C</name><severity>5.0</severity><host>10.0.0.3</host></result>'
    "</results></report>"
    "</get_reports_response>"
)


def test_extract_report_stats_include_results_in_xml():
    stats = extract_report_stats(_ONE_REPORT_XML)
    assert stats["hosts_count"] == 2
    assert stats["vulns_count"] == 3
    assert stats["results_in_xml"] == 3


def test_extract_findings_top_n_zero_returns_all():
    out = extract_findings(_ONE_REPORT_XML, top_n=0)
    assert len(out) == 3
    assert out[0]["cvss"] == 9.2


def test_extract_findings_top_n_caps_results():
    out = extract_findings(_ONE_REPORT_XML, top_n=2)
    assert len(out) == 2
    assert out[0]["cvss"] == 9.2
    assert out[1]["cvss"] == 7.1


def test_extract_findings_preserves_all_cves_and_uses_null_without_cve():
    xml = (
        '<get_reports_response><report><results>'
        '<result><name>Multi CVE</name><severity>8.0</severity><host>10.0.0.1</host>'
        '<nvt><ref type="cve" id="CVE-2024-0001"/><ref type="cve" id="CVE-2024-0002"/>'
        '<cve>CVE-2024-0002, CVE-2024-0003</cve></nvt></result>'
        '<result><name>No CVE</name><severity>2.0</severity><host>10.0.0.2</host>'
        '<nvt><cve>No CVE assigned</cve></nvt></result>'
        '</results></report></get_reports_response>'
    )
    diagnostics = []
    out = extract_findings(xml, top_n=0, diagnostics=diagnostics)
    multi = next(item for item in out if item["name"] == "Multi CVE")
    no_cve = next(item for item in out if item["name"] == "No CVE")
    assert multi["cve"] == "CVE-2024-0001"
    assert multi["cves"] == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
    assert no_cve["cve"] is None
    assert no_cve["cves"] == []
    assert diagnostics == []


def test_state_roundtrip_preserves_snapshot_metadata(tmp_path):
    state = {
        "sent": {" report-1 ": "12", "report-2": "invalid", "": 1},
        "snapshot_signature": "signature-1",
        "has_sent_once": True,
        "unchanged_cycles": 3,
        "last_send_result": "sent",
        "last_sent_at": "2026-10-12T23:02:54+00:00",
    }
    target = tmp_path / "state.json"

    services.save_state(str(target), state)
    restored = services.load_state(str(target))

    assert restored == {**state, "sent": {"report-1": 12, "report-2": 0}}
    assert state["sent"] == {" report-1 ": "12", "report-2": "invalid", "": 1}
    assert not target.with_suffix(".json.tmp").exists()



@pytest.mark.parametrize("operation", ["open", "replace"])
def test_save_state_permission_failure_preserves_original_error_and_target(
    tmp_path, monkeypatch, operation
):
    target = tmp_path / "state.json"
    original = json.dumps({"sent": {"old-report": 1}, "snapshot_signature": "old"})
    target.write_text(original, encoding="utf-8")
    error = PermissionError("state storage denied")

    def denied(*args, **kwargs):
        raise error

    if operation == "open":
        monkeypatch.setattr(services, "open", denied, raising=False)
    else:
        monkeypatch.setattr(services.os, "replace", denied)

    with pytest.raises(PermissionError) as raised:
        services.save_state(str(target), {"sent": {"new-report": 2}})

    assert raised.value is error
    assert target.read_text(encoding="utf-8") == original
    assert not target.with_suffix(".json.tmp").exists()



def test_load_state_permission_failure_returns_empty_state(tmp_path, monkeypatch, capsys):
    target = tmp_path / "state.json"
    target.write_text('{"sent": {"old-report": 1}}', encoding="utf-8")

    def denied(*args, **kwargs):
        raise PermissionError("state read denied")

    monkeypatch.setattr(services, "open", denied, raising=False)

    assert services.load_state(str(target)) == {"sent": {}}
    assert "PermissionError" in capsys.readouterr().out



def test_purge_sent_failure_uses_fallback_without_masking_error(capsys):
    assert services.purge_sent({"report-1": "12"}, max_age_days="invalid") == {
        "report-1": 12
    }
    assert "ValueError" in capsys.readouterr().out



def test_extract_severities_preserves_original_generic_error(monkeypatch):
    error = RuntimeError("XML size limit exceeded")

    def failed_parse(*args, **kwargs):
        raise error

    monkeypatch.setattr(services, "_parse_xml", failed_parse)

    with pytest.raises(RuntimeError) as raised:
        services.extract_severities("<report/>")

    assert raised.value is error


_SIGNED_UPLOAD_URL = (
    "https://s3.example/pending/7/snapshot.json"
    "?X-Amz-Signature=SIGNATURE_SENTINEL&X-Amz-Security-Token=TOKEN_SENTINEL"
)


def _upload_with_put_responses(monkeypatch, responses):
    calls = {"post": [], "put": [], "sleep": []}

    def post(*args, **kwargs):
        calls["post"].append((args, kwargs))
        return _Response(200, payload={"upload_url": _SIGNED_UPLOAD_URL})

    def put(*args, **kwargs):
        calls["put"].append((args, kwargs))
        result = responses[len(calls["put"]) - 1]
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr(services.requests, "post", post)
    monkeypatch.setattr(services.requests, "put", put)
    monkeypatch.setattr(services.time, "sleep", calls["sleep"].append)
    monkeypatch.setenv("OPENVAS_PAYLOAD_DEBUG", "false")
    return calls


def _emit_test_snapshot():
    return services.emit_payload(
        output_mode="http", url="https://backend.example/scans/upload-url",
        api_key="test-agent-key", tenant_id=7, company_id=7,
        payload={"scan_id": "report-1", "scanner_type": "openvas",
                 "idempotency_key": "sha256:unchanged", "findings": []},
    )


def test_s3_put_connection_failure_retries_same_signed_url_body_and_key(monkeypatch):
    calls = _upload_with_put_responses(monkeypatch, [
        services.requests.exceptions.ConnectionError("temporary DNS failure"), _Response(200),
    ])

    assert _emit_test_snapshot() is True
    assert len(calls["post"]) == 1
    assert len(calls["put"]) == 2
    assert calls["put"][0] == calls["put"][1]
    assert calls["put"][0][0] == (_SIGNED_UPLOAD_URL,)
    assert b'"idempotency_key":"sha256:unchanged"' in calls["put"][0][1]["data"]
    assert calls["sleep"] == [0.5]


def test_s3_put_connection_failure_stops_after_three_attempts(monkeypatch, capsys):
    error = services.requests.exceptions.ConnectionError(
        "Max retries exceeded with url: " + _SIGNED_UPLOAD_URL
    )
    calls = _upload_with_put_responses(monkeypatch, [error, error, error])

    assert _emit_test_snapshot() is False
    assert len(calls["post"]) == 1
    assert len(calls["put"]) == 3
    assert calls["put"][0] == calls["put"][1] == calls["put"][2]
    assert calls["sleep"] == [0.5, 1.0]
    output = capsys.readouterr().out
    assert "SIGNATURE_SENTINEL" not in output
    assert "TOKEN_SENTINEL" not in output


@pytest.mark.parametrize("result", [
    _Response(403),
    services.requests.exceptions.SSLError("certificate verification failed"),
    services.requests.exceptions.ReadTimeout("read timed out"),
])
def test_s3_put_does_not_retry_http_tls_or_read_timeout(monkeypatch, result):
    calls = _upload_with_put_responses(monkeypatch, [result])

    assert _emit_test_snapshot() is False
    assert len(calls["post"]) == 1
    assert len(calls["put"]) == 1
    assert calls["sleep"] == []


def test_upload_url_post_connection_failure_is_not_retried(monkeypatch):
    calls = _upload_with_put_responses(monkeypatch, [])

    def failed_post(*args, **kwargs):
        calls["post"].append((args, kwargs))
        raise services.requests.exceptions.ConnectionError("temporary DNS failure")

    monkeypatch.setattr(services.requests, "post", failed_post)

    assert _emit_test_snapshot() is False
    assert len(calls["post"]) == 1
    assert calls["put"] == []
    assert calls["sleep"] == []


@pytest.mark.parametrize("debug", [False, True])
def test_format_exception_redacts_full_and_relative_signed_queries(monkeypatch, debug):
    monkeypatch.setattr(services, "DEBUG", debug)
    relative_url = "/pending/7/snapshot.json?X-Amz-Signature=RELATIVE_SIGNATURE&token=RELATIVE_TOKEN"
    try:
        try:
            raise RuntimeError("original request " + _SIGNED_UPLOAD_URL)
        except RuntimeError as cause:
            raise services.requests.exceptions.ConnectionError("failed request " + relative_url) from cause
    except services.requests.exceptions.ConnectionError as error:
        output = services.format_exception("signed.request", error,
                                           {"absolute": _SIGNED_UPLOAD_URL, "relative": relative_url})

    for secret in ("SIGNATURE_SENTINEL", "TOKEN_SENTINEL", "RELATIVE_SIGNATURE", "RELATIVE_TOKEN"):
        assert secret not in output
    assert "s3.example/pending/7/snapshot.json" in output
    assert "/pending/7/snapshot.json" in output
    assert ("Stacktrace:" in output) is debug


@pytest.mark.parametrize("wrapper_location", ["args", "cause", "context"])
def test_s3_put_does_not_retry_wrapped_urllib3_read_timeout(monkeypatch, wrapper_location):
    timeout = ReadTimeoutError(None, "/pending/7/snapshot.json", "response body timed out")
    error = services.requests.exceptions.ConnectionError("wrapped read timeout")
    if wrapper_location == "args":
        error = services.requests.exceptions.ConnectionError(timeout)
    elif wrapper_location == "cause":
        error.__cause__ = timeout
    else:
        error.__context__ = timeout
    calls = _upload_with_put_responses(monkeypatch, [error, _Response(200)])

    assert _emit_test_snapshot() is False
    assert len(calls["post"]) == 1
    assert len(calls["put"]) == 1
    assert calls["sleep"] == []


def test_s3_put_normal_connection_error_with_cycle_still_retries(monkeypatch):
    error = services.requests.exceptions.ConnectionError("temporary DNS failure")
    nested = RuntimeError("nested connection failure")
    error.__cause__ = nested
    nested.__context__ = error
    calls = _upload_with_put_responses(monkeypatch, [error, _Response(200)])

    assert _emit_test_snapshot() is True
    assert len(calls["put"]) == 2
    assert calls["sleep"] == [0.5]


def test_s3_put_deep_error_chain_is_not_retried(monkeypatch):
    error = services.requests.exceptions.ConnectionError("deep connection error")
    nested = error
    for _ in range(40):
        cause = RuntimeError("nested cause")
        nested.__cause__ = cause
        nested = cause
    nested.__cause__ = ReadTimeoutError(None, "/pending/snapshot.json", "read timed out")
    calls = _upload_with_put_responses(monkeypatch, [error, _Response(200)])

    assert _emit_test_snapshot() is False
    assert len(calls["put"]) == 1
    assert calls["sleep"] == []
