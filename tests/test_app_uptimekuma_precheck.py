import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app  # noqa: E402


def _uptime_spec() -> app.AgentSpec:
    return app.AgentSpec(name="uptimekuma", command_builder=lambda p, e: [])


def _base_env() -> dict[str, str]:
    return {
        "TXDXAI_API_KEY_UPTIMEKUMA": "k-up",
        "TXDXAI_INGEST_URL": "https://ingest.local/api/scans/ingest",
        "TXDXAI_COMPANY_ID": "4",
        "UPTIME_KUMA_URL": "http://127.0.0.1:3001",
        "UPTIME_KUMA_METRICS_PATH": "/metrics",
    }


def _mock_network_ok(monkeypatch):
    monkeypatch.setattr(app, "_resolve_dns", lambda host: (["127.0.0.1"], None))
    monkeypatch.setattr(app, "_tcp_probe", lambda host, port, timeout: (True, None, None))


def _phase(phases: list[dict], name: str) -> dict:
    return next(p for p in phases if p.get("phase") == name)


def test_uptimekuma_precheck_uses_api_key_auth(monkeypatch):
    _mock_network_ok(monkeypatch)
    env = _base_env()
    env["UPTIME_KUMA_API_KEY_ID"] = "1"
    env["UPTIME_KUMA_API_KEY"] = "uk-test"
    captured = {"auth": None}

    def _fake_http(method, url, timeout, auth=None, headers=None, json_body=None):
        _ = method, url, timeout, headers, json_body
        captured["auth"] = auth
        return {"ok": True, "status_code": 200, "body_preview": "ok", "error_kind": None, "error_text": None}

    monkeypatch.setattr(app, "_http_probe_detailed", _fake_http)
    result = app.run_agent_precheck_diagnostic(_uptime_spec(), env, timeout_seconds=2)

    assert result.passed is True
    assert _phase(result.phases, "auth")["status"] == "PASS"
    assert _phase(result.phases, "api")["status"] == "PASS"
    assert captured["auth"] == ("1", "uk-test")


def test_uptimekuma_precheck_supports_quoted_api_key_values(monkeypatch):
    _mock_network_ok(monkeypatch)
    env = _base_env()
    env["UPTIME_KUMA_API_KEY_ID"] = "'1'"
    env["UPTIME_KUMA_API_KEY"] = '"uk-quoted"'
    captured = {"auth": None}

    def _fake_http(method, url, timeout, auth=None, headers=None, json_body=None):
        _ = method, url, timeout, headers, json_body
        captured["auth"] = auth
        return {"ok": True, "status_code": 200, "body_preview": "ok", "error_kind": None, "error_text": None}

    monkeypatch.setattr(app, "_http_probe_detailed", _fake_http)
    result = app.run_agent_precheck_diagnostic(_uptime_spec(), env, timeout_seconds=2)

    assert result.passed is True
    assert captured["auth"] == ("1", "uk-quoted")


def test_uptimekuma_precheck_fails_auth_when_credentials_missing(monkeypatch):
    _mock_network_ok(monkeypatch)
    env = _base_env()
    result = app.run_agent_precheck_diagnostic(_uptime_spec(), env, timeout_seconds=2)

    auth_phase = _phase(result.phases, "auth")
    assert result.passed is False
    assert auth_phase["status"] == "FAIL"
    assert auth_phase["normalized_error"] == "missing_auth"
