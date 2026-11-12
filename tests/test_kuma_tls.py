from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from uptimekuma_integration.tls import metrics_tls_verify
from uptimekuma_integration import config
import app


def test_source_ca_is_separate_from_backend_tls(monkeypatch, tmp_path):
    ca = tmp_path / "internal-ca.pem"
    ca.write_text("test CA placeholder")
    monkeypatch.setattr(config, "load_dotenv", lambda *a, **kw: None)
    monkeypatch.setattr(config.os, "environ", {
        "UPTIME_KUMA_URL": "https://10.208.232.45:443",
        "UPTIME_OUTPUT_MODE": "stdout", "UPTIME_VERIFY_SSL": "true",
        "UPTIME_KUMA_CA_BUNDLE": str(ca),
    })
    cfg = config.load_config()
    assert cfg.metrics_url == "https://10.208.232.45:443/metrics"
    assert cfg.metrics_verify == str(ca)
    assert cfg.verify_ssl is True  # backend remains on its original trust store


def test_tls_defaults_and_relative_bundle(tmp_path):
    assert metrics_tls_verify({}, tmp_path) is True
    assert metrics_tls_verify({"UPTIME_VERIFY_SSL": "false"}, tmp_path) is False
    (tmp_path / "ca.pem").write_text("placeholder")
    assert metrics_tls_verify({"UPTIME_KUMA_CA_BUNDLE": "ca.pem"}, tmp_path) == str(tmp_path / "ca.pem")


@pytest.mark.parametrize("options", [
    {"UPTIME_KUMA_CA_BUNDLE": "missing.pem"},
    {"UPTIME_KUMA_CA_BUNDLE": "."},
    {"UPTIME_KUMA_CA_BUNDLE": "ca.pem", "UPTIME_VERIFY_SSL": "false"},
])
def test_bad_tls_config_fails_closed(options, tmp_path):
    (tmp_path / "ca.pem").write_text("placeholder")
    with pytest.raises(ValueError):
        metrics_tls_verify(options, tmp_path)


def test_precheck_passes_source_ca(monkeypatch, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("placeholder")
    monkeypatch.setattr(app, "_resolve_dns", lambda h: (["10.208.232.45"], None))
    monkeypatch.setattr(app, "_tcp_probe", lambda *a: (True, None, None))
    captured = {}
    def probe(*args, **kwargs):
        captured.update(kwargs)
        return {"ok": True}
    monkeypatch.setattr(app, "_http_probe_detailed", probe)
    env = {"UPTIME_KUMA_URL": "https://10.208.232.45:443", "UPTIME_KUMA_API_KEY_ID": "1",
           "UPTIME_KUMA_API_KEY": "test", "UPTIME_KUMA_CA_BUNDLE": str(ca)}
    assert app.run_agent_precheck_diagnostic(app.AgentSpec("uptimekuma", lambda *a: []), env).passed
    assert captured["verify"] == str(ca)
    env["UPTIME_KUMA_CA_BUNDLE"] = str(tmp_path / "missing")
    captured.clear()
    assert not app.run_agent_precheck_diagnostic(app.AgentSpec("uptimekuma", lambda *a: []), env).passed
    assert not captured  # invalid trust never reaches the network


def test_collector_uses_source_ca_and_does_not_fallback(monkeypatch):
    sys.path.insert(0, str(ROOT / "uptimekuma_integration"))
    import collector
    import requests
    calls = []
    def get(url, **kwargs):
        calls.append(kwargs)
        raise requests.exceptions.SSLError("untrusted certificate")
    monkeypatch.setattr(collector.requests, "get", get)
    cfg = SimpleNamespace(kuma_api_key_id="1", kuma_api_key="test", metrics_url="https://kuma/metrics",
                          metrics_verify="/system/ca.pem", request_timeout=2, http_retries=1)
    with pytest.raises(RuntimeError, match="untrusted certificate"):
        collector.UptimeKumaCollector(cfg).fetch_metrics_text()
    assert len(calls) == 1 and calls[0]["verify"] == "/system/ca.pem"


def test_preflight_uses_same_source_ca(tmp_path):
    from scripts.check_integrations import check_uptimekuma
    ca = tmp_path / "ca.pem"
    ca.write_text("placeholder")
    class Session:
        def request(self, method, url, **kwargs):
            assert url == "https://kuma:443/metrics"
            assert kwargs["verify"] == str(ca)
            return SimpleNamespace(status_code=200, text='monitor_status{monitor_id="1"} 1', headers={})
    result = check_uptimekuma({"UPTIME_KUMA_URL": "https://kuma:443", "UPTIME_KUMA_CA_BUNDLE": str(ca)}, Session(), tmp_path)
    assert result[0].status == "PASS"
