import importlib.util
from io import StringIO
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
import requests


SCRIPT = Path(__file__).resolve().parents[1] / "check_integrations.py"
SPEC = importlib.util.spec_from_file_location("mad_preflight", SCRIPT)
preflight = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = preflight
SPEC.loader.exec_module(preflight)

SECRET = "SECRET_SENTINEL_NEVER_PRINT"


class Response:
    def __init__(self, status=200, body=None, text=SECRET):
        self.status_code = status
        self.body = body
        self.text = text

    def json(self):
        if isinstance(self.body, Exception):
            raise self.body
        return self.body


class Session:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if not self.responses:
            raise AssertionError("Unexpected network request")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def rendered(results):
    output = StringIO()
    code = preflight.print_results(results, output)
    text = output.getvalue()
    assert SECRET not in text
    assert "Authorization" not in text
    return code, text


def wazuh_config(api=False):
    return {
        "WAZUH_INDEXER_HOST": "https://indexer.example:9200",
        "WAZUH_INDEXER_USER": SECRET,
        "WAZUH_INDEXER_PASSWORD": SECRET,
        "WAZUH_INDEXER_VERIFY_TLS": "true",
        "WAZUH_API_ENABLED": "true" if api else "false",
        "WAZUH_API_HOST": "https://wazuh.example:55000",
        "WAZUH_API_USER": SECRET,
        "WAZUH_API_PASSWORD": SECRET,
        "WAZUH_API_VERIFY_TLS": "true",
    }


def test_root_cannot_pass_service_identity_or_make_requests(tmp_path):
    session = Session()
    result = preflight.run_checks({}, tmp_path, session, actual_user="root")
    assert result == [preflight.Result("identity", "service_user", "FAIL", "must_run_as_configured_service_user")]
    assert session.calls == []
    assert rendered(result)[0] == 1


def test_cli_checks_identity_before_reading_env(monkeypatch, capsys):
    monkeypatch.setattr(preflight, "current_user", lambda: "root")

    def forbidden_read(*args, **kwargs):
        raise AssertionError("Must not read credentials with wrong identity")

    monkeypatch.setattr(Path, "read_text", forbidden_read)
    assert preflight.main(["--env", SECRET]) == 1
    output = capsys.readouterr().out
    assert "must_run_as_configured_service_user" in output
    assert SECRET not in output


def test_shared_state_paths_are_blocking(tmp_path):
    cfg = {"ARTIFACTS_DIR": "artifacts", "ZABBIX_STATE_FILE": "state.json"}
    paths = preflight.resolve_paths(tmp_path, cfg)
    assert paths["nessus"]["state"] == paths["uptimekuma"]["state"] == paths["zabbix"]["state"]
    results = preflight.check_state_paths(tmp_path, cfg, access=lambda *args: True)
    collisions = [r for r in results if r.check == "state_collision"]
    assert len(collisions) == 3
    assert all(r.status == "FAIL" for r in collisions)
    assert rendered(collisions)[0] == 1


def test_integration_overrides_separate_state_and_metadata(tmp_path):
    cfg = {"ARTIFACTS_DIR": "artifacts", "NESSUS_ARTIFACTS_DIR": "runtime/nessus",
           "UPTIME_ARTIFACTS_DIR": "runtime/uptimekuma", "ZABBIX_ARTIFACTS_DIR": "runtime/zabbix"}
    paths = preflight.resolve_paths(tmp_path, cfg)
    for name in ("nessus", "uptimekuma", "zabbix"):
        assert paths[name]["state"] == tmp_path / "runtime" / name / "state.json"
        assert paths[name]["delivery_meta"] == tmp_path / "runtime" / name / "last_delivery_meta.json"
    assert not any(r.check == "state_collision" for r in preflight.check_state_paths(tmp_path, cfg))


def test_special_path_semantics_match_main(tmp_path):
    cfg = {"WAZUH_ARTIFACTS_DIR": "runtime/wazuh/artifacts", "CHECKPOINT_FILE": "state/agent_state.db",
           "OPENVAS_STATE_PATH": "state/openvas.json", "OPENVAS_LAST_DELIVERY_META_PATH": "delivery.json"}
    paths = preflight.resolve_paths(tmp_path, cfg)
    assert paths["wazuh"]["artifacts"] == tmp_path / "runtime/wazuh/runtime/wazuh/artifacts"
    assert paths["wazuh"]["state"] == tmp_path / "state/agent_state.db"
    assert paths["openvas"]["state"] == tmp_path / "state/openvas.json"
    assert paths["openvas"]["delivery_meta"] == tmp_path / "runtime/openvas/artifacts/delivery.json"
    assert paths["insightvm"]["delivery_meta"] == tmp_path / "runtime/insightvm/last_delivery_meta.json"


def test_openvas_state_parent_denial_is_blocking(tmp_path):
    result = preflight.check_state_paths(tmp_path, {"OPENVAS_STATE_PATH": "./state.json"},
                                          access=lambda path, mode: Path(path) != tmp_path)
    openvas = next(r for r in result if r.integration == "openvas")
    assert openvas.status == "FAIL"
    assert rendered([openvas])[0] == 1


def test_nessus_authenticated_read_never_exports():
    session = Session(Response(body={"scans": [{"id": 1}]}))
    cfg = {"NESSUS_BASE_URL": "https://nessus.example:8834", "NESSUS_ACCESS_KEY": SECRET,
           "NESSUS_SECRET_KEY": SECRET, "NESSUS_VERIFY_SSL": "true"}
    result = preflight.check_nessus(cfg, session)
    assert result[0].status == "PASS"
    method, url, args = session.calls[0]
    assert method == "GET" and url.endswith("/scans")
    assert args["headers"]["X-ApiKeys"] == f"accessKey={SECRET}; secretKey={SECRET}"
    assert args["verify"] is True and args["allow_redirects"] is False
    assert rendered(result)[0] == 0


@pytest.mark.parametrize("response,code", [
    (Response(401), "http_status=401"),
    (requests.exceptions.ConnectionError(SECRET), "connection_failed"),
    (requests.exceptions.SSLError(SECRET), "tls_verification_failed"),
    (requests.exceptions.Timeout(SECRET), "request_timeout"),
    (Response(body=ValueError(SECRET)), "invalid_configuration_or_response"),
])
def test_failures_never_render_response_bodies_or_exception_secrets(response, code):
    cfg = {"NESSUS_BASE_URL": "https://nessus.example", "NESSUS_ACCESS_KEY": SECRET,
           "NESSUS_SECRET_KEY": SECRET}
    result = preflight.check_nessus(cfg, Session(response))
    status, output = rendered(result)
    assert status == 1
    assert code in output


def test_zabbix_bearer_host_count_without_login():
    session = Session(Response(body={"result": "9"}))
    result = preflight.check_zabbix({"ZABBIX_API_URL": "https://zabbix.example/api_jsonrpc.php",
                                    "ZABBIX_API_TOKEN": SECRET}, session)
    args = session.calls[0][2]
    assert args["headers"] == {"Authorization": "Bearer " + SECRET}
    assert args["json"]["method"] == "host.get"
    assert args["json"]["params"] == {"countOutput": True}
    assert len(session.calls) == 1
    assert rendered(result)[0] == 0


def test_zabbix_login_read_logout_without_token():
    session = Session(Response(body={"result": SECRET}), Response(body={"result": "9"}),
                      Response(body={"result": True}))
    cfg = {"ZABBIX_API_URL": "https://zabbix.example/api_jsonrpc.php", "ZABBIX_USER": SECRET,
           "ZABBIX_PASS": SECRET}
    result = preflight.check_zabbix(cfg, session)
    assert [call[2]["json"]["method"] for call in session.calls] == ["user.login", "host.get", "user.logout"]
    assert rendered(result)[0] == 0


def test_zabbix_host_failure_still_logs_out_without_leaking_jsonrpc_error():
    session = Session(Response(body={"result": SECRET}), Response(body={"error": {"data": SECRET}}),
                      Response(body={"result": True}))
    result = preflight.check_zabbix({"ZABBIX_API_URL": "https://zabbix.example/api_jsonrpc.php",
                                    "ZABBIX_USER": SECRET, "ZABBIX_PASS": SECRET}, session)
    assert session.calls[-1][2]["json"]["method"] == "user.logout"
    assert rendered(result)[0] == 1


def test_wazuh_root_forbidden_but_readable_alerts_is_warning_not_failure():
    session = Session(Response(403), Response(body={"hits": {"total": {"value": 12}}}))
    result = preflight.check_wazuh(wazuh_config(), session)
    assert next(r for r in result if r.check == "search_alerts").status == "PASS"
    assert next(r for r in result if r.check == "indexer_root").status == "WARN"
    method, url, args = session.calls[1]
    assert method == "POST" and url.endswith("/wazuh-alerts-*/_search")
    assert args["json"]["size"] == 0
    assert args["json"]["query"]["range"]["timestamp"]["gte"] == "now-2h"
    assert rendered(result)[0] == 0


def test_wazuh_search_auth_failure_blocks():
    result = preflight.check_wazuh(wazuh_config(), Session(Response(), Response(401)))
    assert rendered(result)[0] == 1


def test_wazuh_network_failure_blocks():
    session = Session(requests.exceptions.ConnectionError(SECRET))
    result = preflight.check_wazuh(wazuh_config(), session)
    assert result[0].detail == "connection_failed"
    assert rendered(result)[0] == 1


def test_wazuh_authenticates_and_reads_agent_summary_without_printing_token():
    session = Session(Response(), Response(body={"hits": {"total": 0}}),
                      Response(body={"data": {"token": SECRET}}),
                      Response(body={"data": {"connection": {"total": 21}}, "error": 0}))
    result = preflight.check_wazuh(wazuh_config(api=True), session)
    assert session.calls[2][1].endswith("/security/user/authenticate")
    assert session.calls[3][2]["headers"] == {"Authorization": "Bearer " + SECRET}
    assert rendered(result)[0] == 0


def test_uptime_metrics_auth_and_database_access_only(tmp_path, monkeypatch):
    monkeypatch.setattr(preflight.os, "access", lambda *args: False)
    session = Session(Response(text='# HELP monitor_status Status\nmonitor_status{monitor_id="1"} 1\n'))
    cfg = {"UPTIME_KUMA_URL": "http://kuma.example:3001", "UPTIME_KUMA_API_KEY_ID": SECRET,
           "UPTIME_KUMA_API_KEY": SECRET, "UPTIME_KUMA_DB_PATH": "/protected/kuma.db"}
    result = preflight.check_uptimekuma(cfg, session, tmp_path)
    assert session.calls[0][2]["auth"] == (SECRET, SECRET)
    assert next(r for r in result if r.check == "read_metrics").detail == "monitors=1"
    assert next(r for r in result if r.check == "database_access").status == "FAIL"
    assert rendered(result)[0] == 1


def test_uptime_falls_back_to_configured_username_password(tmp_path):
    session = Session(Response(text="monitor_status 1\n"))
    cfg = {"UPTIME_KUMA_URL": "http://kuma.example", "UPTIME_KUMA_USERNAME": SECRET,
           "UPTIME_KUMA_PASSWORD": SECRET}
    assert rendered(preflight.check_uptimekuma(cfg, session, tmp_path))[0] == 0
    assert session.calls[0][2]["auth"] == (SECRET, SECRET)


def test_insightvm_reads_one_asset_with_configured_tls():
    session = Session(Response(body={"resources": [{"id": 1}]}))
    cfg = {"INSIGHTVM_BASE_URL": "https://insightvm.example:3780/api/3", "INSIGHTVM_USER": SECRET,
           "INSIGHTVM_PASSWORD": SECRET, "INSIGHTVM_VERIFY_SSL": "false"}
    result = preflight.check_insightvm(cfg, session)
    method, url, args = session.calls[0]
    assert method == "GET" and url.endswith("/api/3/assets")
    assert args["params"] == {"size": 1} and args["verify"] is False
    assert rendered(result)[0] == 0


def test_configured_ca_is_honored_and_missing_ca_blocks(tmp_path):
    bundle = tmp_path / "ca.pem"
    bundle.write_text("test certificate placeholder", encoding="utf-8")
    assert preflight._verify({"REQUESTS_CA_BUNDLE": str(bundle)}, "VERIFY_SSL") == str(bundle)
    cfg = {"NESSUS_BASE_URL": "https://nessus.example", "NESSUS_ACCESS_KEY": SECRET,
           "NESSUS_SECRET_KEY": SECRET, "REQUESTS_CA_BUNDLE": str(tmp_path / SECRET)}
    session = Session()
    assert rendered(preflight.check_nessus(cfg, session))[0] == 1
    assert session.calls == []


def test_openvas_probe_reads_tasks_only_and_sanitizes_failure(tmp_path):
    calls = []

    def probe(cfg, repo):
        calls.append(repo)
        return '<get_tasks_response status="200"><task id="one"/></get_tasks_response>'

    result = preflight.check_openvas({"GVM_PASSWORD": SECRET, "OPENVAS_COLLECTOR": "gmp"}, tmp_path, probe)
    assert result[0].detail == "sample_tasks=1"
    assert calls == [tmp_path]
    assert rendered(result)[0] == 0

    def denied(cfg, repo):
        raise RuntimeError(SECRET)

    assert rendered(preflight.check_openvas({"GVM_PASSWORD": SECRET, "OPENVAS_COLLECTOR": "gmp"}, tmp_path, denied))[0] == 1


@pytest.mark.parametrize("cfg", [
    {},
    {"OPENVAS_COLLECTOR": "simulated"},
    {"COLLECTOR": "simulated"},
    {"OPENVAS_COLLECTOR": "simulated", "COLLECTOR": "gmp"},
])
def test_simulated_openvas_cannot_pass_real_source_preflight(tmp_path, cfg):
    def unexpected_probe(*args):
        pytest.fail("GMP availability must not validate a simulated collector configuration")

    cfg = {**cfg, "GVM_PASSWORD": SECRET}
    result = preflight.check_openvas(cfg, tmp_path, unexpected_probe)
    assert result[0].detail == "real_gmp_collector_required"
    assert rendered(result)[0] == 1


@pytest.mark.parametrize("cfg", [
    {"OPENVAS_COLLECTOR": " gMp "},
    {"COLLECTOR": "gmp"},
])
def test_openvas_real_collector_normalization_and_global_fallback(tmp_path, cfg):
    result = preflight.check_openvas({**cfg, "GVM_PASSWORD": SECRET}, tmp_path,
                                     lambda *args: '<get_tasks_response status="200"/>')
    assert rendered(result)[0] == 0


@pytest.mark.parametrize("transport", ["plain", "tls"])
def test_gvm_adapter_limits_tasks_and_suppresses_transport_output(tmp_path, monkeypatch, capsys, transport):
    calls = []
    xml = '<get_tasks_response status="200"><task id="one"/></get_tasks_response>'

    class Client:
        def __init__(self, **kwargs):
            assert kwargs["debug"] is False
            self.transport = transport
            self.gmp = SimpleNamespace(get_tasks=self.get_tasks)

        def __enter__(self):
            print(SECRET)
            return self

        def __exit__(self, *args):
            return None

        def _send_plain_gmp(self, command, expected):
            calls.append((command, expected))
            return xml

        def get_tasks(self, **kwargs):
            calls.append(kwargs)
            return xml

    monkeypatch.setitem(sys.modules, "gvm_client", SimpleNamespace(GVMClient=Client))
    monkeypatch.setenv("GVM_ALLOW_PLAIN_TCP", "false")
    cfg = {"GVM_PASSWORD": SECRET, "GVM_TRANSPORT": transport, "GVM_ALLOW_PLAIN_TCP": "true",
           "OPENVAS_COLLECTOR": "gmp"}
    result = preflight.check_openvas(cfg, tmp_path)
    assert result[0].status == "PASS"
    assert preflight.os.environ["GVM_ALLOW_PLAIN_TCP"] == "false"
    assert SECRET not in capsys.readouterr().out
    if transport == "plain":
        assert calls == [('<get_tasks filter="rows=1 first=1"/>', "get_tasks_response")]
    else:
        assert calls == [{"filter_string": "rows=1 first=1"}]


def test_aws_is_options_only_not_delivery_proof():
    session = Session(Response(204))
    result = preflight.check_aws({"TXDXAI_INGEST_URL": "https://backend.example/scans/upload-url"}, session)
    assert session.calls[0][0] == "OPTIONS"
    code, output = rendered(result)
    assert code == 0 and "upload_and_processing_NOT_tested" in output


def test_invalid_env_copy_is_rejected_without_printing_content(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(preflight, "current_user", lambda: "desarrollo-xoc")
    env = tmp_path / "invalid.env"
    text = "this is terminal text " + SECRET + "\n"
    env.write_text(text, encoding="utf-8")
    assert preflight.main(["--env", str(env)]) == 1
    assert SECRET not in capsys.readouterr().out
    assert env.read_text(encoding="utf-8") == text
