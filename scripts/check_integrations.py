#!/usr/bin/env python3
"""Read-only MAD preflight. No collectors, uploads, queues, or file writes."""

from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from io import StringIO
import os
from pathlib import Path
import re
import sys
from typing import Callable, Mapping
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

import requests
from dotenv import dotenv_values
from dotenv.parser import parse_stream


INTEGRATIONS = ("nessus", "uptimekuma", "zabbix", "openvas", "wazuh", "insightvm")
TIMEOUT = (5, 20)


@dataclass(frozen=True)
class Result:
    integration: str
    check: str
    status: str
    detail: str


class CheckFailure(Exception):
    """Only fixed, non-sensitive diagnostic codes belong in this exception."""


class HTTPFailure(CheckFailure):
    def __init__(self, status: int):
        super().__init__(f"http_status={int(status)}")


def _bool(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "t", "y"}


def _required(cfg: Mapping[str, str], *keys: str) -> None:
    if any(not cfg.get(key, "").strip() for key in keys):
        raise CheckFailure("required_configuration_missing")


def _url(cfg: Mapping[str, str], key: str) -> str:
    _required(cfg, key)
    value = cfg[key].strip().rstrip("/")
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment):
        raise CheckFailure("invalid_endpoint_configuration")
    return value


def _verify(cfg: Mapping[str, str], key: str, default: bool = True,
            ca_key: str | None = None, *, use_global: bool = True) -> bool | str:
    if ca_key and cfg.get(ca_key):
        bundle = cfg[ca_key]
    elif not _bool(cfg.get(key, cfg.get("VERIFY_SSL") if use_global else None), default):
        return False
    else:
        bundle = cfg.get("REQUESTS_CA_BUNDLE", "")
    if bundle:
        if not Path(bundle).is_file() or not os.access(bundle, os.R_OK):
            raise CheckFailure("configured_ca_bundle_unreadable")
        return bundle
    return True


def _request(session, method: str, url: str, *, expected=(200,), **kwargs):
    response = session.request(method, url, timeout=TIMEOUT, allow_redirects=False, **kwargs)
    status = int(response.status_code)
    if status not in expected:
        raise HTTPFailure(status)
    return response


def _json(response) -> dict:
    body = response.json()
    if not isinstance(body, dict):
        raise CheckFailure("unexpected_response_shape")
    return body


def _count(value) -> int:
    number = int(value)
    if number < 0:
        raise CheckFailure("invalid_count")
    return number


def _run(integration: str, check: str, action: Callable[[], list[Result]]) -> list[Result]:
    """Never render response bodies, exception text, endpoints, or credentials."""
    try:
        return action()
    except HTTPFailure as exc:
        detail = str(exc)
    except CheckFailure as exc:
        # Only our own fixed diagnostic codes are allowed through.
        detail = str(exc)
    except requests.exceptions.SSLError:
        detail = "tls_verification_failed"
    except requests.exceptions.Timeout:
        detail = "request_timeout"
    except requests.exceptions.ConnectionError:
        detail = "connection_failed"
    except PermissionError:
        detail = "permission_denied"
    except (ValueError, TypeError, KeyError, ET.ParseError):
        detail = "invalid_configuration_or_response"
    except Exception:
        detail = "protocol_or_runtime_failure"
    return [Result(integration, check, "FAIL", detail)]


def check_nessus(cfg, session) -> list[Result]:
    def action():
        _required(cfg, "NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY")
        headers = {"X-ApiKeys": f"accessKey={cfg['NESSUS_ACCESS_KEY']}; secretKey={cfg['NESSUS_SECRET_KEY']}"}
        body = _json(_request(session, "GET", _url(cfg, "NESSUS_BASE_URL") + "/scans",
                              headers=headers, verify=_verify(cfg, "NESSUS_VERIFY_SSL")))
        scans = body.get("scans")
        if not isinstance(scans, list):
            raise CheckFailure("unexpected_scans_response")
        return [Result("nessus", "read_scans", "PASS", f"scans={len(scans)}")]
    return _run("nessus", "read_scans", action)


def check_zabbix(cfg, session) -> list[Result]:
    def action():
        url = _url(cfg, "ZABBIX_API_URL")
        verify = _verify(cfg, "ZABBIX_VERIFY_SSL")

        def rpc(method, params, token=None):
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            body = _json(_request(session, "POST", url, headers=headers, verify=verify,
                                  json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            if "error" in body or "result" not in body:
                raise CheckFailure("jsonrpc_request_failed")
            return body["result"]

        token = cfg.get("ZABBIX_API_TOKEN")
        logged_in = not bool(token)
        if logged_in:
            _required(cfg, "ZABBIX_USER", "ZABBIX_PASS")
            token = rpc("user.login", {"username": cfg["ZABBIX_USER"], "password": cfg["ZABBIX_PASS"]})
            if not isinstance(token, str) or not token:
                raise CheckFailure("authentication_response_invalid")
        logout_failed = False
        try:
            total = _count(rpc("host.get", {"countOutput": True}, token))
        finally:
            if logged_in:
                try:
                    rpc("user.logout", [], token)
                except Exception:
                    logout_failed = True
        result = [Result("zabbix", "read_hosts", "PASS", f"hosts={total}")]
        if logout_failed:
            result.append(Result("zabbix", "logout", "WARN", "temporary_session_logout_failed"))
        return result
    return _run("zabbix", "read_hosts", action)


def check_uptimekuma(cfg, session, repo: Path) -> list[Result]:
    def action():
        api_auth = (cfg.get("UPTIME_KUMA_API_KEY_ID"), cfg.get("UPTIME_KUMA_API_KEY"))
        user_auth = (cfg.get("UPTIME_KUMA_USERNAME"), cfg.get("UPTIME_KUMA_PASSWORD"))
        auth = api_auth if all(api_auth) else user_auth if all(user_auth) else None
        path = cfg.get("UPTIME_KUMA_METRICS_PATH", "/metrics")
        url = _url(cfg, "UPTIME_KUMA_URL") + "/" + path.lstrip("/")
        response = _request(session, "GET", url, auth=auth, verify=_verify(cfg, "UPTIME_VERIFY_SSL"))
        count = sum(bool(re.match(r"^monitor_status(?:\{|\s)", line)) for line in response.text.splitlines())
        if not count:
            raise CheckFailure("monitor_status_metrics_missing")
        result = [Result("uptimekuma", "read_metrics", "PASS", f"monitors={count}")]
        if cfg.get("UPTIME_KUMA_DB_PATH"):
            db = _resolve(repo / "uptimekuma_integration", cfg["UPTIME_KUMA_DB_PATH"])
            readable = os.access(db, os.R_OK)
            result.append(Result("uptimekuma", "database_access", "PASS" if readable else "FAIL",
                                 "configured_database_readable" if readable else "configured_database_not_readable"))
        return result
    return _run("uptimekuma", "read_metrics", action)


def check_insightvm(cfg, session) -> list[Result]:
    def action():
        _required(cfg, "INSIGHTVM_USER", "INSIGHTVM_PASSWORD")
        body = _json(_request(session, "GET", _url(cfg, "INSIGHTVM_BASE_URL") + "/assets",
                              params={"size": 1}, auth=(cfg["INSIGHTVM_USER"], cfg["INSIGHTVM_PASSWORD"]),
                              verify=_verify(cfg, "INSIGHTVM_VERIFY_SSL", ca_key="INSIGHTVM_CA_BUNDLE", use_global=False)))
        if not isinstance(body.get("resources"), list):
            raise CheckFailure("unexpected_assets_response")
        return [Result("insightvm", "read_assets", "PASS", f"sample_assets={len(body['resources'])}")]
    return _run("insightvm", "read_assets", action)


def check_wazuh(cfg, session) -> list[Result]:
    def indexer():
        _required(cfg, "WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASSWORD")
        url = _url(cfg, "WAZUH_INDEXER_HOST")
        auth = (cfg["WAZUH_INDEXER_USER"], cfg["WAZUH_INDEXER_PASSWORD"])
        verify = _verify(cfg, "WAZUH_INDEXER_VERIFY_TLS", False, use_global=False)
        # Root visibility is not equivalent to permission to search alert indices.
        root = session.request("GET", url + "/", auth=auth, verify=verify,
                               timeout=TIMEOUT, allow_redirects=False)
        root_status = int(root.status_code)
        if root_status == 401:
            raise HTTPFailure(401)
        query = {"size": 0, "track_total_hits": True,
                 "query": {"range": {"timestamp": {"gte": "now-2h", "lte": "now"}}}}
        body = _json(_request(session, "POST", url + "/wazuh-alerts-*/_search",
                              json=query, auth=auth, verify=verify))
        total = body.get("hits", {}).get("total")
        if isinstance(total, dict):
            total = total.get("value")
        total = _count(total)
        result = [Result("wazuh", "search_alerts", "PASS", f"alerts_last_2h={total}")]
        if root_status != 200:
            result.append(Result("wazuh", "indexer_root", "WARN",
                                 f"root_http_status={root_status}; alert_search_succeeded"))
        return result

    def api():
        _required(cfg, "WAZUH_API_USER", "WAZUH_API_PASSWORD")
        url = _url(cfg, "WAZUH_API_HOST")
        verify = _verify(cfg, "WAZUH_API_VERIFY_TLS", False, use_global=False)
        body = _json(_request(session, "GET", url + "/security/user/authenticate", verify=verify,
                              auth=(cfg["WAZUH_API_USER"], cfg["WAZUH_API_PASSWORD"])))
        token = body.get("data", {}).get("token")
        if not isinstance(token, str) or not token:
            raise CheckFailure("authentication_response_invalid")
        summary = _json(_request(session, "GET", url + "/agents/summary/status", verify=verify,
                                 headers={"Authorization": f"Bearer {token}"}))
        if summary.get("error", 0) != 0 or not isinstance(summary.get("data"), dict):
            raise CheckFailure("unexpected_agent_summary_response")
        return [Result("wazuh", "read_agent_summary", "PASS", "authenticated_summary_read")]

    results = _run("wazuh", "search_alerts", indexer)
    if _bool(cfg.get("WAZUH_API_ENABLED"), True):
        results.extend(_run("wazuh", "read_agent_summary", api))
    else:
        results.append(Result("wazuh", "read_agent_summary", "WARN", "api_disabled_by_configuration"))
    return results


def _gvm_probe(cfg, repo: Path) -> str:
    """Reuse the deployed transport, but request just one task; never export reports."""
    sys.path.insert(0, str(repo / "openVAS_integration"))
    try:
        from gvm_client import GVMClient
    finally:
        sys.path.pop(0)
    transport = (cfg.get("GVM_TRANSPORT") or ("unix" if cfg.get("GVM_SOCKET") else "tls")).lower()
    if transport in {"plain", "tcp"} and not _bool(cfg.get("GVM_ALLOW_PLAIN_TCP"), False):
        raise CheckFailure("plain_gmp_not_enabled_in_configuration")
    old_plain = os.environ.get("GVM_ALLOW_PLAIN_TCP")
    os.environ["GVM_ALLOW_PLAIN_TCP"] = cfg.get("GVM_ALLOW_PLAIN_TCP", "false")
    try:
        # GVM transport errors/debug output must never leak authentication XML.
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            with GVMClient(host=cfg.get("GVM_HOST", ""), port=int(cfg.get("GVM_PORT", "9390")),
                           user=cfg.get("GVM_USERNAME") or cfg.get("GVM_USER", "admin"),
                           password=cfg.get("GVM_PASSWORD") or cfg.get("GVM_PASS", ""),
                           socket_path=cfg.get("GVM_SOCKET", ""), transport=transport,
                           cafile=cfg.get("GVM_TLS_CAFILE", ""), certfile=cfg.get("GVM_TLS_CERTFILE", ""),
                           keyfile=cfg.get("GVM_TLS_KEYFILE", ""), timeout=20, debug=False) as client:
                if client.transport == "plain":
                    return client._send_plain_gmp('<get_tasks filter="rows=1 first=1"/>', "get_tasks_response")
                return client.gmp.get_tasks(filter_string="rows=1 first=1")
    finally:
        if old_plain is None:
            os.environ.pop("GVM_ALLOW_PLAIN_TCP", None)
        else:
            os.environ["GVM_ALLOW_PLAIN_TCP"] = old_plain


def check_openvas(cfg, repo: Path, gvm_probe=None) -> list[Result]:
    def action():
        collector = (cfg.get("OPENVAS_COLLECTOR") or cfg.get("COLLECTOR") or "simulated").strip().lower()
        if collector != "gmp":
            raise CheckFailure("real_gmp_collector_required")
        if not (cfg.get("GVM_PASSWORD") or cfg.get("GVM_PASS")):
            raise CheckFailure("required_configuration_missing")
        response = (gvm_probe or _gvm_probe)(cfg, repo)
        root = ET.fromstring(response)
        if root.get("status") != "200":
            raise CheckFailure("gmp_authentication_or_read_failed")
        return [Result("openvas", "read_tasks", "PASS", f"sample_tasks={len(root.findall('task'))}")]
    return _run("openvas", "read_tasks", action)


def check_aws(cfg, session) -> list[Result]:
    def action():
        backend_tls = dict(cfg)
        backend_tls["BACKEND_VERIFY_SSL"] = cfg.get("BACKEND_VERIFY_SSL", cfg.get("BACKEND_TLS_VERIFY", "true"))
        _request(session, "OPTIONS", _url(cfg, "TXDXAI_INGEST_URL"), expected=(200, 204),
                 verify=_verify(backend_tls, "BACKEND_VERIFY_SSL", use_global=False))
        return [Result("aws", "endpoint_reachability", "PASS", "OPTIONS_only; upload_and_processing_NOT_tested")]
    return _run("aws", "endpoint_reachability", action)


def _resolve(base: Path, raw: str) -> Path:
    path = Path(raw.strip())
    return (path if path.is_absolute() else base / path).resolve()


def resolve_paths(repo: Path, cfg: Mapping[str, str]) -> dict[str, dict[str, Path]]:
    """Mirror main's collector path semantics; no file reads or writes."""
    paths = {}
    for name, prefix in (("nessus", "NESSUS"), ("uptimekuma", "UPTIME"), ("zabbix", "ZABBIX")):
        artifacts = _resolve(repo, cfg.get(prefix + "_ARTIFACTS_DIR") or cfg.get("ARTIFACTS_DIR") or f"runtime/{name}")
        state = cfg.get("STATE_FILE", "state.json")
        if name == "zabbix":
            state = cfg.get("ZABBIX_STATE_FILE") or cfg.get("STATE_FILE") or cfg.get("STATE_PATH", "state.json")
        meta = cfg.get(prefix + "_DELIVERY_META_PATH") or cfg.get("DELIVERY_META_PATH", "last_delivery_meta.json")
        paths[name] = {"artifacts": artifacts, "state": _resolve(artifacts, state or "state.json"),
                       "delivery_meta": _resolve(artifacts, meta or "last_delivery_meta.json")}
    artifacts = _resolve(repo, cfg.get("OPENVAS_ARTIFACTS_DIR") or "runtime/openvas/artifacts")
    paths["openvas"] = {"artifacts": artifacts,
                        "state": _resolve(repo, cfg.get("OPENVAS_STATE_PATH") or cfg.get("STATE_PATH") or "./state.json"),
                        "delivery_meta": _resolve(artifacts, cfg.get("OPENVAS_LAST_DELIVERY_META_PATH") or "last_delivery_meta.json")}
    artifacts = _resolve(repo / "runtime/wazuh", cfg.get("WAZUH_ARTIFACTS_DIR") or cfg.get("ARTIFACTS_DIR", "artifacts"))
    paths["wazuh"] = {"artifacts": artifacts,
                      "state": _resolve(repo, cfg.get("WAZUH_CHECKPOINT_FILE") or cfg.get("CHECKPOINT_FILE", "state/agent_state.db")),
                      "delivery_meta": artifacts / "last_delivery_meta.json"}
    artifacts = _resolve(repo, "runtime/insightvm")
    paths["insightvm"] = {"artifacts": artifacts,
                          "state": _resolve(repo, cfg.get("INSIGHTVM_STATE_FILE") or cfg.get("STATE_FILE") or "runtime/insightvm/state.json"),
                          "delivery_meta": artifacts / "last_delivery_meta.json"}
    return paths


def check_state_paths(repo: Path, cfg, access=os.access) -> list[Result]:
    paths = resolve_paths(repo, cfg)
    results = []
    for name, item in paths.items():
        state = item["state"]
        writable = state.parent.is_dir() and access(state.parent, os.W_OK | os.X_OK)
        readable = not state.exists() or (state.is_file() and access(state, os.R_OK))
        valid = writable and readable
        results.append(Result(name, "state_access", "PASS" if valid else "FAIL",
                              "state_parent_writable" if valid else "state_parent_not_writable_or_state_not_readable"))
    shared = {}
    for name in ("nessus", "uptimekuma", "zabbix"):
        shared.setdefault(paths[name]["state"], []).append(name)
    for names in shared.values():
        if len(names) > 1:
            for name in names:
                results.append(Result(name, "state_collision", "FAIL", "shared_state=" + ",".join(names)))
    return results


def current_user() -> str:
    import pwd
    return pwd.getpwuid(os.geteuid()).pw_name


def run_checks(cfg, repo: Path, session, *, service_user="desarrollo-xoc", actual_user=None,
               gvm_probe=None) -> list[Result]:
    if (actual_user if actual_user is not None else current_user()) != service_user:
        return [Result("identity", "service_user", "FAIL", "must_run_as_configured_service_user")]
    results = [Result("identity", "service_user", "PASS", "effective_service_identity_confirmed")]
    results.extend(_run("configuration", "state_access", lambda: check_state_paths(repo, cfg)))
    results.extend(check_nessus(cfg, session))
    results.extend(check_zabbix(cfg, session))
    results.extend(check_uptimekuma(cfg, session, repo))
    results.extend(check_insightvm(cfg, session))
    results.extend(check_wazuh(cfg, session))
    results.extend(check_openvas(cfg, repo, gvm_probe))
    results.extend(check_aws(cfg, session))
    return results


def print_results(results: list[Result], stream=None) -> int:
    stream = stream or sys.stdout
    for item in results:
        print(f"{item.status:4} {item.integration}.{item.check}: {item.detail}", file=stream)
    for name in INTEGRATIONS:
        statuses = [r.status for r in results if r.integration == name]
        overall = "FAIL" if "FAIL" in statuses else "WARN" if "WARN" in statuses else "PASS" if statuses else "NOT_RUN"
        print(f"SUMMARY {name}: {overall}", file=stream)
    print("Read-only preflight: no full collection, uploads, queue replay, or AWS processing verification occurred.", file=stream)
    return 1 if any(r.status == "FAIL" for r in results) else 0


def main(argv=None) -> int:
    repo = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", type=Path, default=repo / ".env")
    parser.add_argument("--service-user", default="desarrollo-xoc")
    args = parser.parse_args(argv)
    try:
        if current_user() != args.service_user:
            return print_results([Result("identity", "service_user", "FAIL", "must_run_as_configured_service_user")])
        text = args.env.read_text(encoding="utf-8-sig")
        if any(binding.error for binding in parse_stream(StringIO(text))):
            raise CheckFailure("env_file_has_invalid_statements")
        with redirect_stderr(StringIO()):
            cfg = {key: value for key, value in dotenv_values(stream=StringIO(text)).items() if value is not None}
        with requests.Session() as session:
            results = run_checks(cfg, repo, session, service_user=args.service_user)
        return print_results(results)
    except CheckFailure as exc:
        return print_results([Result("configuration", "load_preflight", "FAIL", str(exc))])
    except PermissionError:
        return print_results([Result("configuration", "load_preflight", "FAIL", "env_file_unreadable")])
    except Exception:
        return print_results([Result("configuration", "load_preflight", "FAIL", "unable_to_load_configuration_or_execute_preflight")])


if __name__ == "__main__":
    raise SystemExit(main())
