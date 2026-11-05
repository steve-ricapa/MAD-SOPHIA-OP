import argparse
import asyncio
import hashlib
import json
import math
import os
import sys
import uuid
from pathlib import Path
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from loguru import logger

from src.indexer import IndexerClient
from src.api import WazuhApiClient
from src.aggregator import Aggregator
from src.state import StateStore
from src.sender import Sender
from snapshot import build_snapshot_signature
from mad_common.delivery import DeliveryJournal, resolve_delivery_policy
from mad_common.logs import append_jsonl
from mad_common.artifacts import archive_bundle, log_retention, maintain_history, resolve_artifact_policy
from mad_common.collector_delivery import private_json


WAZUH_BANNER = r"""
 __        __   _    _____ _   _ _   _
 \ \      / /  / \  |__  /| | | | | | |
  \ \ /\ / /  / _ \   / / | | | | |_| |
   \ V  V /  / ___ \ / /_ | |_| |  _  |
    \_/\_/  /_/   \_\____| \___/|_| |_|
"""

NON_RETRYABLE_FAILURE_KINDS = {
    "config_missing_api_key",
    "config_missing_tenant",
    "auth",
    "validation",
    "endpoint_not_found",
}


def parse_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def archive_json(path, data):
    private_json(Path(path), data)


def resolve_path(base_dir: Path, raw_path: str) -> Path:
    candidate = Path((raw_path or "").strip())
    if not candidate.is_absolute():
        candidate = base_dir / candidate
    return candidate


def collect_missing_required_config(tenant_id, api_key, ingest_url, indexer_host, indexer_user, indexer_pass, api_host, api_user, api_pass):
    checks = {
        "TXDXAI_TENANT_ID / TXDXAI_COMPANY_ID (>0)": tenant_id > 0,
        "TXDXAI_API_KEY_WAZUH / TXDXAI_API_KEY / API_KEY": bool(api_key),
        "TXDXAI_INGEST_URL": bool(ingest_url),
        "WAZUH_INDEXER_HOST": bool(indexer_host),
        "WAZUH_INDEXER_USER": bool(indexer_user),
        "WAZUH_INDEXER_PASSWORD": bool(indexer_pass),
    }
    return [name for name, is_ok in checks.items() if not is_ok]


def resolve_startup_action(menu_enabled, default_option):
    if not menu_enabled:
        return "run_and_continue"

    logger.info("")
    logger.info("Startup Menu")
    logger.info("1) Run integration tests and continue (recommended)")
    logger.info("2) Run integration tests and exit")
    logger.info("3) Skip integration tests and continue")

    if not sys.stdin or not sys.stdin.isatty():
        logger.info("No interactive console detected; using default option {}", default_option)
        choice = default_option
    else:
        try:
            choice = input("Select option [1]: ").strip() or default_option
        except Exception:
            logger.warning("Could not read menu option; using default option {}", default_option)
            choice = default_option

    mapping = {
        "1": "run_and_continue",
        "2": "run_and_exit",
        "3": "skip_and_continue",
    }
    action = mapping.get(choice)
    if action is None:
        logger.warning("Invalid menu option '{}'; using default option {}", choice, default_option)
        action = mapping.get(default_option, "run_and_continue")
    return action


def log_precheck_results(results):
    logger.info("")
    logger.info("Integration Test Results")
    for i, result in enumerate(results, start=1):
        status = "PASS" if result["passed"] else "FAIL"
        logger.info(
            "[{}] {}. {} | required={} | {}",
            status,
            i,
            result["name"],
            result["required"],
            result["details"],
        )
        evidence = result.get("evidence") or {}
        if evidence and not result["passed"]:
            logger.info("   evidence={}", json.dumps(evidence, ensure_ascii=False))

    passed_count = sum(1 for r in results if r["passed"])
    total = len(results)
    required_failed = [r for r in results if r["required"] and not r["passed"]]
    logger.info("Integration summary: {}/{} tests passed", passed_count, total)
    if required_failed:
        logger.error(
            "Required tests failed: {}",
            ", ".join(r["name"] for r in required_failed),
        )
    return passed_count, total, required_failed


async def run_startup_integration_tests(indexer, api, sender, api_key, missing_required, api_enabled=True):
    results = []

    env_ok = len(missing_required) == 0
    results.append(
        {
            "name": "Required Environment",
            "required": True,
            "passed": env_ok,
            "details": "all required vars present" if env_ok else f"missing: {', '.join(missing_required)}",
        }
    )

    if not api_enabled:
        results.append(
            {
                "name": "Wazuh API Authentication",
                "required": False,
                "passed": True,
                "details": "disabled by WAZUH_API_ENABLED=false; agent inventory polling will be skipped",
                "evidence": {"api_enabled": False},
            }
        )
    elif api is None:
        results.append(
            {
                "name": "Wazuh API Authentication",
                "required": False,
                "passed": False,
                "details": "missing Wazuh API configuration; agent inventory polling will be skipped",
                "evidence": {},
            }
        )
    else:
        auth_ok = await api._authenticate()
        auth_details = "token acquired successfully"
        if not auth_ok:
            error_kind = api.last_error_kind or "unknown"
            error_text = api.last_error or api.last_response_excerpt or "no extra details"
            auth_details = f"authentication failed | kind={error_kind} | detail={error_text}"
        results.append(
            {
                "name": "Wazuh API Authentication",
                "required": False,
                "passed": auth_ok,
                "details": auth_details,
                "evidence": {
                    "host": api.host,
                    "verify_certs": api.verify_certs,
                    "status_code": api.last_status,
                    "failure_kind": api.last_error_kind,
                    "response_excerpt": api.last_response_excerpt,
                },
            }
        )

    if indexer is None:
        results.append(
            {
                "name": "Wazuh Indexer Connectivity",
                "required": True,
                "passed": False,
                "details": "missing Indexer configuration",
            }
        )
    else:
        ping_ok = await indexer.ping()
        if ping_ok:
            sample_since = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
            sample_alerts = await indexer.get_new_alerts(sample_since, limit=1)
            details = f"ping ok, sample_alerts={len(sample_alerts)}"
        else:
            details = f"ping failed | kind={indexer.last_error_kind or 'unknown'} | detail={indexer.last_error or 'no extra details'}"
        results.append(
            {
                "name": "Wazuh Indexer Connectivity",
                "required": True,
                "passed": ping_ok,
                "details": details,
                "evidence": {
                    "host": indexer.host,
                    "verify_certs": indexer.verify_certs,
                    "operation": indexer.last_operation,
                    "failure_kind": indexer.last_error_kind,
                    "error": indexer.last_error,
                },
            }
        )

    if sender is None:
        results.append(
            {
                "name": "Backend Ingest Endpoint",
                "required": True,
                "passed": False,
                "details": "missing TXDXAI_INGEST_URL",
            }
        )
    elif not api_key:
        results.append(
            {
                "name": "Backend Ingest Endpoint",
                "required": True,
                "passed": False,
                "details": "missing API key for backend authentication",
            }
        )
    else:
        backend_ok, backend_details = await sender.probe_endpoint(api_key=api_key)
        results.append(
            {
                "name": "Backend Ingest Endpoint",
                "required": True,
                "passed": backend_ok,
                "details": backend_details,
                "evidence": {
                    "endpoint": sender.ingest_url,
                    "status_code": sender.last_status_code,
                    "failure_kind": sender.last_failure_kind,
                    "error": sender.last_error_body,
                },
            }
        )

    return results


def _update_delivery_checkpoint(state, key, value):
    """StateStore logs write errors; verify persistence before acknowledging."""
    state.update_checkpoint(key, value)
    if state.get_checkpoint(key, default=None) != value:
        raise RuntimeError(f"Unable to persist Wazuh delivery checkpoint {key}")


def _ack_delivery(state, event):
    _update_delivery_checkpoint(state, "snapshot_signature", event["signature"])
    _update_delivery_checkpoint(state, "has_sent_once", "true")
    _update_delivery_checkpoint(state, "last_idempotency_key", event["key"])
    _update_delivery_checkpoint(state, "last_sent_at", datetime.now(timezone.utc).isoformat())
    _update_delivery_checkpoint(state, "last_send_result", "sent")


async def poll_alerts(indexer, aggregator, state, sender, tenant_id, company_id, api_key, app_cfg, single_run=False):
    """Drain durable delivery events independently, then observe source content."""
    while True:
        cycle_ok = True
        try:
            maintain_history(Path(app_cfg["raw_dir"]).parent, "wazuh")
            legacy = list(Path(app_cfg["failed_dir"]).glob("failed_*.json"))
            if legacy:
                raise RuntimeError(
                    "Legacy Wazuh failed_payloads contains pending reports. "
                    "Migrate or reconcile these reports before using delivery-v2; "
                    "the collector will not silently replay or discard them."
                )
            policy = app_cfg.get("delivery_policy") or resolve_delivery_policy(os.environ, "wazuh")
            directory = app_cfg.get("delivery_dir") or str(Path(app_cfg["failed_dir"]).parent / "delivery-v2")
            dry_run = parse_bool(app_cfg["dry_run"], default=False)
            last_result = state.get_checkpoint("last_send_result", "") or ""
            baseline = state.get_checkpoint("snapshot_signature", "") if (
                parse_bool(state.get_checkpoint("has_sent_once", "false"), default=False)
                and not str(last_result).startswith(("failed", "queued"))
            ) else None
            with DeliveryJournal(directory, "wazuh", policy, baseline_signature=baseline,
                                 baseline_sent_at=state.get_checkpoint("last_sent_at", None)) as journal:
                async def send(payload, key):
                    nonlocal cycle_ok
                    try:
                        ok = await sender.send_report(payload)
                    except Exception as error:
                        logger.exception("Wazuh queued delivery failed: {}", error)
                        ok = False
                    if ok is not True:
                        cycle_ok = False
                    archive_json(Path(app_cfg["last_delivery_meta_path"]), {
                        "saved_at_utc": datetime.now(timezone.utc).isoformat(),
                        "scan_id": payload.get("scan_id"), "idempotency_key": key,
                        "delivery_success": ok is True,
                        "status_code": getattr(sender, "last_status_code", None),
                        "failure_kind": getattr(sender, "last_failure_kind", None),
                        "error_body": getattr(sender, "last_error_body", None),
                    })
                    append_jsonl(Path(app_cfg["last_delivery_meta_path"]).parent / "delivery_receipts.jsonl", {
                        "saved_at_utc": datetime.now(timezone.utc).isoformat(), "integration": "wazuh",
                        "scan_id": payload.get("scan_id"), "idempotency_key": key,
                        "sent": ok is True, "status_code": getattr(sender, "last_status_code", None),
                    })
                    return ok is True

                if not dry_run:
                    await journal.drain_async(send, on_ack=lambda event: _ack_delivery(state, event))

                window_end = datetime.now(timezone.utc)
                window_start = window_end - timedelta(hours=app_cfg["initial_lookback_hours"])
                w_start_str, w_end_str = window_start.isoformat(), window_end.isoformat()
                raw_alerts = await indexer.get_new_alerts(w_start_str, limit=int(app_cfg["alert_batch_size"]))
                if getattr(indexer, "last_error_kind", None) or getattr(indexer, "last_error", None):
                    raise RuntimeError(f"Wazuh source collection failed: {getattr(indexer, 'last_error', None)}")
                raw_count = len(raw_alerts)
                raw_alerts = [a for a in raw_alerts if int(a.get("rule", {}).get("level", 0)) >= int(app_cfg["min_rule_level"])]
                findings = [aggregator.normalize_alert(a) for a in raw_alerts]
                agent_summary = state.get_checkpoint("agent_summary", default=None)
                if agent_summary:
                    agent_summary = json.loads(agent_summary)
                signature = build_snapshot_signature(findings, agent_summary, w_start_str, w_end_str)
                decision = journal.decision(signature)
                logger.info("Delivery decision | reason={} unchanged={}/{}", decision["reason"], decision["unchanged_cycles"], policy.backup_cycles)
                if decision["should_send"]:
                    scan_id = str(uuid.uuid4())
                    report = aggregator.create_report(
                        findings, agent_summary,
                        {"scan_id": scan_id, "tenant_id": tenant_id, "company_id": company_id, "api_key": api_key},
                        snapshot_signature=signature, snapshot_mode=decision["snapshot_mode"],
                        send_reason=decision["reason"], snapshot_changed=decision["changed"],
                        mad_version=app_cfg["mad_version"], integration_version=app_cfg["integration_version"],
                        source=app_cfg["source"],
                    )
                    if not dry_run:
                        event = journal.enqueue(signature, report)
                        if event is not None:
                            report = event["payload"]
                    raw_record = {"scan_id": scan_id, "window": {"start": w_start_str, "end": w_end_str},
                                  "raw_count": raw_count, "filtered_count": len(raw_alerts),
                                  "finding_count": len(findings), "snapshot_signature": signature,
                                  "send_reason": decision["reason"], "raw_alerts": raw_alerts}
                    archive_json(Path(app_cfg["last_raw_path"]), raw_record)
                    archive_json(Path(app_cfg["last_payload_path"]), report)
                    archive_bundle(Path(app_cfg["raw_dir"]).parent, "wazuh", {
                        "raw.json": raw_record, "payload.json": report,
                    })
                    if dry_run:
                        logger.info("DRY_RUN enabled: preview archived; no delivery state advanced")
                    elif cycle_ok:
                        await journal.drain_async(send, on_ack=lambda event: _ack_delivery(state, event))
                else:
                    if not dry_run:
                        journal.commit_observation(signature)
                    logger.info("Snapshot skipped | reason={}", decision["reason"])
                if not dry_run and journal.state.get("pending"):
                    cycle_ok = False
        except Exception as e:
            cycle_ok = False
            logger.exception("Error in poll_alerts cycle: {}", e)
        if single_run:
            return cycle_ok
        await asyncio.sleep(int(app_cfg["poll_interval_alerts"]))

async def poll_agents(api, aggregator, state, single_run=False):
    """Loop to fetch agent status updates and detect changes."""
    while True:
        try:
            logger.info("Polling agent status...")
            summary = await api.get_agents_summary()
            current_agents = await api.get_agents_list()
            
            if summary and current_agents:
                # Load previous state for deltas
                prev_agents_str = state.get_checkpoint("agents_map", default="{}")
                try:
                    prev_agents_map = json.loads(prev_agents_str)
                except (json.JSONDecodeError, TypeError):
                    prev_agents_map = {}

                changes, current_map = aggregator.detect_agent_changes(current_agents, prev_agents_map)
                
                # Update state — serialize with json.dumps instead of str()
                state.update_checkpoint("agent_summary", json.dumps(summary))
                state.update_checkpoint("agents_map", json.dumps(current_map))
                
                if changes:
                    logger.warning("Inventory Change: {} agents changed status.", len(changes))
                    for change in changes:
                        logger.info(
                            " | Agent: {} ({} -> {})",
                            change["name"],
                            change["old_status"],
                            change["new_status"],
                        )
                
                logger.info(
                    "Inventory Health: {} active / {} total agents.",
                    summary.get("active", 0),
                    summary.get("total", 0),
                )
        except Exception as e:
            logger.error("Error in poll_agents loop: {}", e)
            
        if single_run:
            logger.info("Single-run mode: poll_agents completed one cycle.")
            break
        await asyncio.sleep(int(os.getenv("WAZUH_POLL_INTERVAL_AGENTS") or os.getenv("POLL_INTERVAL_AGENTS", 60)))

from aiohttp import web


async def healthcheck_handler(request):
    """Provides a basic healthcheck endpoint."""
    return web.json_response({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})


async def main():
    parser = argparse.ArgumentParser(description="Wazuh real-time integration agent")
    parser.add_argument("--once", action="store_true", help="Run one cycle and exit")
    args = parser.parse_args()

    load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=True)

    company_id = int(os.getenv("TXDXAI_COMPANY_ID") or "0")
    tenant_id = int(os.getenv("TXDXAI_TENANT_ID", company_id))
    api_key = (
        os.getenv("TXDXAI_API_KEY_WAZUH")
        or os.getenv("TXDXAI_API_KEY")
        or os.getenv("API_KEY")
    )
    indexer_host = os.getenv("WAZUH_INDEXER_HOST")
    indexer_user = os.getenv("WAZUH_INDEXER_USER")
    indexer_pass = os.getenv("WAZUH_INDEXER_PASSWORD")
    indexer_verify_tls = parse_bool(os.getenv("WAZUH_INDEXER_VERIFY_TLS"), default=False)
    api_host = os.getenv("WAZUH_API_HOST")
    api_user = os.getenv("WAZUH_API_USER")
    api_pass = os.getenv("WAZUH_API_PASSWORD")
    api_verify_tls = parse_bool(os.getenv("WAZUH_API_VERIFY_TLS"), default=False)
    api_enabled = parse_bool(os.getenv("WAZUH_API_ENABLED"), default=True)
    ingest_url = os.getenv("TXDXAI_INGEST_URL")
    health_port = int(os.getenv("HEALTH_CHECK_PORT", 8000))
    checkpoint_file = os.getenv("WAZUH_CHECKPOINT_FILE") or os.getenv("CHECKPOINT_FILE", "state/agent_state.db")

    runtime_dir = Path(__file__).resolve().parent.parent / "runtime" / "wazuh"
    artifacts_dir = resolve_path(runtime_dir, os.getenv("WAZUH_ARTIFACTS_DIR") or os.getenv("ARTIFACTS_DIR", "artifacts"))
    raw_dir = artifacts_dir / "raw_batches"
    payload_dir = artifacts_dir / "payloads"
    failed_dir = artifacts_dir / "failed_payloads"
    logs_dir = artifacts_dir / "logs"
    last_raw_path = artifacts_dir / "last_raw_snapshot.json"
    last_payload_path = artifacts_dir / "last_payload_sent.json"
    last_delivery_meta_path = artifacts_dir / "last_delivery_meta.json"
    for p in (failed_dir, logs_dir):
        p.mkdir(parents=True, exist_ok=True)

    delivery_policy = resolve_delivery_policy(os.environ, "wazuh")
    mad_version = (os.getenv("MAD_VERSION") or "2.3.0").strip()
    wazuh_integration_version = (os.getenv("WAZUH_INTEGRATION_VERSION") or os.getenv("INTEGRATION_VERSION", "1.0.0")).strip()
    source = (os.getenv("SOURCE") or "mad-collector").strip()

    app_cfg = {
        "poll_interval_alerts": int(os.getenv("WAZUH_POLL_INTERVAL_ALERTS") or os.getenv("POLL_INTERVAL_ALERTS", 30)),
        "initial_lookback_hours": int(os.getenv("INITIAL_LOOKBACK_HOURS", 2)),
        "alert_batch_size": int(os.getenv("ALERT_BATCH_SIZE", 500)),
        "retry_failed_interval_seconds": int(os.getenv("WAZUH_RETRY_FAILED_INTERVAL_SECONDS") or os.getenv("RETRY_FAILED_INTERVAL_SECONDS", 30)),
        "min_rule_level": int(os.getenv("MIN_RULE_LEVEL", 7)),
        "delivery_policy": delivery_policy,
        "delivery_dir": str(artifacts_dir / "delivery-v2"),
        "mad_version": mad_version,
        "integration_version": wazuh_integration_version,
        "source": source,
        "dry_run": os.getenv("DRY_RUN", "false"),
        "non_retryable_backoff_seconds": int(os.getenv("NON_RETRYABLE_BACKOFF_SECONDS", 300)),
        "startup_menu_enabled": parse_bool(os.getenv("STARTUP_MENU_ENABLED", "true"), default=True),
        "startup_menu_default_option": os.getenv("STARTUP_MENU_DEFAULT_OPTION", "1"),
        "startup_require_all_tests": parse_bool(os.getenv("STARTUP_REQUIRE_ALL_TESTS", "true"), default=True),
        "raw_dir": str(raw_dir),
        "payload_dir": str(payload_dir),
        "failed_dir": str(failed_dir),
        "last_raw_path": str(last_raw_path),
        "last_payload_path": str(last_payload_path),
        "last_delivery_meta_path": str(last_delivery_meta_path),
    }

    logger.info("Starting WazuhC Agent...")
    logger.info("\n{}", WAZUH_BANNER)

    debug_log_path = logs_dir / "agent_console.json"
    log_max_mb = resolve_artifact_policy().log_max_mb
    try:
        log_retention(list(logs_dir.glob("agent_console.*.json")))
    except OSError as exc:
        logger.warning("Rotated log maintenance skipped: {}", type(exc).__name__)
    logger.add(debug_log_path, rotation=int(log_max_mb * 1024 * 1024),
               retention=log_retention, level=os.getenv("LOG_LEVEL", "INFO"), serialize=True)
    logger.info("Console logs are being saved as JSON to: {}", debug_log_path)

    indexer = None
    if indexer_host and indexer_user and indexer_pass:
        indexer = IndexerClient(indexer_host, indexer_user, indexer_pass, verify_certs=indexer_verify_tls)

    api = None
    if api_enabled and api_host and api_user and api_pass:
        api = WazuhApiClient(api_host, api_user, api_pass, verify_certs=api_verify_tls)

    sender = Sender(ingest_url) if ingest_url else None
    agent_polling_enabled = api_enabled and api is not None

    missing_required = collect_missing_required_config(
        tenant_id=tenant_id,
        api_key=api_key,
        ingest_url=ingest_url,
        indexer_host=indexer_host,
        indexer_user=indexer_user,
        indexer_pass=indexer_pass,
        api_host=api_host,
        api_user=api_user,
        api_pass=api_pass,
    )

    startup_action = resolve_startup_action(
        menu_enabled=app_cfg["startup_menu_enabled"],
        default_option=app_cfg["startup_menu_default_option"],
    )

    if startup_action in {"run_and_continue", "run_and_exit"}:
        precheck_results = await run_startup_integration_tests(
            indexer,
            api,
            sender,
            api_key,
            missing_required,
            api_enabled=api_enabled,
        )
        archive_json(
            logs_dir / "startup_precheck.json",
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "results": precheck_results,
            },
        )
        _, _, required_failed = log_precheck_results(precheck_results)
        api_result = next((r for r in precheck_results if r["name"] == "Wazuh API Authentication"), None)
        if api_enabled and api_result and not api_result["passed"]:
            agent_polling_enabled = False
            logger.warning(
                "Wazuh API precheck failed; alert collection will continue with Indexer only and agent inventory polling will be disabled for this run."
            )

        if startup_action == "run_and_exit":
            logger.info("Startup menu requested exit after integration tests.")
            if indexer is not None:
                await indexer.close()
            return

        pending_path = artifacts_dir / "delivery-v2" / "wazuh.json"
        pending_delivery = False
        if pending_path.exists():
            with pending_path.open(encoding="utf-8") as pending_file:
                pending_delivery = bool(json.load(pending_file).get("pending"))
        if required_failed and app_cfg["startup_require_all_tests"]:
            if pending_delivery and not missing_required:
                logger.warning("Startup prechecks failed; continuing to retry durable pending delivery before source collection.")
            else:
                logger.error("Startup aborted because required integration tests failed.")
                if indexer is not None:
                    await indexer.close()
                raise SystemExit(1)
    else:
        logger.warning("Startup prechecks were skipped by menu selection.")

    if missing_required:
        logger.error("Startup aborted due missing required configuration:")
        for missing_item in missing_required:
            logger.error(" - {}", missing_item)
        if indexer is not None:
            await indexer.close()
        raise SystemExit(1)

    if indexer is None or sender is None:
        logger.error("Startup aborted: required clients could not be initialized.")
        if indexer is not None:
            await indexer.close()
        raise SystemExit(1)

    if not agent_polling_enabled:
        if api_enabled:
            logger.warning("Wazuh API polling disabled for this run; only Indexer alerts will be collected.")
        else:
            logger.info("Wazuh API polling disabled by configuration; only Indexer alerts will be collected.")

    aggregator = Aggregator(tenant_id=str(tenant_id))
    state = StateStore(db_path=checkpoint_file)

    app = web.Application()
    app.router.add_get('/health', healthcheck_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', health_port)

    logger.info("Healthcheck endpoint available at http://0.0.0.0:{}/health", health_port)
    logger.info(
        "Runtime config | poll={}s | retry={}s | min_level={} | dry_run={} | backoff_non_retryable={}s | artifacts={}",
        app_cfg["poll_interval_alerts"],
        app_cfg["retry_failed_interval_seconds"],
        app_cfg["min_rule_level"],
        app_cfg["dry_run"],
        app_cfg["non_retryable_backoff_seconds"],
        artifacts_dir,
    )

    try:
        if args.once:
            await site.start()
            delivery_ok = await poll_alerts(indexer, aggregator, state, sender, tenant_id, company_id, api_key, app_cfg, single_run=True)
            if agent_polling_enabled and api is not None:
                await poll_agents(api, aggregator, state, single_run=True)
            logger.info("Single-run mode completed. Exiting.")
            if not delivery_ok:
                raise SystemExit(1)
        else:
            tasks = [
                site.start(),
                poll_alerts(indexer, aggregator, state, sender, tenant_id, company_id, api_key, app_cfg),
            ]
            if agent_polling_enabled and api is not None:
                tasks.append(poll_agents(api, aggregator, state))
            await asyncio.gather(*tasks)
    finally:
        if indexer is not None:
            await indexer.close()
        await runner.cleanup()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Agent stopped by user.")
