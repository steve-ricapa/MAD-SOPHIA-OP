import argparse
import asyncio
import hashlib
import json
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
from snapshot import build_snapshot_signature, decide_snapshot_send


WAZUH_BANNER = r"""
 __        __   _    _____ _   _ _   _
 \ \      / /  / \  |__  /| | | | | | |
  \ \ /\ / /  / _ \   / / | | | | |_| |
   \ V  V /  / ___ \ / /_ | |_| |  _  |
    \_/\_/  /_/   \_\____| \___/|_| |_|
"""

NON_RETRYABLE_FAILURE_KINDS = {
    "config_missing_api_key",
    "auth",
    "validation",
    "endpoint_not_found",
}


def parse_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def archive_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def collect_missing_required_config(company_id, api_key, ingest_url, indexer_host, indexer_user, indexer_pass, api_host, api_user, api_pass):
    checks = {
        "TXDXAI_COMPANY_ID (>0)": company_id > 0,
        "TXDXAI_API_KEY_WAZUH / TXDXAI_API_KEY / API_KEY": bool(api_key),
        "TXDXAI_INGEST_URL": bool(ingest_url),
        "WAZUH_INDEXER_HOST": bool(indexer_host),
        "WAZUH_INDEXER_USER": bool(indexer_user),
        "WAZUH_INDEXER_PASSWORD": bool(indexer_pass),
        "WAZUH_API_HOST": bool(api_host),
        "WAZUH_API_USER": bool(api_user),
        "WAZUH_API_PASSWORD": bool(api_pass),
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


async def run_startup_integration_tests(indexer, api, sender, api_key, missing_required):
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

    if api is None:
        results.append(
            {
                "name": "Wazuh API Authentication",
                "required": True,
                "passed": False,
                "details": "missing Wazuh API configuration",
            }
        )
    else:
        auth_ok = await api._authenticate()
        results.append(
            {
                "name": "Wazuh API Authentication",
                "required": True,
                "passed": auth_ok,
                "details": "token acquired successfully" if auth_ok else "authentication failed (401 or connectivity issue)",
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
            details = "ping failed"
        results.append(
            {
                "name": "Wazuh Indexer Connectivity",
                "required": True,
                "passed": ping_ok,
                "details": details,
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
            }
        )

    return results


async def retry_failed_payloads(sender, app_cfg):
    """Retries payloads that failed to send due to transient issues."""
    failed_dir = Path(app_cfg["failed_dir"])
    payload_dir = Path(app_cfg["payload_dir"])
    invalid_dir = failed_dir / "invalid"
    invalid_dir.mkdir(parents=True, exist_ok=True)

    while True:
        try:
            failed_files = sorted(failed_dir.glob("failed_*.json"), key=lambda p: p.stat().st_mtime)

            if failed_files:
                logger.info("Retry queue status | pending_payloads={}", len(failed_files))

            for failed_file in failed_files:
                try:
                    with open(failed_file, "r", encoding="utf-8") as f:
                        payload = json.load(f)
                except Exception as e:
                    invalid_target = invalid_dir / failed_file.name
                    failed_file.replace(invalid_target)
                    logger.error("Invalid failed payload moved to {}: {}", invalid_target.name, e)
                    continue

                if parse_bool(app_cfg["dry_run"], default=False):
                    logger.info("DRY_RUN enabled: skipping retry for {}", failed_file.name)
                    continue

                success = await sender.send_report(payload)
                if success:
                    retried_name = failed_file.name.replace("failed_", "retried_")
                    retried_target = payload_dir / retried_name
                    failed_file.replace(retried_target)
                    logger.success("Retry succeeded | file={} | moved_to={}", failed_file.name, retried_target.name)
                else:
                    failure_kind = sender.last_failure_kind or "unknown"
                    status_code = sender.last_status_code

                    if failure_kind in NON_RETRYABLE_FAILURE_KINDS:
                        invalid_target = invalid_dir / failed_file.name
                        failed_file.replace(invalid_target)
                        logger.error(
                            "Retry marked non-retryable | file={} | kind={} | status={} | moved_to={}",
                            failed_file.name,
                            failure_kind,
                            status_code,
                            invalid_target.name,
                        )
                        continue

                    logger.warning(
                        "Retry failed, keeping queued payload | file={} | kind={} | status={}",
                        failed_file.name,
                        failure_kind,
                        status_code,
                    )
                    break
        except Exception as e:
            logger.exception(f"Error in retry_failed_payloads loop: {e}")

        await asyncio.sleep(int(app_cfg["retry_failed_interval_seconds"]))


async def poll_alerts(indexer, aggregator, state, sender, company_id, api_key, app_cfg, single_run=False):
    """Snapshot-based loop: fetch full window, compute signature, decide send."""
    while True:
        try:
            window_end = datetime.now(timezone.utc)
            window_start = window_end - timedelta(hours=app_cfg["initial_lookback_hours"])
            w_start_str = window_start.isoformat()
            w_end_str = window_end.isoformat()

            logger.info("Snapshot cycle | window=[{}, {}]", w_start_str, w_end_str)

            batch_size = int(app_cfg["alert_batch_size"])
            raw_alerts = await indexer.get_new_alerts(w_start_str, limit=batch_size)
            raw_count = len(raw_alerts)

            min_level = int(app_cfg["min_rule_level"])
            raw_alerts = [a for a in raw_alerts if int(a.get('rule', {}).get('level', 0)) >= min_level]
            filtered_count = len(raw_alerts)

            findings = [aggregator.normalize_alert(a) for a in raw_alerts]

            agent_summary = state.get_checkpoint("agent_summary", default=None)
            if agent_summary:
                try:
                    agent_summary = json.loads(agent_summary)
                except (json.JSONDecodeError, TypeError):
                    agent_summary = None

            prev_signature = str(state.get_checkpoint("snapshot_signature", ""))
            unchanged_cycles = int(state.get_checkpoint("unchanged_cycles", "0") or "0")
            has_sent_once = parse_bool(state.get_checkpoint("has_sent_once", "false"), default=False)

            current_signature = build_snapshot_signature(findings, agent_summary, w_start_str, w_end_str)

            snapshot_decision = decide_snapshot_send(
                current_signature=current_signature,
                previous_signature=prev_signature,
                unchanged_cycles=unchanged_cycles,
                has_sent_once=has_sent_once,
                force_send_every_cycles=int(app_cfg["force_send_every_cycles"]),
                snapshot_always_send=bool(app_cfg["snapshot_always_send"]),
            )
            send_reason = str(snapshot_decision.get("reason", "snapshot_changed"))
            should_send = bool(snapshot_decision.get("should_send", False))
            snapshot_changed = bool(snapshot_decision.get("changed", False))
            unchanged_cycles = int(snapshot_decision.get("unchanged_cycles", 0))
            snapshot_mode = "always" if app_cfg["snapshot_always_send"] else "delta_with_periodic_forced"

            idempotency_digest = hashlib.sha256(current_signature.encode("utf-8")).hexdigest()
            idempotency_key = f"sha256:{idempotency_digest}"

            state.update_checkpoint("snapshot_signature", current_signature)
            state.update_checkpoint("unchanged_cycles", str(unchanged_cycles))
            state.update_checkpoint("last_idempotency_key", idempotency_key)

            if not should_send:
                state.update_checkpoint("last_send_result", "skipped_no_change")
                logger.info(
                    "Snapshot sin cambios | cycle_unchanged={} reason={} sig={}",
                    unchanged_cycles,
                    send_reason,
                    current_signature[:16],
                )
            else:
                scan_id = str(uuid.uuid4())
                config = {"scan_id": scan_id, "company_id": company_id, "api_key": api_key}

                report = aggregator.create_report(
                    findings, agent_summary, config,
                    idempotency_key=idempotency_key,
                    snapshot_signature=current_signature,
                    snapshot_mode=snapshot_mode,
                    send_reason=send_reason,
                    snapshot_changed=snapshot_changed,
                    mad_version=app_cfg["mad_version"],
                    integration_version=app_cfg["integration_version"],
                    source=app_cfg["source"],
                )

                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                archive_json(
                    Path(app_cfg["raw_dir"]) / f"raw_{timestamp}_{scan_id}.json",
                    {
                        "scan_id": scan_id,
                        "window": {"start": w_start_str, "end": w_end_str},
                        "raw_count": raw_count,
                        "filtered_count": filtered_count,
                        "finding_count": len(findings),
                        "snapshot_signature": current_signature,
                        "send_reason": send_reason,
                        "raw_alerts": raw_alerts,
                    },
                )
                archive_json(
                    Path(app_cfg["payload_dir"]) / f"payload_{timestamp}_{scan_id}.json",
                    report,
                )

                dry_run = parse_bool(app_cfg["dry_run"], default=False)
                success = False

                if dry_run:
                    logger.info("DRY_RUN enabled: payload not sent")
                    logger.info(
                        "Snapshot | scan_id={} | findings={} | reason={} | results={}",
                        scan_id,
                        len(findings),
                        send_reason,
                        report["scan_summary"]["results"],
                    )
                    success = True
                else:
                    success = await sender.send_report(report)

                if success:
                    state.update_checkpoint("has_sent_once", "true")
                    state.update_checkpoint("last_send_result", "sent")
                    state.update_checkpoint("last_sent_at", datetime.now(timezone.utc).isoformat())
                    logger.success(
                        "Snapshot sent | scan_id={} | findings={} | reason={} | changed={} | sig={}",
                        scan_id,
                        len(findings),
                        send_reason,
                        snapshot_changed,
                        current_signature[:16],
                    )
                else:
                    failure_kind = sender.last_failure_kind or "unknown"
                    status_code = sender.last_status_code
                    state.update_checkpoint("last_send_result", f"failed_{failure_kind}")

                    if failure_kind in NON_RETRYABLE_FAILURE_KINDS:
                        logger.error(
                            "Non-retryable backend failure | kind={} | status={} | cooldown={}s",
                            failure_kind,
                            status_code,
                            app_cfg["non_retryable_backoff_seconds"],
                        )
                        await asyncio.sleep(int(app_cfg["non_retryable_backoff_seconds"]))
                    else:
                        failed_name = f"failed_{timestamp}_{scan_id}.json"
                        archive_json(Path(app_cfg["failed_dir"]) / failed_name, report)
                        logger.error(
                            "Snapshot send failed (retryable). Saved: {}",
                            failed_name,
                        )

        except Exception as e:
            logger.exception(f"Error in poll_alerts cycle: {e}")

        if single_run:
            logger.info("Single-run mode: poll_alerts completed one cycle.")
            break
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
        await asyncio.sleep(int(os.getenv("POLL_INTERVAL_AGENTS", 60)))

from aiohttp import web


async def healthcheck_handler(request):
    """Provides a basic healthcheck endpoint."""
    return web.json_response({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})


async def main():
    parser = argparse.ArgumentParser(description="Wazuh real-time integration agent")
    parser.add_argument("--once", action="store_true", help="Run one cycle and exit")
    args = parser.parse_args()

    load_dotenv()

    company_id = int(os.getenv("TXDXAI_COMPANY_ID", 0))
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
    ingest_url = os.getenv("TXDXAI_INGEST_URL")
    health_port = int(os.getenv("HEALTH_CHECK_PORT", 8000))
    checkpoint_file = os.getenv("CHECKPOINT_FILE", "state/agent_state.db")

    artifacts_dir = Path(os.getenv("ARTIFACTS_DIR", "artifacts"))
    raw_dir = artifacts_dir / "raw_batches"
    payload_dir = artifacts_dir / "payloads"
    failed_dir = artifacts_dir / "failed_payloads"
    logs_dir = artifacts_dir / "logs"
    for p in (raw_dir, payload_dir, failed_dir, logs_dir):
        p.mkdir(parents=True, exist_ok=True)

    force_send_every_cycles = int(os.getenv("WAZUH_FORCE_SEND_EVERY_CYCLES") or os.getenv("FORCE_SEND_EVERY_CYCLES", "10"))
    snapshot_always_send = parse_bool(os.getenv("WAZUH_SNAPSHOT_ALWAYS_SEND") or os.getenv("SNAPSHOT_ALWAYS_SEND"), default=False)
    mad_version = (os.getenv("MAD_VERSION") or "2.3.0").strip()
    wazuh_integration_version = (os.getenv("WAZUH_INTEGRATION_VERSION") or os.getenv("INTEGRATION_VERSION", "1.0.0")).strip()
    source = (os.getenv("SOURCE") or "mad-collector").strip()

    app_cfg = {
        "poll_interval_alerts": int(os.getenv("POLL_INTERVAL_ALERTS", 30)),
        "initial_lookback_hours": int(os.getenv("INITIAL_LOOKBACK_HOURS", 2)),
        "alert_batch_size": int(os.getenv("ALERT_BATCH_SIZE", 500)),
        "retry_failed_interval_seconds": int(os.getenv("RETRY_FAILED_INTERVAL_SECONDS", 30)),
        "min_rule_level": int(os.getenv("MIN_RULE_LEVEL", 7)),
        "force_send_every_cycles": force_send_every_cycles,
        "snapshot_always_send": snapshot_always_send,
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
    }

    logger.info("Starting WazuhC Agent...")
    logger.info("\n{}", WAZUH_BANNER)

    debug_log_path = logs_dir / "agent_console.json"
    logger.add(debug_log_path, rotation="10 MB", level=os.getenv("LOG_LEVEL", "INFO"), serialize=True)
    logger.info("Console logs are being saved as JSON to: {}", debug_log_path)

    indexer = None
    if indexer_host and indexer_user and indexer_pass:
        indexer = IndexerClient(indexer_host, indexer_user, indexer_pass, verify_certs=indexer_verify_tls)

    api = None
    if api_host and api_user and api_pass:
        api = WazuhApiClient(api_host, api_user, api_pass, verify_certs=api_verify_tls)

    sender = Sender(ingest_url) if ingest_url else None

    missing_required = collect_missing_required_config(
        company_id=company_id,
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
        precheck_results = await run_startup_integration_tests(indexer, api, sender, api_key, missing_required)
        _, _, required_failed = log_precheck_results(precheck_results)

        if startup_action == "run_and_exit":
            logger.info("Startup menu requested exit after integration tests.")
            if indexer is not None:
                await indexer.close()
            return

        if required_failed and app_cfg["startup_require_all_tests"]:
            logger.error("Startup aborted because required integration tests failed.")
            if indexer is not None:
                await indexer.close()
            return
    else:
        logger.warning("Startup prechecks were skipped by menu selection.")

    if missing_required:
        logger.error("Startup aborted due missing required configuration:")
        for missing_item in missing_required:
            logger.error(" - {}", missing_item)
        if indexer is not None:
            await indexer.close()
        return

    if indexer is None or api is None or sender is None:
        logger.error("Startup aborted: required clients could not be initialized.")
        if indexer is not None:
            await indexer.close()
        return

    aggregator = Aggregator(tenant_id=str(company_id))
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
            await poll_alerts(indexer, aggregator, state, sender, company_id, api_key, app_cfg, single_run=True)
            await poll_agents(api, aggregator, state, single_run=True)
            logger.info("Single-run mode completed. Exiting.")
        else:
            await asyncio.gather(
                site.start(),
                poll_alerts(indexer, aggregator, state, sender, company_id, api_key, app_cfg),
                poll_agents(api, aggregator, state),
                retry_failed_payloads(sender, app_cfg),
            )
    finally:
        if indexer is not None:
            await indexer.close()
        await runner.cleanup()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Agent stopped by user.")
