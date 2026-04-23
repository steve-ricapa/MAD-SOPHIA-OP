import asyncio
import os
import uuid
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from loguru import logger

from src.indexer import IndexerClient
from src.api import WazuhApiClient
from src.aggregator import Aggregator
from src.state import StateStore
from src.sender import Sender


WAZUH_BANNER = r"""
 __        __   _    _____ _   _ _   _
 \ \      / /  / \  |__  /| | | | | | |
  \ \ /\ / /  / _ \   / / | | | | |_| |
   \ V  V /  / ___ \ / /_ | |_| |  _  |
    \_/\_/  /_/   \_\____| \___/|_| |_|
"""


def parse_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def archive_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


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
                logger.info("Retry queue: {} pending payload(s)", len(failed_files))

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
                    logger.success("Retry succeeded: {}", retried_name)
                else:
                    logger.warning("Retry failed, keeping queued payload: {}", failed_file.name)
                    break
        except Exception as e:
            logger.exception(f"Error in retry_failed_payloads loop: {e}")

        await asyncio.sleep(int(app_cfg["retry_failed_interval_seconds"]))


async def poll_alerts(indexer, aggregator, state, sender, company_id, api_key, app_cfg):
    """Loop to fetch, deduplicate, archive and send alerts."""
    empty_cycles = 0
    max_empty_cycles = max(1, int(app_cfg["heartbeat_cycles"]))

    while True:
        try:
            default_time = (datetime.now(timezone.utc) - timedelta(hours=app_cfg["initial_lookback_hours"])).isoformat()
            last_ts = state.get_checkpoint("alerts_timestamp", default=None)

            if last_ts is None:
                logger.info(f"Fresh start: no checkpoint found, polling since {default_time}")
                last_ts = default_time
                state.update_checkpoint("alerts_timestamp", last_ts)
            else:
                logger.info(f"Polling alerts since {last_ts}...")

            batch_size = int(app_cfg["alert_batch_size"])
            raw_alerts = await indexer.get_new_alerts(last_ts, limit=batch_size)
            raw_count = len(raw_alerts)

            min_level = int(app_cfg["min_rule_level"])
            raw_alerts = [a for a in raw_alerts if int(a.get('rule', {}).get('level', 0)) >= min_level]

            unique_alerts = []
            for alert in raw_alerts:
                alert_id = alert.get("_id")
                if not state.is_alert_processed(alert_id):
                    unique_alerts.append(alert)

            agent_summary = state.get_checkpoint("agent_summary", default=None)
            if agent_summary:
                try:
                    agent_summary = json.loads(agent_summary)
                except (json.JSONDecodeError, TypeError):
                    agent_summary = None

            scan_id = str(uuid.uuid4())
            config = {"scan_id": scan_id, "company_id": company_id, "api_key": api_key}

            if raw_alerts:
                empty_cycles = 0
                logger.success(
                    "Security feed: raw={} | after_level_filter={} | unique_for_send={}",
                    raw_count,
                    len(raw_alerts),
                    len(unique_alerts),
                )

                if not unique_alerts:
                    new_last_ts = raw_alerts[-1]["timestamp"]
                    state.update_checkpoint("alerts_timestamp", new_last_ts)
                    state.purge_processed_alerts(app_cfg["dedup_retention_days"])
                    logger.info("All alerts in this cycle were already processed; no payload sent")
                    continue

                processed = [aggregator.normalize_alert(a) for a in unique_alerts]
                report = aggregator.create_report(processed, agent_summary, config)

                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                archive_json(
                    Path(app_cfg["raw_dir"]) / f"raw_{timestamp}_{scan_id}.json",
                    {
                        "scan_id": scan_id,
                        "checkpoint_used": last_ts,
                        "raw_alerts": raw_alerts,
                        "unique_alerts": unique_alerts,
                    },
                )
                archive_json(
                    Path(app_cfg["payload_dir"]) / f"payload_{timestamp}_{scan_id}.json",
                    report,
                )

                dry_run = parse_bool(app_cfg["dry_run"], default=False)

                if dry_run:
                    sm = report.get('scan_summary', {})
                    logger.info("DRY_RUN enabled: payload not sent")
                    logger.info(
                        "Scan ID: {} | findings={} | critical={} | high={}",
                        scan_id,
                        len(report.get("findings", [])),
                        sm.get("disaster_count", 0),
                        sm.get("high_count", 0),
                    )
                    success = True
                else:
                    success = await sender.send_report(report)

                if success:
                    new_last_ts = raw_alerts[-1]["timestamp"]
                    state.update_checkpoint("alerts_timestamp", new_last_ts)
                    state.mark_alerts_processed([a.get("_id") for a in unique_alerts])
                    state.purge_processed_alerts(app_cfg["dedup_retention_days"])
                    logger.debug(f"Sync checkpoint advanced to {new_last_ts}")
                else:
                    failed_name = f"failed_{timestamp}_{scan_id}.json"
                    archive_json(Path(app_cfg["failed_dir"]) / failed_name, report)
                    logger.error(f"Payload send failed. Saved for retry/inspection: {failed_name}")
            else:
                empty_cycles += 1
                if empty_cycles >= max_empty_cycles:
                    if not app_cfg["send_heartbeat"]:
                        logger.info("Security feed idle, heartbeat disabled")
                    else:
                        logger.info("Security feed idle, sending heartbeat")
                        heartbeat_report = aggregator.create_report([], agent_summary, config)
                        heartbeat_report['event_type'] = "wazuh_heartbeat"

                        if parse_bool(app_cfg["dry_run"], default=False):
                            logger.info("Heartbeat skipped (DRY_RUN)")
                        else:
                            await sender.send_report(heartbeat_report)

                    empty_cycles = 0
                else:
                    logger.debug(f"Quiet period... cycle {empty_cycles}")

        except Exception as e:
            logger.exception(f"Error in poll_alerts loop: {e}")

        await asyncio.sleep(int(app_cfg["poll_interval_alerts"]))

async def poll_agents(api, aggregator, state):
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
                    logger.warning(f"Inventory Change: {len(changes)} agents changed status.")
                    for change in changes:
                        logger.info(f" | Agent: {change['name']} ({change['old_status']} -> {change['new_status']})")
                
                logger.info(f"Inventory Health: {summary.get('active', 0)} active / {summary.get('total', 0)} total agents.")
        except Exception as e:
            logger.error(f"Error in poll_agents loop: {e}")
            
        await asyncio.sleep(int(os.getenv("POLL_INTERVAL_AGENTS", 60)))

from aiohttp import web


async def healthcheck_handler(request):
    """Provides a basic healthcheck endpoint."""
    return web.json_response({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})


async def main():
    load_dotenv()

    company_id = int(os.getenv("TXDXAI_COMPANY_ID", 0))
    api_key = os.getenv("TXDXAI_API_KEY")
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

    app_cfg = {
        "poll_interval_alerts": int(os.getenv("POLL_INTERVAL_ALERTS", 30)),
        "initial_lookback_hours": int(os.getenv("INITIAL_LOOKBACK_HOURS", 2)),
        "alert_batch_size": int(os.getenv("ALERT_BATCH_SIZE", 500)),
        "retry_failed_interval_seconds": int(os.getenv("RETRY_FAILED_INTERVAL_SECONDS", 30)),
        "min_rule_level": int(os.getenv("MIN_RULE_LEVEL", 7)),
        "dedup_retention_days": int(os.getenv("DEDUP_RETENTION_DAYS", 7)),
        "heartbeat_cycles": int(os.getenv("HEARTBEAT_EMPTY_CYCLES", 6)),
        "send_heartbeat": parse_bool(os.getenv("SEND_HEARTBEAT", "false"), default=False),
        "dry_run": os.getenv("DRY_RUN", "false"),
        "raw_dir": str(raw_dir),
        "payload_dir": str(payload_dir),
        "failed_dir": str(failed_dir),
    }

    logger.info("Starting WazuhC Agent...")
    logger.info("\n{}", WAZUH_BANNER)

    debug_log_path = logs_dir / "agent_console.json"
    logger.add(debug_log_path, rotation="10 MB", level=os.getenv("LOG_LEVEL", "INFO"), serialize=True)
    logger.info(f"Console logs are being saved as JSON to: {debug_log_path}")

    indexer = IndexerClient(indexer_host, indexer_user, indexer_pass, verify_certs=indexer_verify_tls)
    api = WazuhApiClient(api_host, api_user, api_pass, verify_certs=api_verify_tls)
    aggregator = Aggregator(tenant_id=str(company_id))
    state = StateStore(db_path=checkpoint_file)
    sender = Sender(ingest_url)

    app = web.Application()
    app.router.add_get('/health', healthcheck_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', health_port)

    logger.info(f"Healthcheck endpoint available at http://0.0.0.0:{health_port}/health")
    logger.info(
        "Runtime config | poll={}s | retry={}s | min_level={} | dry_run={} | artifacts={}",
        app_cfg["poll_interval_alerts"],
        app_cfg["retry_failed_interval_seconds"],
        app_cfg["min_rule_level"],
        app_cfg["dry_run"],
        artifacts_dir,
    )

    try:
        await asyncio.gather(
            site.start(),
            poll_alerts(indexer, aggregator, state, sender, company_id, api_key, app_cfg),
            poll_agents(api, aggregator, state),
            retry_failed_payloads(sender, app_cfg),
        )
    finally:
        await indexer.close()
        await runner.cleanup()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Agent stopped by user.")
