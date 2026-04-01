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

async def poll_alerts(indexer, aggregator, state, sender, company_id, api_key):
    """Loop to fetch and send alerts."""
    empty_cycles = 0
    max_empty_cycles = 6 # Send heartbeat every ~1 minute if POLL_INTERVAL is 10s
    
    while True:
        try:
            # Checkpoint management: default to last 30 minutes if fresh
            default_time = (datetime.now(timezone.utc) - timedelta(minutes=120)).isoformat()
            last_ts = state.get_checkpoint("alerts_timestamp", default=None)
            
            if last_ts is None:
                logger.info(f"Fresh start: No checkpoint found. Polling alerts from last 120 min ({default_time})...")
                last_ts = default_time
            else:
                logger.info(f"Polling alerts since {last_ts}...")
            batch_size = int(os.getenv("ALERT_BATCH_SIZE", 500))
            raw_alerts = await indexer.get_new_alerts(last_ts, limit=batch_size)
            
            # Data Reduction: Filter by minimum rule level
            min_level = int(os.getenv("MIN_RULE_LEVEL", 3))
            raw_alerts = [a for a in raw_alerts if int(a.get('rule', {}).get('level', 0)) >= min_level]
            
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
                logger.success(f"Security Feed: {len(raw_alerts)} new events detected.")
                processed = [aggregator.normalize_alert(a) for a in raw_alerts]
                report = aggregator.create_report(processed, agent_summary, config)
                
                dry_run = os.getenv("DRY_RUN", "false").lower() == "true"
                
                if dry_run:
                    # Professional Dry-Run Summary
                    sm = report.get('scan_summary', {})
                    logger.info("--- [DRY_RUN SUMMARY] ---")
                    logger.info(f" | Scan ID:     {scan_id}")
                    logger.info(f" | Findings:    {len(report.get('findings', []))}")
                    logger.info(f" | Criticalss:  {sm.get('disaster_count', 0)}")
                    logger.info(f" | Highs:       {sm.get('high_count', 0)}")
                    logger.info("--------------------------")
                    
                    # Save to file
                    debug_dir = Path("debug_output")
                    debug_dir.mkdir(exist_ok=True)
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    file_name = debug_dir / f"report_{timestamp}_{scan_id}.json"
                    
                    with open(file_name, "w", encoding="utf-8") as f:
                        json.dump(report, f, indent=4, ensure_ascii=False)
                    
                    logger.info(f"Report payload archived: {file_name}")
                    success = True
                else:
                    success = await sender.send_report(report)

                if success:
                    new_last_ts = raw_alerts[-1]['timestamp']
                    state.update_checkpoint("alerts_timestamp", new_last_ts)
                    logger.debug(f"Sync checkpoint advanced to: {new_last_ts}")
            else:
                empty_cycles += 1
                if empty_cycles >= max_empty_cycles:
                    logger.info("Security Feed: No activity in last minute. Sending heartbeat...")
                    heartbeat_report = aggregator.create_report([], agent_summary, config)
                    heartbeat_report['event_type'] = "wazuh_heartbeat"
                    
                    if os.getenv("DRY_RUN", "false").lower() == "true":
                        logger.info("Heartbeat skipped (Dry Run).")
                    else:
                        await sender.send_report(heartbeat_report)
                    
                    empty_cycles = 0
                else:
                    # Silently log cycles in debug, keep console clean
                    logger.debug(f"Quiet period... cycle {empty_cycles}")
                
        except Exception as e:
            logger.exception(f"Error in poll_alerts loop: {e}")
            
        await asyncio.sleep(int(os.getenv("POLL_INTERVAL_ALERTS", 10)))

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
    
    # Configuration
    company_id = int(os.getenv("TXDXAI_COMPANY_ID", 0))
    api_key = os.getenv("TXDXAI_API_KEY")
    indexer_host = os.getenv("WAZUH_INDEXER_HOST")
    indexer_user = os.getenv("WAZUH_INDEXER_USER")
    indexer_pass = os.getenv("WAZUH_INDEXER_PASSWORD")
    api_host = os.getenv("WAZUH_API_HOST")
    api_user = os.getenv("WAZUH_API_USER")
    api_pass = os.getenv("WAZUH_API_PASSWORD")
    ingest_url = os.getenv("TXDXAI_INGEST_URL")

    logger.info("Starting WazuhC Agent...")

    # Configure logging to file (JSON format for detailed inspection)
    debug_log_path = Path("debug_output") / "agent_console.json"
    logger.add(debug_log_path, rotation="10 MB", level=os.getenv("LOG_LEVEL", "INFO"), serialize=True)
    logger.info(f"Console logs are being saved as JSON to: {debug_log_path}")

    # Initialize components
    indexer = IndexerClient(indexer_host, indexer_user, indexer_pass)
    api = WazuhApiClient(api_host, api_user, api_pass)
    aggregator = Aggregator(tenant_id=str(company_id))
    state = StateStore()
    sender = Sender(ingest_url)

    # Healthcheck setup
    app = web.Application()
    app.router.add_get('/health', healthcheck_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 8080)
    
    logger.info("Healthcheck endpoint available at http://0.0.0.0:8080/health")

    try:
        await asyncio.gather(
            site.start(),
            poll_alerts(indexer, aggregator, state, sender, company_id, api_key),
            poll_agents(api, aggregator, state)
        )
    finally:
        await indexer.close()
        await runner.cleanup()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Agent stopped by user.")
