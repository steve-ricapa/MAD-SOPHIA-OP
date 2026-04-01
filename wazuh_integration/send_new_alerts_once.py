import asyncio
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

from src.aggregator import Aggregator
from src.api import WazuhApiClient
from src.indexer import IndexerClient
from src.sender import Sender
from src.state import StateStore


def parse_state_json(raw_value):
    if not raw_value:
        return None
    try:
        return json.loads(raw_value)
    except (json.JSONDecodeError, TypeError):
        return None


async def main():
    load_dotenv()

    company_id = int(os.getenv("TXDXAI_COMPANY_ID", 0))
    api_key = os.getenv("TXDXAI_API_KEY")
    batch_size = int(os.getenv("ALERT_BATCH_SIZE", 500))
    min_level = int(os.getenv("MIN_RULE_LEVEL", 0))
    fallback_hours = int(os.getenv("INITIAL_LOOKBACK_HOURS", 2))

    state = StateStore()
    checkpoint = state.get_checkpoint("alerts_timestamp", default=None)
    if checkpoint is None:
        checkpoint = (datetime.now(timezone.utc) - timedelta(hours=fallback_hours)).isoformat()

    api = WazuhApiClient(
        os.getenv("WAZUH_API_HOST"),
        os.getenv("WAZUH_API_USER"),
        os.getenv("WAZUH_API_PASSWORD"),
    )
    indexer = IndexerClient(
        os.getenv("WAZUH_INDEXER_HOST"),
        os.getenv("WAZUH_INDEXER_USER"),
        os.getenv("WAZUH_INDEXER_PASSWORD"),
    )
    sender = Sender(os.getenv("TXDXAI_INGEST_URL"))
    aggregator = Aggregator(tenant_id=str(company_id))

    agent_summary = None
    try:
        agent_summary = await api.get_agents_summary()
        if not agent_summary:
            agent_summary = parse_state_json(state.get_checkpoint("agent_summary", default=None))

        raw_alerts = await indexer.get_new_alerts(checkpoint, limit=batch_size)
        filtered_alerts = [
            alert for alert in raw_alerts
            if int(alert.get("rule", {}).get("level", 0)) >= min_level
        ]

        processed = [aggregator.normalize_alert(alert) for alert in filtered_alerts]
        scan_id = str(uuid.uuid4())
        report = aggregator.create_report(
            processed,
            agent_summary,
            {"scan_id": scan_id, "company_id": company_id, "api_key": api_key},
        )

        debug_dir = Path("debug_output")
        debug_dir.mkdir(exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        payload_path = debug_dir / f"send_new_alerts_once_{stamp}.json"
        with open(payload_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=4, ensure_ascii=False)

        if processed:
            sent = await sender.send_report(report)
            if sent:
                state.update_checkpoint("alerts_timestamp", raw_alerts[-1]["timestamp"])
        else:
            sent = True

        print(json.dumps({
            "checkpoint_used": checkpoint,
            "raw_alerts": len(raw_alerts),
            "filtered_alerts": len(filtered_alerts),
            "scan_id": scan_id,
            "payload_file": str(payload_path),
            "sent": sent,
            "next_checkpoint": raw_alerts[-1]["timestamp"] if raw_alerts and sent else checkpoint,
        }, indent=4, ensure_ascii=False))
    finally:
        await indexer.close()


if __name__ == "__main__":
    asyncio.run(main())
