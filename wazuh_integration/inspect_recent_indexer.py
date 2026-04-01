import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

from src.indexer import IndexerClient


async def main():
    load_dotenv()

    client = IndexerClient(
        os.getenv("WAZUH_INDEXER_HOST"),
        os.getenv("WAZUH_INDEXER_USER"),
        os.getenv("WAZUH_INDEXER_PASSWORD"),
    )

    now = datetime.now(timezone.utc)
    since_24h = (now - timedelta(hours=24)).isoformat()

    queries = {
        "latest_any": {
            "size": 20,
            "sort": [
                {"timestamp": {"order": "desc"}},
                {"_id": {"order": "desc"}},
            ],
        },
        "last_24h_any": {
            "query": {"range": {"timestamp": {"gte": since_24h}}},
            "size": 20,
            "sort": [
                {"timestamp": {"order": "desc"}},
                {"_id": {"order": "desc"}},
            ],
        },
        "last_24h_high_critical": {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": since_24h}}},
                        {"range": {"rule.level": {"gte": 12}}},
                    ]
                }
            },
            "size": 50,
            "sort": [
                {"timestamp": {"order": "desc"}},
                {"_id": {"order": "desc"}},
            ],
        },
    }

    results = {}
    try:
        for name, body in queries.items():
            resp = await client.client.search(index="wazuh-alerts-*", body=body)
            hits = resp["hits"]["hits"]
            results[name] = {
                "count": len(hits),
                "items": [
                    {
                        "timestamp": hit.get("_source", {}).get("timestamp"),
                        "rule_id": hit.get("_source", {}).get("rule", {}).get("id"),
                        "level": hit.get("_source", {}).get("rule", {}).get("level"),
                        "description": hit.get("_source", {}).get("rule", {}).get("description"),
                        "agent": hit.get("_source", {}).get("agent", {}).get("name"),
                        "id": hit.get("_id"),
                    }
                    for hit in hits
                ],
            }
    finally:
        await client.close()

    out = Path("debug_output") / "inspect_recent_indexer.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(results, indent=4, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"output": str(out), **{k: v['count'] for k, v in results.items()}}, indent=4, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
