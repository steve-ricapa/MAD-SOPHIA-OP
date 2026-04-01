import argparse
import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

from src.aggregator import Aggregator
from src.indexer import IndexerClient


def parse_args():
    parser = argparse.ArgumentParser(
        description="Busca alertas high/critical reales en el historico de Wazuh."
    )
    parser.add_argument("--hours", type=int, default=4000, help="Ventana historica a revisar")
    parser.add_argument("--batch-size", type=int, default=1000, help="Tamano de pagina para OpenSearch")
    parser.add_argument("--limit", type=int, default=None, help="Maximo de alertas a leer")
    parser.add_argument("--sample-size", type=int, default=20, help="Cantidad de hallazgos de muestra a guardar")
    return parser.parse_args()


async def main():
    args = parse_args()
    load_dotenv()

    start_time = (datetime.now(timezone.utc) - timedelta(hours=args.hours)).isoformat()
    indexer = IndexerClient(
        os.getenv("WAZUH_INDEXER_HOST"),
        os.getenv("WAZUH_INDEXER_USER"),
        os.getenv("WAZUH_INDEXER_PASSWORD"),
    )
    aggregator = Aggregator(tenant_id=str(os.getenv("TXDXAI_COMPANY_ID", "0")))

    try:
        raw_alerts = await indexer.get_alerts_range(
            start_timestamp=start_time,
            batch_size=args.batch_size,
            max_alerts=args.limit,
        )
    finally:
        await indexer.close()

    processed = [aggregator.normalize_alert(alert) for alert in raw_alerts]
    high_critical = [f for f in processed if f.get("severity") in {"high", "critical"}]

    by_severity = {"critical": 0, "high": 0}
    for finding in high_critical:
        by_severity[finding["severity"]] += 1

    sample = high_critical[: args.sample_size]
    debug_dir = Path("debug_output")
    debug_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sample_path = debug_dir / f"high_critical_sample_{stamp}.json"

    with open(sample_path, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "searched_from": start_time,
                "total_alerts_scanned": len(processed),
                "high_critical_counts": by_severity,
                "sample_findings": sample,
            },
            fh,
            indent=4,
            ensure_ascii=False,
        )

    print(json.dumps(
        {
            "searched_from": start_time,
            "total_alerts_scanned": len(processed),
            "critical": by_severity["critical"],
            "high": by_severity["high"],
            "sample_file": str(sample_path),
        },
        indent=4,
        ensure_ascii=False,
    ))


if __name__ == "__main__":
    asyncio.run(main())
