import argparse
import asyncio
import json
import os
import uuid
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

from src.aggregator import Aggregator
from src.api import WazuhApiClient
from src.indexer import IndexerClient
from src.sender import Sender


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extrae alertas de Wazuh, arma un payload completo y opcionalmente lo reenvia al dashboard."
    )
    parser.add_argument("--hours", type=int, default=24, help="Ventana historica a consultar")
    parser.add_argument("--min-level", type=int, default=0, help="Nivel minimo de regla a incluir")
    parser.add_argument("--batch-size", type=int, default=1000, help="Tamano de pagina para OpenSearch")
    parser.add_argument("--limit", type=int, default=None, help="Maximo de alertas a procesar")
    parser.add_argument("--send", action="store_true", help="Enviar el payload al backend configurado")
    return parser.parse_args()


def print_block(title):
    print(f"\n{'=' * 72}")
    print(title)
    print(f"{'=' * 72}")


def build_sample_payload(report):
    sample = deepcopy(report)
    sample["api_key"] = "***REDACTED***"
    sample["findings"] = sample.get("findings", [])[:3]
    return sample


async def fetch_agent_summary():
    api_host = os.getenv("WAZUH_API_HOST")
    api_user = os.getenv("WAZUH_API_USER")
    api_pass = os.getenv("WAZUH_API_PASSWORD")

    api = WazuhApiClient(api_host, api_user, api_pass)
    try:
        if await api._authenticate():
            return await api.get_agents_summary()
    except Exception:
        return None
    return None


async def main():
    args = parse_args()
    load_dotenv()

    company_id = int(os.getenv("TXDXAI_COMPANY_ID", 0))
    api_key = os.getenv("TXDXAI_API_KEY")
    ingest_url = os.getenv("TXDXAI_INGEST_URL")

    start_time = (datetime.now(timezone.utc) - timedelta(hours=args.hours)).isoformat()

    print_block("1) Extrayendo alertas desde Wazuh Indexer")
    print(f"Desde: {start_time}")
    print(f"Nivel minimo: {args.min_level}")
    print(f"Batch size: {args.batch_size}")

    indexer = IndexerClient(
        os.getenv("WAZUH_INDEXER_HOST"),
        os.getenv("WAZUH_INDEXER_USER"),
        os.getenv("WAZUH_INDEXER_PASSWORD"),
    )

    try:
        raw_alerts = await indexer.get_alerts_range(
            start_timestamp=start_time,
            batch_size=args.batch_size,
            max_alerts=args.limit,
        )
    finally:
        await indexer.close()

    filtered_alerts = [
        alert for alert in raw_alerts
        if int(alert.get("rule", {}).get("level", 0)) >= args.min_level
    ]

    print(f"Alertas recuperadas: {len(raw_alerts)}")
    print(f"Alertas filtradas:   {len(filtered_alerts)}")

    print_block("2) Leyendo inventario de agentes")
    agent_summary = await fetch_agent_summary()
    print(f"Resumen agentes: {agent_summary or 'no disponible'}")

    print_block("3) Construyendo payload")
    aggregator = Aggregator(tenant_id=str(company_id))
    findings = [aggregator.normalize_alert(alert) for alert in filtered_alerts]
    scan_id = str(uuid.uuid4())
    report = aggregator.create_report(
        findings,
        agent_summary,
        {"scan_id": scan_id, "company_id": company_id, "api_key": api_key},
    )

    debug_dir = Path("debug_output")
    debug_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    full_payload_path = debug_dir / f"replay_full_ingest_{stamp}.json"
    sample_payload_path = debug_dir / f"replay_full_ingest_sample_{stamp}.json"

    with open(full_payload_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=4, ensure_ascii=False)

    with open(sample_payload_path, "w", encoding="utf-8") as fh:
        json.dump(build_sample_payload(report), fh, indent=4, ensure_ascii=False)

    summary = report.get("scan_summary", {})
    print(f"Scan ID:       {scan_id}")
    print(f"Findings:      {len(findings)}")
    print(f"Critical:      {summary.get('disaster_count', 0)}")
    print(f"High:          {summary.get('high_count', 0)}")
    print(f"Medium:        {summary.get('average_count', 0)}")
    print(f"Low:           {summary.get('warning_count', 0)}")
    print(f"JSON completo: {full_payload_path}")
    print(f"JSON muestra:  {sample_payload_path}")

    if args.send:
        print_block("4) Enviando payload al dashboard")
        sender = Sender(ingest_url)
        success = await sender.send_report(report)
        print(f"Envio: {'OK' if success else 'ERROR'}")
        print(f"Destino: {ingest_url}")
    else:
        print_block("4) Envio omitido")
        print("Usa --send para reenviar el payload al dashboard.")


if __name__ == "__main__":
    asyncio.run(main())
