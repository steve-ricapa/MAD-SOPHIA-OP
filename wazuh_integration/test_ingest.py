"""
Test de Integración End-to-End: Wazuh → Normalización → Dashboard
Ejecutar: python test_ingest.py

Este script:
1. Se conecta al Wazuh Indexer y extrae alertas reales
2. Las normaliza con el código enriquecido (MITRE, compliance, IP, groups)
3. Arma el reporte completo (igual que lo haría main.py)
4. Muestra el JSON exacto en consola
5. Intenta enviarlo al endpoint del Dashboard y muestra la respuesta
"""

import asyncio
import os
import uuid
import json
import aiohttp
from pathlib import Path
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

from src.indexer import IndexerClient
from src.api import WazuhApiClient
from src.aggregator import Aggregator


def print_section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


async def main():
    load_dotenv()

    company_id = int(os.getenv("TXDXAI_COMPANY_ID", 0))
    api_key = os.getenv("TXDXAI_API_KEY")
    ingest_url = os.getenv("TXDXAI_INGEST_URL")

    # ── PASO 1: Conectar a Wazuh Indexer y extraer alertas ──────────
    print_section("PASO 1: Conectando a Wazuh Indexer")

    indexer_host = os.getenv("WAZUH_INDEXER_HOST")
    indexer_user = os.getenv("WAZUH_INDEXER_USER")
    indexer_pass = os.getenv("WAZUH_INDEXER_PASSWORD")

    indexer = IndexerClient(indexer_host, indexer_user, indexer_pass)

    try:
        info = await indexer.client.info()
        print(f"✅ Indexer conectado (Versión: {info.get('version', {}).get('number')})")
    except Exception as e:
        print(f"❌ No se pudo conectar al Indexer: {e}")
        print("   → Asegúrate de que el laboratorio Wazuh esté encendido.")
        await indexer.close()
        return

    # Buscar alertas de las últimas 2 horas
    since = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    min_level = int(os.getenv("MIN_RULE_LEVEL", 7))
    print(f"   Buscando alertas desde: {since}")
    print(f"   Nivel mínimo: {min_level}")

    raw_alerts = await indexer.get_new_alerts(since, limit=10)  # Solo 10 para la prueba
    raw_alerts = [a for a in raw_alerts if int(a.get('rule', {}).get('level', 0)) >= min_level]

    print(f"   Alertas encontradas (filtradas): {len(raw_alerts)}")

    if not raw_alerts:
        print("⚠️  No se encontraron alertas en las últimas 2 horas con nivel >= {min_level}.")
        print("    Intentando sin filtro de nivel para verificar la conexión...")
        raw_alerts = await indexer.get_new_alerts(since, limit=5)
        if raw_alerts:
            print(f"   ✅ Hay {len(raw_alerts)} alertas sin filtro (nivel < {min_level}), conexión OK.")
            print(f"   Usando estas alertas para la prueba de envío...")
        else:
            print("   ❌ No hay alertas en las últimas 2 horas. ¿Wazuh está generando eventos?")
            await indexer.close()
            return

    await indexer.close()

    # ── PASO 2: Conectar a Wazuh API para inventario ─────────────────
    print_section("PASO 2: Conectando a Wazuh API (inventario)")

    api_host = os.getenv("WAZUH_API_HOST")
    api_user = os.getenv("WAZUH_API_USER")
    api_pass = os.getenv("WAZUH_API_PASSWORD")

    api = WazuhApiClient(api_host, api_user, api_pass)

    agent_summary = None
    try:
        if await api._authenticate():
            print("✅ API autenticada correctamente")
            agent_summary = await api.get_agents_summary()
            if agent_summary:
                print(f"   Agentes: {agent_summary}")
            else:
                print("⚠️  No se pudo obtener resumen de agentes (no crítico)")
        else:
            print("⚠️  API auth falló (no crítico, continuamos con alertas)")
    except Exception as e:
        print(f"⚠️  Error API: {e} (no crítico, continuamos)")

    # ── PASO 3: Normalizar con el código enriquecido ─────────────────
    print_section("PASO 3: Normalizando alertas (código enriquecido)")

    aggregator = Aggregator(tenant_id=str(company_id))
    processed = [aggregator.normalize_alert(a) for a in raw_alerts]

    print(f"   Findings generados: {len(processed)}")

    # Mostrar un ejemplo completo del finding enriquecido
    if processed:
        print("\n   📋 Ejemplo de finding enriquecido (primer alerta):")
        print(json.dumps(processed[0], indent=4, ensure_ascii=False))

    # ── PASO 4: Armar el reporte completo ────────────────────────────
    print_section("PASO 4: Armando reporte completo")

    scan_id = str(uuid.uuid4())
    config = {"scan_id": scan_id, "company_id": company_id, "api_key": api_key}
    report = aggregator.create_report(processed, agent_summary, config)

    # Guardar copia local del JSON que se va a enviar
    debug_dir = Path("debug_output")
    debug_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    local_file = debug_dir / f"test_ingest_{timestamp}.json"

    with open(local_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    print(f"   📄 Reporte guardado localmente: {local_file}")
    print(f"   Scan ID: {scan_id}")
    print(f"   Company ID: {company_id}")
    print(f"   Findings: {len(report['findings'])}")

    sm = report.get('scan_summary', {})
    print(f"   Criticals: {sm.get('disaster_count', 0)}")
    print(f"   Highs: {sm.get('high_count', 0)}")
    print(f"   Mediums: {sm.get('average_count', 0)}")
    print(f"   Total Hosts: {sm.get('total_hosts', 0)}")

    # ── PASO 5: Enviar al Dashboard ──────────────────────────────────
    print_section("PASO 5: Enviando al Dashboard")
    print(f"   URL: {ingest_url}")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                ingest_url,
                json=report,
                headers={"Content-Type": "application/json"}
            ) as resp:
                status = resp.status
                body = await resp.text()

                if status in [200, 201]:
                    print(f"   ✅ ÉXITO — Status: {status}")
                    print(f"   Respuesta del servidor:")
                    # Intentar formatear JSON de respuesta
                    try:
                        print(json.dumps(json.loads(body), indent=4, ensure_ascii=False))
                    except:
                        print(f"   {body}")
                else:
                    print(f"   ❌ ERROR — Status: {status}")
                    print(f"   Respuesta del servidor:")
                    print(f"   {body[:1000]}")

    except aiohttp.ClientConnectorError as e:
        print(f"   ❌ No se pudo conectar al Dashboard: {e}")
        print(f"   → ¿Está el backend corriendo en {ingest_url}?")
    except Exception as e:
        print(f"   ❌ Error inesperado: {e}")

    # ── RESUMEN ──────────────────────────────────────────────────────
    print_section("RESUMEN")
    print(f"   JSON local:   {local_file}")
    print(f"   Dashboard:    {ingest_url}")
    print(f"   Scan ID:      {scan_id}")
    print(f"   Findings:     {len(processed)}")
    print(f"\n   Revisa el archivo JSON guardado para ver el payload completo.")


if __name__ == "__main__":
    asyncio.run(main())
