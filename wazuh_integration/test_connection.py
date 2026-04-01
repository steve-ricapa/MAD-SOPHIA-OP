import asyncio
import os
from dotenv import load_dotenv
from src.api import WazuhApiClient
from src.indexer import IndexerClient

async def test():
    load_dotenv()
    print("🔍 Probando conexión con Wazuh en 192.168.50.83...")
    
    # Test API
    api_host = os.getenv("WAZUH_API_HOST")
    api_user = os.getenv("WAZUH_API_USER")
    api_pass = os.getenv("WAZUH_API_PASSWORD")
    
    api = WazuhApiClient(api_host, api_user, api_pass)
    print(f"--- Intentando API ({api_host}) con usuario: {api_user} ---")
    if await api._authenticate():
        print("✅ API: Conectado con éxito!")
        summary = await api.get_agents_summary()
        if summary:
            print(f"📊 Resumen de agentes: {summary}")
        else:
            print("⚠️ API: Conectado pero no se pudo obtener el resumen.")
    else:
        print("❌ API: Falló la autenticación.")

    # Test Indexer
    idx_host = os.getenv("WAZUH_INDEXER_HOST")
    idx_user = os.getenv("WAZUH_INDEXER_USER")
    idx_pass = os.getenv("WAZUH_INDEXER_PASSWORD")
    
    print(f"\n--- Intentando Indexer ({idx_host}) con usuario: {idx_user} ---")
    indexer = IndexerClient(idx_host, idx_user, idx_pass)
    try:
        info = await indexer.client.info()
        print(f"✅ Indexer: Conectado con éxito! (Versión: {info.get('version', {}).get('number')})")
    except Exception as e:
        print(f"❌ Indexer: Falló la conexión ({e})")
    finally:
        await indexer.close()

if __name__ == "__main__":
    asyncio.run(test())
