import asyncio
import os
import json
from dotenv import load_dotenv
from src.indexer import IndexerClient

async def debug_indexer():
    load_dotenv()
    
    host = os.getenv("WAZUH_INDEXER_HOST")
    user = os.getenv("WAZUH_INDEXER_USER")
    password = os.getenv("WAZUH_INDEXER_PASSWORD")
    
    client = IndexerClient(host, user, password)
    
    print(f"Connecting to Indexer: {host}")
    # Query for alerts that HAVE mitre enrichment
    query = {
        "query": {
            "exists": {"field": "rule.mitre.id"}
        },
        "size": 5
    }
    
    try:
        response = await client.client.search(index="wazuh-alerts-*", body=query)
        alerts = [hit['_source'] for hit in response['hits']['hits']]
    except Exception as e:
        print(f"Error searching for MITRE alerts: {e}")
        alerts = []
    
    print(f"Found {len(alerts)} alerts.")
    if alerts:
        # Save a few raw alerts to a file for inspection
        with open("debug_output/raw_alerts_inspection.json", "w") as f:
            json.dump(alerts[:5], f, indent=4)
        print("First 5 raw alerts saved to debug_output/raw_alerts_inspection.json")
        
        for i, alert in enumerate(alerts[:5]):
            rule = alert.get('rule', {})
            mitre = rule.get('mitre')
            print(f"Alert {i} - Rule ID: {rule.get('id')} - MITRE: {mitre}")

if __name__ == "__main__":
    asyncio.run(debug_indexer())
