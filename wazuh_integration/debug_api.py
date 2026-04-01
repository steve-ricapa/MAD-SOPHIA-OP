import asyncio
import os
import json
from dotenv import load_dotenv
from src.api import WazuhApiClient

async def debug_summary():
    load_dotenv()
    host = os.getenv("WAZUH_API_HOST")
    user = os.getenv("WAZUH_API_USER")
    password = os.getenv("WAZUH_API_PASSWORD")
    
    api = WazuhApiClient(host, user, password)
    print(f"--- Debugging Agent Summary for {host} ---")
    
    # We use the internal _authenticate to get a token
    if await api._authenticate():
        url = f"{api.host}/agents/summary/status"
        headers = {"Authorization": f"Bearer {api.token}"}
        
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, ssl=False) as resp:
                print(f"Status: {resp.status}")
                body = await resp.json()
                print("Raw Response:")
                print(json.dumps(body, indent=2))
                
                # Check list of agents too
                url_list = f"{api.host}/agents?limit=5"
                async with session.get(url_list, headers=headers, ssl=False) as resp_list:
                    print(f"\nAgents List Status: {resp_list.status}")
                    body_list = await resp_list.json()
                    print("Raw Agents List (first 5):")
                    print(json.dumps(body_list, indent=2))
    else:
        print("Auth failed")

if __name__ == "__main__":
    asyncio.run(debug_summary())
