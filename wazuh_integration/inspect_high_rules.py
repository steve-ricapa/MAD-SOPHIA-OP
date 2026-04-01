import asyncio
import json
import os
from pathlib import Path

from dotenv import load_dotenv

from src.api import WazuhApiClient


async def fetch_json(session, url, headers, params=None, ssl=False):
    async with session.get(url, headers=headers, params=params, ssl=ssl) as resp:
        body = await resp.text()
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = {"raw": body}
        return resp.status, data


async def main():
    load_dotenv()

    api = WazuhApiClient(
        os.getenv("WAZUH_API_HOST"),
        os.getenv("WAZUH_API_USER"),
        os.getenv("WAZUH_API_PASSWORD"),
    )

    if not await api._authenticate():
        print(json.dumps({"error": "authentication_failed"}, indent=4))
        return

    import aiohttp

    headers = {"Authorization": f"Bearer {api.token}"}
    base = api.host
    ssl = api.verify_certs

    endpoints = [
        ("rules_level_gte_12", f"{base}/rules", {"limit": 500, "level": "12-16", "sort": "+level"}),
        ("rules_level_gte_12_alt", f"{base}/rules", {"limit": 500, "sort": "+level", "q": "level>11"}),
        ("rules_files", f"{base}/rules/files", {"limit": 500}),
        ("rules_groups", f"{base}/rules/groups", {"limit": 500}),
    ]

    results = {}
    async with aiohttp.ClientSession() as session:
        for name, url, params in endpoints:
            status, data = await fetch_json(session, url, headers, params=params, ssl=ssl)
            results[name] = {
                "status": status,
                "keys": list(data.keys()) if isinstance(data, dict) else [],
                "sample": data,
            }

    debug_dir = Path("debug_output")
    debug_dir.mkdir(exist_ok=True)
    output_path = debug_dir / "inspect_high_rules_output.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=4, ensure_ascii=False)

    print(json.dumps({"output": str(output_path), "endpoints": list(results.keys())}, indent=4))


if __name__ == "__main__":
    asyncio.run(main())
