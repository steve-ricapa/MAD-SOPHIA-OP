import aiohttp
from loguru import logger
import urllib3

# Disable warnings for self-signed certs in POC
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WazuhApiClient:
    def __init__(self, host, user, password, verify_certs=False):
        self.host = host.rstrip('/')
        self.auth = aiohttp.BasicAuth(user, password)
        self.verify_certs = verify_certs
        self.token = None

    async def _authenticate(self):
        """Authenticates with Wazuh API and retrieves a JWT token."""
        url = f"{self.host}/security/user/authenticate"
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, auth=self.auth, ssl=self.verify_certs) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self.token = data['data']['token']
                        return True
                    else:
                        logger.error(f"Wazuh API Authentication failed: {resp.status}")
                        return False
            except Exception as e:
                logger.error(f"Wazuh API connection error: {e}")
                return False

    async def get_agents_summary(self):
        """Fetches a summary of agent statuses."""
        if not self.token and not await self._authenticate():
            return None
            
        url = f"{self.host}/agents/summary/status"
        headers = {"Authorization": f"Bearer {self.token}"}
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=headers, ssl=self.verify_certs) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        logger.debug(f"Wazuh API Agent Summary Response: {data}")
                        # Flatten the response: use the 'connection' sub-block as the main summary
                        summary = data.get('data', {}).get('connection', {})
                        return summary
                    elif resp.status == 401:
                        self.token = None
                        return await self.get_agents_summary()
                    else:
                        logger.error(f"Error getting agent summary: Status {resp.status}, Body: {await resp.text()}")
            except Exception as e:
                logger.error(f"Error getting agent summary: {e}")
        return None

    async def get_agents_list(self, limit=500, select=["id", "status", "name", "lastKeepAlive"]):
        """Fetches the list of agents to detect status changes."""
        if not self.token and not await self._authenticate():
            return None
            
        url = f"{self.host}/agents"
        params = {
            "limit": limit,
            "select": ",".join(select)
        }
        headers = {"Authorization": f"Bearer {self.token}"}
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=headers, params=params, ssl=self.verify_certs) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data['data']['affected_items']
            except Exception as e:
                logger.error(f"Error getting agents list: {e}")
        return None

    async def get_agent_sca(self, agent_id):
        """Fetches the latest SCA summary for an agent."""
        if not self.token and not await self._authenticate():
            return None
        url = f"{self.host}/sca/{agent_id}/summary"
        headers = {"Authorization": f"Bearer {self.token}"}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=headers, ssl=self.verify_certs) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('data')
            except: pass
        return None

    async def get_agent_vulnerabilities(self, agent_id):
        """Fetches the latest vulnerability severity summary for an agent."""
        if not self.token and not await self._authenticate():
            return None
        url = f"{self.host}/vulnerability/{agent_id}/summary/severity"
        headers = {"Authorization": f"Bearer {self.token}"}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=headers, ssl=self.verify_certs) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('data')
            except: pass
        return None
