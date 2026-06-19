import asyncio

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
        self.last_status = None
        self.last_error = None
        self.last_error_kind = None
        self.last_response_excerpt = None

    def _reset_last_result(self):
        self.last_status = None
        self.last_error = None
        self.last_error_kind = None
        self.last_response_excerpt = None

    @staticmethod
    def _classify_exception(exc):
        if isinstance(exc, asyncio.TimeoutError):
            return "timeout"
        if isinstance(exc, (aiohttp.ClientConnectorCertificateError, aiohttp.ClientConnectorSSLError)):
            return "tls"
        return "network"

    async def _authenticate(self):
        """Authenticates with Wazuh API and retrieves a JWT token."""
        url = f"{self.host}/security/user/authenticate"
        self._reset_last_result()
        timeout = aiohttp.ClientTimeout(total=20, connect=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            try:
                async with session.get(url, auth=self.auth, ssl=self.verify_certs) as resp:
                    self.last_status = resp.status
                    if resp.status == 200:
                        data = await resp.json()
                        self.token = data['data']['token']
                        return True
                    else:
                        body = await resp.text()
                        self.last_response_excerpt = body[:500]
                        self.last_error_kind = "http_error"
                        self.last_error = f"status={resp.status}"
                        logger.error(
                            "Wazuh API authentication failed | host={} | status={} | body={}",
                            self.host,
                            resp.status,
                            self.last_response_excerpt,
                        )
                        return False
            except Exception as e:
                self.last_error_kind = self._classify_exception(e)
                self.last_error = f"{type(e).__name__}: {e}"
                logger.error(
                    "Wazuh API connection error | host={} | verify_certs={} | kind={} | error={}",
                    self.host,
                    self.verify_certs,
                    self.last_error_kind,
                    self.last_error,
                )
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
