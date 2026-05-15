import json
import time
import requests
from typing import Any, Dict, Optional
import urllib3


class ZabbixClient:
    def __init__(
        self,
        api_url: str,
        api_token: str = "",
        user: str = "",
        password: str = "",
        timeout: int = 30,
        verify_ssl: bool = True,
        retries: int = 3,
        backoff_seconds: int = 5,
    ):
        self.api_url = api_url.rstrip("/")
        self.api_token = api_token.strip()
        self.user = user
        self.password = password
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.retries = max(retries, 1)
        self.backoff_seconds = backoff_seconds
        self.auth_token = api_token if api_token else None
        self.session = requests.Session()

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def login(self):
        if self.api_token:
            self.auth_token = self.api_token
            return self.auth_token
        try:
            resp = self.call("user.login", {"username": self.user, "password": self.password})
        except Exception:
            resp = self.call("user.login", {"user": self.user, "password": self.password})
        self.auth_token = resp
        return resp

    def _should_retry_auth(self, error: Dict[str, Any]) -> bool:
        error_data = str(error.get("data", "")).lower()
        error_message = str(error.get("message", "")).lower()
        return "not authorised" in error_data or "re-login" in error_data or "session terminated" in error_data or "not authorized" in error_message

    def call(self, method: str, params: Any) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": int(time.time()),
        }

        if method not in ("apiinfo.version", "user.login") and not self.auth_token:
            self.login()

        headers = {
            "Content-Type": "application/json-rpc",
            "Accept": "application/json",
        }
        if self.auth_token and method != "apiinfo.version":
            headers["Authorization"] = f"Bearer {self.auth_token}"

        last_error: Optional[str] = None
        for attempt in range(1, self.retries + 1):
            try:
                r = self.session.post(
                    self.api_url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                )

                if not (200 <= r.status_code < 300):
                    last_error = f"HTTP {r.status_code}: {(r.text or '')[:300]}"
                    if attempt == self.retries:
                        break
                    print(f"[WARN] Zabbix API attempt {attempt}/{self.retries} failed for {method}: {last_error}")
                    time.sleep(self.backoff_seconds)
                    continue

                try:
                    data = r.json()
                except Exception as exc:
                    last_error = f"JSON decode error: {type(exc).__name__}: {exc}"
                    if attempt == self.retries:
                        break
                    print(f"[WARN] Zabbix API attempt {attempt}/{self.retries} failed for {method}: {last_error}")
                    time.sleep(self.backoff_seconds)
                    continue

                if "error" in data:
                    if method not in ("apiinfo.version", "user.login") and self._should_retry_auth(data["error"]):
                        self.auth_token = None if not self.api_token else self.api_token
                        self.login()
                        headers["Authorization"] = f"Bearer {self.auth_token}"
                        continue
                    last_error = f"Zabbix JSON-RPC error: {json.dumps(data['error'], ensure_ascii=False)}"
                    if attempt == self.retries:
                        break
                    print(f"[WARN] Zabbix API attempt {attempt}/{self.retries} failed for {method}: {last_error}")
                    time.sleep(self.backoff_seconds)
                    continue

                result = data.get("result")
                if result is not None:
                    return result

                last_error = "Response missing 'result' key"
                if attempt == self.retries:
                    break
                print(f"[WARN] Zabbix API attempt {attempt}/{self.retries} failed for {method}: {last_error}")
                time.sleep(self.backoff_seconds)

            except requests.RequestException as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt == self.retries:
                    break
                print(f"[WARN] Zabbix API attempt {attempt}/{self.retries} failed for {method}: {last_error}")
                time.sleep(self.backoff_seconds)

        raise RuntimeError(f"Zabbix API request failed after {self.retries} attempts: {last_error}")

    def api_version(self) -> str:
        return self.call("apiinfo.version", {})

    def get_problems(self, time_from: int, limit: int = 2000):
        problems = self.call("problem.get", {
            "output": ["eventid", "name", "severity", "clock", "r_clock", "acknowledged", "objectid"],
            "selectTags": "extend",
            "selectAcknowledges": "extend",
            "time_from": time_from,
            "sortfield": ["eventid"],
            "sortorder": "DESC",
            "limit": limit
        })

        if not problems:
            return []

        trigger_ids = list(set(p["objectid"] for p in problems if p.get("objectid")))
        if trigger_ids:
            triggers = self.call("trigger.get", {
                "triggerids": trigger_ids,
                "selectHosts": ["hostid", "name", "host", "inventory"],
                "output": ["triggerid"]
            })

            trigger_map = {t["triggerid"]: t.get("hosts", []) for t in triggers}

            for p in problems:
                p["hosts"] = trigger_map.get(p["objectid"], [])

        return problems

    def get_hosts(self):
        return self.call("host.get", {
            "output": ["hostid", "name", "host", "status"],
            "selectInventory": "extend",
            "selectInterfaces": "extend",
            "filter": {"status": "0"}
        })

    def get_system_info(self):
        try:
            return self.call("apiinfo.version", {})
        except:
            return "unknown"

    def get_all_triggers(self, limit: int = 5000):
        return self.call("trigger.get", {
            "output": ["triggerid", "description", "priority", "status", "lastchange"],
            "selectHosts": ["hostid", "name", "host", "inventory"],
            "selectInterfaces": ["ip", "port", "main"],
            "selectTags": "extend",
            "monitored": True,
            "filter": {"status": "0"},
            "limit": limit
        })

    def get_events(self, time_from: int, limit: int = 2000):
        return self.call("event.get", {
            "output": ["eventid", "name", "severity", "clock", "value"],
            "time_from": time_from,
            "sortfield": ["eventid"],
            "sortorder": "DESC",
            "limit": limit,
        })
