from __future__ import annotations

import logging
from typing import Any, Dict, Iterator, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config.insightvm_config import InsightVMSettings, load_insightvm_settings

log = logging.getLogger("clients.insightvm")


class InsightVMClient:
    def __init__(self, settings: Optional[InsightVMSettings] = None, session: Optional[requests.Session] = None) -> None:
        self.settings = settings or load_insightvm_settings()
        self.session = session or requests.Session()

        # Si verify=False, apagar warnings
        if self.settings.verify is False:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
            log.warning("SSL verify DESACTIVADO (INSIGHTVM_VERIFY_SSL=false).")

        retry = Retry(
            total=5,
            connect=5,
            read=5,
            backoff_factor=0.6,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _require_auth(self) -> None:
        if not self.settings.username or not self.settings.password:
            raise ValueError("Faltan INSIGHTVM_USER / INSIGHTVM_PASSWORD en .env")

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Any:
        self._require_auth()
        url = self.settings.base_url.rstrip("/") + "/" + endpoint.lstrip("/")

        r = self.session.get(
            url,
            auth=(self.settings.username, self.settings.password),
            verify=self.settings.verify,
            timeout=self.settings.timeout,
            params=params,
        )

        if r.status_code >= 400:
            raise Exception(f"HTTP {r.status_code} -> {r.text}")

        try:
            return r.json()
        except ValueError:
            return {"raw": r.text}

    def get_paged(
        self,
        endpoint: str,
        size: int = 200,
        params: Optional[Dict[str, Any]] = None,
        items_key: str = "resources",
        max_pages: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        page = 0
        while True:
            if max_pages is not None and page >= max_pages:
                break

            q = dict(params or {})
            q.update({"page": page, "size": size})

            log.info("Consultando página %s de %s...", page, endpoint)
            data = self.get(endpoint, params=q)
            if not isinstance(data, dict):
                log.warning("Respuesta no es un diccionario en %s página %s", endpoint, page)
                break

            items = data.get(items_key)
            if not isinstance(items, list):
                log.warning("No se encontró la clave '%s' en la respuesta de %s", items_key, endpoint)
                break

            log.info("Página %s: Recibidos %s elementos.", page, len(items))
            for it in items:
                if isinstance(it, dict):
                    yield it

            if len(items) < size:
                log.info("Fin de paginación para %s (última página: %s)", endpoint, page)
                break

            page += 1
