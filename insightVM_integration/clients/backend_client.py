from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("clients.backend")

class BackendClient:
    """
    Cliente para enviar datos normalizados al servidor central (Backend).
    """

    def __init__(self, ingest_url: str, api_key: Optional[str] = None, verify_ssl: bool = True) -> None:
        self.ingest_url = ingest_url
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = requests.Session()

        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=(500, 502, 503, 504),
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))

    def send_data(self, data: Dict[str, Any]) -> bool:
        """Envía datos al ingest_url vía POST."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["x-api-key"] = self.api_key # Usamos x-api-key como estándar común
            headers["Authorization"] = f"Bearer {self.api_key}" # Opcional: mantengo ambos por si acaso

        try:
            log.info("Enviando datos al backend TxDxAI...")
            r = self.session.post(
                self.ingest_url,
                json=data,
                headers=headers,
                verify=self.verify_ssl,
                timeout=60
            )
            if r.status_code >= 400:
                log.error("Error del servidor (HTTP %s): %s", r.status_code, r.text)
                return False
            
            log.info("Datos enviados exitosamente (HTTP %s)", r.status_code)
            return True
        except Exception as e:
            log.error("Error de conexión al enviar datos: %s", e)
            return False
