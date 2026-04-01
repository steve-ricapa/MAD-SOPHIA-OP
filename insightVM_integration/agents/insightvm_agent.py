from __future__ import annotations

import logging
from typing import Optional

from clients.insightvm_client import InsightVMClient
from config.insightvm_config import load_insightvm_settings
from utils.state_manager import StateManager

log = logging.getLogger("agents.insightvm")


class InsightVMAgent:
    def __init__(self, client: Optional[InsightVMClient] = None, state_manager: Optional[StateManager] = None) -> None:
        self.client = client
        self.state_manager = state_manager

    def _ensure_client(self, timeout_override=None, verify_ssl_override=None) -> None:
        if self.client is None:
            settings = load_insightvm_settings(
                timeout_override=timeout_override,
                verify_ssl_override=verify_ssl_override,
            )
            self.client = InsightVMClient(settings=settings)

    def run(self, page_size: int = 200, timeout_override=None, verify_ssl_override=None) -> dict:
        log.info("Recolectando datos InsightVM")
        self._ensure_client(timeout_override, verify_ssl_override)

        data: dict = {"assets": {"resources": []}, "vulnerabilities": {"resources": []}}

        try:
            for asset in self.client.get_paged("/assets", size=page_size):
                data["assets"]["resources"].append(asset)
        except Exception as e:
            data["assets"] = {"error": str(e)}

        try:
            vuln_definitions = {}
            for asset in data["assets"]["resources"]:
                asset_id = asset.get("id")
                if asset_id:
                    log.debug("Buscando vulnerabilidades para el activo: %s", asset_id)
                    try:
                        asset_vulns_resp = self.client.get(f"/assets/{asset_id}/vulnerabilities")
                        if isinstance(asset_vulns_resp, dict) and "resources" in asset_vulns_resp:
                            # Guardamos los IDs de las vulnerabilidades en el activo
                            v_ids = [v.get("id") for v in asset_vulns_resp["resources"] if v.get("id")]
                            asset["vulnerabilities_ids"] = v_ids
                            
                            for v_id in v_ids:
                                if v_id not in vuln_definitions:
                                    log.debug("Obteniendo detalles de vulnerabilidad: %s", v_id)
                                    v_def = self.client.get(f"/vulnerabilities/{v_id}")
                                    if v_def and not v_def.get("error"):
                                        vuln_definitions[v_id] = v_def
                    except Exception as e:
                        log.warning("No se pudieron obtener vulns para el activo %s: %s", asset_id, e)

            data["vulnerabilities"] = {"resources": list(vuln_definitions.values())}
            log.info("Total de definiciones de vulnerabilidades obtenidas: %s", len(vuln_definitions))

        except Exception as e:
            data["vulnerabilities"] = {"error": str(e)}

        return data
