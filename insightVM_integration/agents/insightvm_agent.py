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
        # La consola permite hasta 500 elementos por página; protegemos con un piso razonable.
        size = page_size if 0 < page_size <= 500 else 500

        data: dict = {"assets": {"resources": []}, "vulnerabilities": {"resources": []}}

        # 1) Todos los assets (metadata) paginados.
        try:
            for asset in self.client.get_paged("/assets", size=size):
                data["assets"]["resources"].append(asset)
        except Exception as e:
            log.error("Error recolectando /assets: %s", e, exc_info=True)
            data["assets"] = {"error": str(e)}

        # Si la recolección de assets falló, no tiene sentido consultar vulnerabilidades.
        assets_ok = isinstance(data["assets"], dict) and isinstance(data["assets"].get("resources"), list)

        # 2) Tabla puente asset -> vulnerability IDs (1 request por asset, paginado si >500).
        asset_vuln_ids: dict = {}
        if assets_ok:
            for asset in data["assets"]["resources"]:
                asset_id = asset.get("id")
                if asset_id is None:
                    continue
                log.debug("Buscando vulnerabilidades para el activo: %s", asset_id)
                try:
                    ids = list(self.client.get_paged(f"/assets/{asset_id}/vulnerabilities", size=size))
                    v_ids = [v.get("id") for v in ids if isinstance(v, dict) and v.get("id")]
                    asset["vulnerabilities_ids"] = v_ids
                    asset_vuln_ids[asset_id] = v_ids
                except Exception as e:
                    log.warning("No se pudieron obtener vulns para el activo %s: %s", asset_id, e)

        # 3) Definiciones de vulnerabilidades SOLO de las que están presentes en los assets.
        #    /vulnerabilities devuelve TODO el catálogo mundial (~300k); NO lo paginamos entero.
        #    Resolvemos únicamente los IDs únicos encontrados vía GET /vulnerabilities/{id}.
        vuln_definitions: dict = {}
        if assets_ok and asset_vuln_ids:
            used_ids = sorted({v for ids in asset_vuln_ids.values() for v in ids})
            if used_ids:
                if len(used_ids) <= size:
                    for vid in used_ids:
                        try:
                            v_def = self.client.get(f"/vulnerabilities/{vid}")
                            if isinstance(v_def, dict) and v_def.get("id"):
                                vuln_definitions[v_def["id"]] = v_def
                            else:
                                log.warning("Definición vacía para /vulnerabilities/%s", vid)
                        except Exception as e:
                            log.warning("No se pudo obtener la definición /vulnerabilities/%s: %s", vid, e)
                else:
                    # Respaldo: un catálogo paginado a tamaño máx. si used_ids fuese muy grande.
                    log.warning(
                        "used_ids (%s) excede el tamaño de página; usando catálogo paginado.",
                        len(used_ids),
                    )
                    try:
                        for v_def in self.client.get_paged("/vulnerabilities", size=size, params={"sort": "id,ASC"}):
                            if isinstance(v_def, dict) and v_def.get("id") and v_def["id"] in used_ids:
                                vuln_definitions[v_def["id"]] = v_def
                    except Exception as e:
                        log.error("Error recolectando /vulnerabilities: %s", e, exc_info=True)
                        vuln_definitions = {}

            data["vulnerabilities"] = {"resources": list(vuln_definitions.values())}
            log.info("Total de definiciones de vulnerabilidades obtenidas: %s", len(vuln_definitions))
        else:
            data["vulnerabilities"] = {"resources": []}

        return data
