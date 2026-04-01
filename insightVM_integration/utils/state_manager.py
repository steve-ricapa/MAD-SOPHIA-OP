from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
try:
    import fcntl
except ImportError:
    fcntl = None # fcntl no está disponible en Windows

log = logging.getLogger("utils.state_manager")

class StateManager:
    """
    Gestiona la persistencia (memoria) del agente para evitar procesar datos duplicados.
    Implementa un bloqueo simple para evitar corrupción en ejecuciones paralelas.
    """

    def __init__(self, state_file: str = "state.json") -> None:
        self.state_file = Path(state_file)
        self.state: Dict[str, Any] = {
            "processed_assets": {}, # asset_id -> last_scan_id
            "processed_findings": [], # List of finding hashes
            "last_run": None
        }
        self._load()

    def _load(self) -> None:
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self.state.update(data)
            except Exception as e:
                log.error("Error al cargar state.json: %s", e)

    def save(self) -> None:
        # Implementar bloqueo si fcntl está disponible (Linux)
        f = None
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                if fcntl:
                    try:
                        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except Exception:
                        log.warning("No se pudo obtener el bloqueo del archivo (ya está en uso).")
                        return

                json.dump(self.state, f, indent=2, ensure_ascii=False)
                log.debug("State guardado exitosamente.")
        except Exception as e:
            log.error("Error al guardar state.json: %s", e)
        finally:
            if f and fcntl:
                try:
                    fcntl.flock(f, fcntl.LOCK_UN)
                except Exception:
                    pass

    def is_asset_processed(self, asset_id: str, last_scan_id: Optional[int]) -> bool:
        """Determina si un activo ya fue procesado con el mismo scan_id."""
        if last_scan_id is None:
            return False
        
        processed_scan_id = self.state["processed_assets"].get(str(asset_id))
        return str(processed_scan_id) == str(last_scan_id)

    def mark_asset_processed(self, asset_id: str, last_scan_id: Optional[int]) -> None:
        if last_scan_id is not None:
            self.state["processed_assets"][str(asset_id)] = last_scan_id

    def is_finding_processed(self, finding_id: str) -> bool:
        return finding_id in self.state["processed_findings"]

    def mark_finding_processed(self, finding_id: str) -> None:
        if finding_id not in self.state["processed_findings"]:
            self.state["processed_findings"].append(finding_id)
            # Limitar tamaño de la lista de findings para evitar que state.json crezca infinitamente
            if len(self.state["processed_findings"]) > 10000:
                self.state["processed_findings"] = self.state["processed_findings"][-10000:]
