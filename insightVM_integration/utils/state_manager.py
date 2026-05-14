from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict
try:
    import fcntl
except ImportError:
    fcntl = None

log = logging.getLogger("utils.state_manager")


def _initial_state() -> Dict[str, Any]:
    return {
        "snapshot_signature": "",
        "unchanged_cycles": 0,
        "has_sent_once": False,
    }


class StateManager:
    def __init__(self, state_file: str = "state.json") -> None:
        self.state_file = Path(state_file)
        self.state: Dict[str, Any] = dict(_initial_state())
        self._load()

    def _load(self) -> None:
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        base = _initial_state()
                        base.update(data)
                        self.state = base
            except Exception as e:
                log.error("Error al cargar state.json: %s", e)

    def save(self) -> None:
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
        except Exception as e:
            log.error("Error al guardar state.json: %s", e)
        finally:
            if f and fcntl:
                try:
                    fcntl.flock(f, fcntl.LOCK_UN)
                except Exception:
                    pass
