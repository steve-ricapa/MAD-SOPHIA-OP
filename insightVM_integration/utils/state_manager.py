from __future__ import annotations

import json
import logging
import os
import tempfile
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
                    if not isinstance(data, dict):
                        raise ValueError("InsightVM state must be a JSON object")
                    if isinstance(data, dict):
                        base = _initial_state()
                        base.update(data)
                        self.state = base
            except Exception as e:
                log.error("Error al cargar state.json: %s", e)
                raise

    def save(self) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".insight-state-", dir=self.state_file.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(self.state, stream, indent=2, ensure_ascii=False, allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.state_file)
            if os.name != "nt":
                directory_fd = os.open(self.state_file.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
