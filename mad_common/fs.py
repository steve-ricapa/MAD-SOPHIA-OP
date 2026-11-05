"""Atomic replacement, allowing brief Windows sharing locks to clear."""
import os
import time
_WINDOWS = os.name == "nt"


def atomic_replace(source, target):
    for attempt in range(6):
        try:
            os.replace(source, target)
            return
        except PermissionError as exc:
            if not _WINDOWS or getattr(exc, "winerror", None) not in {5, 32, 33} or attempt == 5:
                raise
            time.sleep(0.01 * (attempt + 1))
