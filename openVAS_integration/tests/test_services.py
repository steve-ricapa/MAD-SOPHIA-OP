from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services import map_status

def test_status():
    assert map_status("Running") == "running"
    assert map_status("Pending") == "pending"
    assert map_status("Done") == "completed"
    assert map_status("Completed") == "completed"
