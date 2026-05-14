import sys
from pathlib import Path


for _module_name in ("services", "snapshot", "gvm_client", "config"):
    sys.modules.pop(_module_name, None)

OPENVAS_DIR = Path(__file__).resolve().parents[1]
if str(OPENVAS_DIR) not in sys.path:
    sys.path.insert(0, str(OPENVAS_DIR))

from services import map_status

def test_status():
    assert map_status("Running") == "running"
    assert map_status("Pending") == "pending"
    assert map_status("Completed") == "completed"
