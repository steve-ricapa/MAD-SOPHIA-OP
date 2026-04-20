import tempfile
import unittest
import time
from pathlib import Path

import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from src.state import StateStore


class TestStateStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.tmp.name) / "agent_state.db"
        self.store = StateStore(db_path=str(self.db_path))

    def tearDown(self):
        del self.store
        time.sleep(0.05)
        try:
            self.tmp.cleanup()
        except PermissionError:
            pass

    def test_checkpoint_roundtrip(self):
        self.assertEqual(self.store.get_checkpoint("alerts_timestamp", "none"), "none")
        self.store.update_checkpoint("alerts_timestamp", "2026-01-01T00:00:00Z")
        self.assertEqual(
            self.store.get_checkpoint("alerts_timestamp", "none"),
            "2026-01-01T00:00:00Z",
        )

    def test_processed_alert_dedup(self):
        self.assertFalse(self.store.is_alert_processed("abc"))
        self.store.mark_alerts_processed(["abc", "abc", "def", None])
        self.assertTrue(self.store.is_alert_processed("abc"))
        self.assertTrue(self.store.is_alert_processed("def"))
        self.assertFalse(self.store.is_alert_processed("zzz"))


if __name__ == "__main__":
    unittest.main()
