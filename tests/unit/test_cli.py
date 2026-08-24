from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from txdx_etl.cli import build_runtime
from txdx_etl.pipeline.runtime import PipelineRuntime


class CliStackTests(unittest.TestCase):
    def test_build_runtime_wires_shared_sqlite_components(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_path = str(Path(tmp.name) / "spool.db")

        runtime, resources = build_runtime(
            tenant_id="1",
            instance_id="kuma-lab",
            display_name="Uptime Kuma",
            base_url="http://127.0.0.1:3001",
            username="lab",
            password="secret",
            db_path=db_path,
            allow_insecure=True,
        )
        try:
            self.assertIsInstance(runtime, PipelineRuntime)
            conn = sqlite3.connect(db_path)
            try:
                names = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            finally:
                conn.close()
            self.assertLessEqual(
                {"outbox", "cycle_log", "kuma_monitor_state"}, names
            )
        finally:
            for resource in resources:
                resource.close()

    def test_build_runtime_rejects_bad_url(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db_path = str(Path(tmp.name) / "spool.db")
        with self.assertRaises(ValueError):
            build_runtime(
                tenant_id="1",
                instance_id="kuma-lab",
                display_name="Uptime Kuma",
                base_url="not-a-url",
                username="lab",
                password="secret",
                db_path=db_path,
            )


if __name__ == "__main__":
    unittest.main()
