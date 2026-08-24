from __future__ import annotations

import os
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from txdx_etl.cli import load_settings, main, parse_env_file


def write_env(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


class ParseEnvFileTests(unittest.TestCase):
    def test_parses_comments_blanks_and_quotes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = write_env(
                Path(tmp) / ".env",
                "# comentario\n"
                "\n"
                "UPTIME_KUMA_URL=http://10.0.0.5:3001\n"
                'UPTIME_KUMA_USERNAME="diegx"\n'
                "UPTIME_KUMA_PASSWORD='pepe123'\n"
                "LINEA_MALA_SIN_IGUAL\n"
                "TXDX_ETL_INTERVAL=45\n",
            )
            data = parse_env_file(env)
        self.assertEqual(data["UPTIME_KUMA_URL"], "http://10.0.0.5:3001")
        self.assertEqual(data["UPTIME_KUMA_USERNAME"], "diegx")
        self.assertEqual(data["UPTIME_KUMA_PASSWORD"], "pepe123")
        self.assertEqual(data["TXDX_ETL_INTERVAL"], "45")
        self.assertNotIn("LINEA_MALA_SIN_IGUAL", data)

    def test_missing_file_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            data = parse_env_file(Path(tmp) / "nope.env")
        self.assertEqual(data, {})


class LoadSettingsTests(unittest.TestCase):
    def base_args(self, **overrides) -> Namespace:
        values = {
            "env": None,
            "url": None,
            "username": None,
            "password": None,
            "db": None,
            "tenant": None,
            "instance": None,
            "display_name": None,
            "interval": None,
            "allow_insecure": False,
        }
        values.update(overrides)
        return Namespace(**values)

    def test_flag_beats_os_env_and_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = write_env(
                Path(tmp) / ".env",
                "UPTIME_KUMA_URL=http://desde-archivo:1\n"
                "UPTIME_KUMA_USERNAME=u\n"
                "UPTIME_KUMA_PASSWORD=p\n",
            )
            args = self.base_args(env=str(env), url="http://desde-flag:2")
            with mock.patch.dict(
                os.environ, {"UPTIME_KUMA_URL": "http://desde-os:3"}
            ):
                settings, missing = load_settings(args)
        self.assertEqual(settings["url"], "http://desde-flag:2")
        self.assertEqual(settings["username"], "u")
        self.assertEqual(missing, [])

    def test_file_beats_nothing_when_os_absent_and_fills_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = write_env(
                Path(tmp) / ".env",
                "UPTIME_KUMA_URL=http://kuma:3001\n"
                "UPTIME_KUMA_USERNAME=u\n"
                "UPTIME_KUMA_PASSWORD=p\n",
            )
            clean = {k: "" for k in list(os.environ) if k.startswith("TXDX_") or k.startswith("UPTIME_")}
            with mock.patch.dict(os.environ, clean, clear=True):
                settings, missing = load_settings(self.base_args(env=str(env)))
        self.assertEqual(settings["url"], "http://kuma:3001")
        self.assertEqual(settings["db"], "runtime/spool.db")
        self.assertEqual(settings["interval"], "30")
        self.assertEqual(settings["allow_insecure"], "false")
        self.assertEqual(missing, [])

    def test_missing_required_keys_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            absent = str(Path(tmp) / "nope.env")
            clean = {
                k: ""
                for k in list(os.environ)
                if k.startswith("TXDX_") or k.startswith("UPTIME_")
            }
            with mock.patch.dict(os.environ, clean, clear=True):
                settings, missing = load_settings(self.base_args(env=absent))
        self.assertEqual(
            missing,
            ["UPTIME_KUMA_URL", "UPTIME_KUMA_USERNAME", "UPTIME_KUMA_PASSWORD"],
        )
        self.assertEqual(settings["tenant"], "1")


class MainGuardTests(unittest.TestCase):
    def test_main_returns_exit_code_two_without_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            absent = str(Path(tmp) / "nope.env")
            clean = {
                k: ""
                for k in list(os.environ)
                if k.startswith("TXDX_") or k.startswith("UPTIME_")
            }
            with mock.patch.dict(os.environ, clean, clear=True):
                code = main(["--env", absent])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
