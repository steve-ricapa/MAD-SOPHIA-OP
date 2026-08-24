from __future__ import annotations

import io
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from txdx_etl import cli  # noqa: E402
from txdx_etl.pipeline.runtime import CycleReport, DrainReport  # noqa: E402


def _report() -> CycleReport:
    drain = DrainReport(
        attempted=0,
        delivered=0,
        parked=0,
        transient_failures=0,
        skipped_by_backoff=False,
        paused_remaining_seconds=None,
        next_retry_wait_seconds=None,
        pending_left=0,
    )
    return CycleReport(
        observed_at="2026-08-24T00:00:00Z",
        scrape_ok=True,
        scrape_error=None,
        records_detected=0,
        records_enqueued=0,
        drain=drain,
    )


class FakeResource:
    def __init__(self, name: str = "res", fail_on_close: bool = False) -> None:
        self.name = name
        self.fail_on_close = fail_on_close
        self.closed = False
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        if self.fail_on_close:
            raise ValueError(f"cierre explosivo de {self.name}")
        self.closed = True


class FakeRuntime:
    """run_cycle que sigue un guion: 'ok', excepciones o KeyboardInterrupt."""

    def __init__(self, script: list) -> None:
        self.script = list(script)
        self.cycles = 0

    def run_cycle(self, *, observed_at: str) -> CycleReport:
        self.cycles += 1
        action = self.script.pop(0) if self.script else "ok"
        if isinstance(action, BaseException):
            raise action
        return _report()


class ScriptedRunner:
    """run_fn de supervise que lanza una secuencia fija de acciones."""

    def __init__(self, actions: list) -> None:
        self.actions = list(actions)

    def __call__(self, settings):
        action = self.actions.pop(0)
        if isinstance(action, BaseException):
            raise action
        return action


def _fake_builder(runtime, resources):
    """Builder que ademas registra recursos en resources_out (como el real)."""

    def _build(**kwargs):
        kwargs["resources_out"].extend(resources)
        return runtime, list(resources)

    return _build


def _settings(interval: str = "1") -> dict[str, str]:
    return {
        "tenant": "1",
        "instance": "kuma-lab",
        "display_name": "Uptime Kuma",
        "url": "http://127.0.0.1:3001",
        "username": "lab",
        "password": "secret",
        "db": str(Path(tempfile.mkdtemp()) / "spool.db"),
        "allow_insecure": "true",
        "interval": interval,
    }


class RunSessionTests(unittest.TestCase):
    def _run(self, settings, builder):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.run_session(settings, builder=builder)
        return code, out.getvalue(), err.getvalue()

    def test_ctrl_c_termina_limpio_a_traves_de_main(self) -> None:
        # main() en modo simple es quien traduce Ctrl+C a salida 0
        resources = [FakeResource("a"), FakeResource("b")]
        runtime = FakeRuntime([_report(), KeyboardInterrupt()])
        builder = mock.Mock(return_value=(runtime, list(resources)))
        argv = ["--once"]
        with mock.patch.dict(
            "os.environ",
            {
                "UPTIME_KUMA_URL": "http://127.0.0.1:3001",
                "UPTIME_KUMA_USERNAME": "lab",
                "UPTIME_KUMA_PASSWORD": "secret",
                "TXDX_ETL_ALLOW_INSECURE": "true",
            },
        ):
            with mock.patch.object(cli, "run_single_cycle", side_effect=KeyboardInterrupt):
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    code = cli.main(argv)
        self.assertEqual(code, 0)
        self.assertIn("interrumpido por el usuario", out.getvalue())

    def test_supervisor_y_run_session_ctrl_c_limpio_con_recursos_cerrados(self) -> None:
        resources = [FakeResource("a"), FakeResource("b")]
        runtime = FakeRuntime([KeyboardInterrupt()])
        builder = _fake_builder(runtime, resources)
        out, err = io.StringIO(), io.StringIO()
        sleeps: list[float] = []
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.supervise(
                _settings(),
                run=lambda s: cli.run_session(s, builder=builder),
                sleep=sleeps.append,
            )
        self.assertEqual(code, 0)
        self.assertTrue(all(r.closed for r in resources))
        self.assertIn("supervisor detenido por el usuario", out.getvalue())
        self.assertEqual(sleeps, [])  # sin reinicios previos

    def test_excepcion_original_no_es_enmascarada_por_cierre_roto(self) -> None:
        broken = FakeResource("sqlite", fail_on_close=True)
        runtime = FakeRuntime([RuntimeError("fallo original")])
        builder = _fake_builder(runtime, [broken])
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with self.assertRaisesRegex(RuntimeError, "fallo original"):
                cli.run_session(_settings(), builder=builder)
        self.assertEqual(broken.close_calls, 1)
        self.assertIn("aviso: fallo cerrando FakeResource", out.getvalue())

    def test_runtime_y_recursos_se_reconstruyen_tras_fallo(self) -> None:
        gen1_res = [FakeResource("g1")]
        gen2_res = [FakeResource("g2")]
        generations = [
            (FakeRuntime([RuntimeError("muerte sesion 1")]), gen1_res),
            (FakeRuntime([KeyboardInterrupt()]), gen2_res),
        ]
        constructions: list[dict] = []

        def builder(**kwargs):
            runtime, res = generations[len(constructions)]
            kwargs["resources_out"].extend(res)
            constructions.append(kwargs)
            return runtime, list(res)

        out, err = io.StringIO(), io.StringIO()
        sleeps: list[float] = []
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.supervise(
                _settings(),
                run=lambda s: cli.run_session(s, builder=builder),
                sleep=sleeps.append,
            )
        self.assertEqual(code, 0)
        self.assertEqual(len(constructions), 2)          # runtime reconstruido
        self.assertTrue(gen1_res[0].closed)              # sesion muerta liberada
        self.assertTrue(gen2_res[0].closed)              # salida limpia tambien
        self.assertEqual(sleeps, [5])                    # backoff inicial aplicado
        self.assertIn(
            "sesion #1 termino inesperadamente "
            "(duro 0s; RuntimeError: muerte sesion 1); "
            "reconstruyendo runtime y reiniciando en 5s",
            out.getvalue().replace("\n", ""),
        )

    def test_keyboardinterrupt_no_es_tragado_por_run_session(self) -> None:
        runtime = FakeRuntime([KeyboardInterrupt()])
        builder = mock.Mock(return_value=(runtime, []))
        with self.assertRaises(KeyboardInterrupt):
            self._run_quiet(lambda: cli.run_session(_settings(), builder=builder))

    @staticmethod
    def _run_quiet(fn):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            return fn()


class SuperviseTests(unittest.TestCase):
    def _supervise(self, run_fn, monotonic=time.monotonic):
        out, err = io.StringIO(), io.StringIO()
        sleeps: list[float] = []
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.supervise(
                {"interval": "30"},
                run=run_fn,
                sleep=sleeps.append,
                monotonic=monotonic,
            )
        return code, sleeps, out.getvalue(), err.getvalue()

    def test_excepcion_inesperada_no_termina_al_supervisor(self) -> None:
        runner = ScriptedRunner(
            [
                RuntimeError("boom inesperado"),
                RuntimeError("boom otra vez"),
                KeyboardInterrupt(),
            ]
        )
        code, sleeps, out, _ = self._supervise(runner)
        self.assertEqual(code, 0)
        self.assertEqual(sleeps, [5, 10])
        self.assertIn("RuntimeError: boom inesperado", out)
        self.assertIn("reconstruyendo runtime y reiniciando en 5s", out)
        self.assertIn("reconstruyendo runtime y reiniciando en 10s", out)
        self.assertIn("supervisor detenido por el usuario", out)

    def test_backoff_duplica_pero_nunca_supera_60_segundos(self) -> None:
        runner = ScriptedRunner(
            [RuntimeError(f"falla {i}") for i in range(7)] + [KeyboardInterrupt()]
        )
        code, sleeps, _, _ = self._supervise(runner)
        self.assertEqual(code, 0)
        self.assertLessEqual(max(sleeps), 60)
        self.assertEqual(sleeps, [5, 10, 20, 40, 60, 60, 60])

    def test_backoff_se_reinicia_tras_sesion_estable(self) -> None:
        runner = ScriptedRunner(
            [
                RuntimeError("rapida 1"),
                RuntimeError("rapida 2"),
                RuntimeError("lenta estable"),
                KeyboardInterrupt(),
            ]
        )
        # duraciones simuladas: 1s, 1s, 400s (>300s => estable), 0s (ctrl+c)
        ticks = iter([0, 1, 50, 51, 100, 500, 600, 600])
        code, sleeps, _, _ = self._supervise(runner, monotonic=lambda: next(ticks))
        self.assertEqual(code, 0)
        # dos fallos rapidos duplican la pausa; el fallo tras sesion estable
        # (duro 400s > 300s) reinicia el backoff al valor inicial
        self.assertEqual(sleeps, [5, 10, 5])

    def test_mensaje_claro_de_reinicio_incluye_tipo_y_contador(self) -> None:
        runner = ScriptedRunner([ValueError("dato malo"), KeyboardInterrupt()])
        code, _, out, _ = self._supervise(runner)
        self.assertEqual(code, 0)
        self.assertRegex(out, r"sesion #\d+ termino inesperadamente")
        self.assertIn("ValueError: dato malo", out)

    def test_systemexit_propaga_por_ser_salida_explicita_del_proceso(self) -> None:
        # Contrato documentado: SystemExit NO se supervisa (es una salida
        # deliberada); las excepciones comunes si siempre se supervisan.
        def run(settings):
            raise SystemExit(3)

        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(SystemExit):
                cli.supervise({"interval": "30"}, run=run, sleep=lambda s: None)


if __name__ == "__main__":
    unittest.main()
