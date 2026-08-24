"""Reproduccion local del incidente 2026-08-24 (Kuma caido + muerte del ETL).

Simula, sin depender de la laptop remota:
  1. dos errores transitorios de scrape (HTTP 500 y conexion rechazada);
  2. una excepcion INESPERADA no clasificada que mata la sesion interna;
  3. verificacion de que --supervise reconstruye el runtime y continua;
  4. Ctrl+C simulado que termina limpiamente.

Uso:
    PYTHONPATH=src python tools/demo_supervisor_recovery.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import httpx

from txdx_etl import cli
from txdx_etl.connectors.uptime_kuma.client import MetricsClient, MetricsClientConfig
from txdx_etl.connectors.uptime_kuma.detector import ChangeDetector
from txdx_etl.connectors.uptime_kuma.state_store import SqliteStateStore
from txdx_etl.pipeline.cycle_log import SqliteCycleLog
from txdx_etl.pipeline.outbox import SqliteOutbox
from txdx_etl.pipeline.runtime import PipelineRuntime

# Guion del "Kuma falso": igual que el incidente real.
SCRIPT = [
    ("http_500", None),        # ciclo 1 -> TransientMetricsError
    ("connect_error", None),   # ciclo 2 -> TransientMetricsError
    ("raw_crash", None),       # sesion muere por excepcion no clasificada
    ("ctrl_c", None),          # usuario corta: salida limpia
]
step = {"n": -1}


def fake_kuma_handler(request: httpx.Request) -> httpx.Response:
    step["n"] += 1
    kind = SCRIPT[min(step["n"], len(SCRIPT) - 1)][0]
    print(f"    [kuma-falso] peticion #{step['n'] + 1}: {kind}")
    if kind == "http_500":
        return httpx.Response(500, text="simulando kuma caido")
    if kind == "connect_error":
        raise httpx.ConnectError("conexion rechazada (puerto muerto)")
    if kind == "raw_crash":
        raise RuntimeError("fallo inesperado no clasificado")
    raise KeyboardInterrupt()


constructions = {"n": 0}


def make_builder(db_path: str):
    def builder(**kwargs):
        constructions["n"] += 1
        print(f"    [builder] construyendo runtime #{constructions['n']} "
              f"(state/outbox/cycle_log/client nuevos)")
        config = MetricsClientConfig(
            base_url="http://demo.local",
            username="lab",
            password="secret",
            allow_insecure_transport=True,
            timeout_seconds=2.0,
        )
        state = SqliteStateStore(db_path)
        outbox = SqliteOutbox(db_path)
        cycle_log = SqliteCycleLog(db_path)
        client = MetricsClient(config, transport=httpx.MockTransport(fake_kuma_handler))
        runtime = PipelineRuntime(
            tenant_id="1",
            instance_id="kuma-lab",
            client=client,
            detector=ChangeDetector(
                tenant_id="1", instance_id="kuma-lab", state_store=state
            ),
            outbox=outbox,
            sink=lambda envelope: None,
            display_name="Uptime Kuma",
            cycle_log=cycle_log,
        )
        kwargs["resources_out"].extend([state, outbox, cycle_log, client])
        return runtime, [state, outbox, cycle_log, client]

    return builder


def run_session(settings):
    return cli.run_session(settings, builder=make_builder(settings["db"]))


def main() -> int:
    db_path = str(Path(tempfile.mkdtemp(prefix="etl_repro_")) / "spool.db")
    settings = {
        "tenant": "1",
        "instance": "kuma-lab",
        "display_name": "Uptime Kuma",
        "url": "http://demo.local",
        "username": "lab",
        "password": "secret",
        "db": db_path,
        "allow_insecure": "true",
        "interval": "1",
    }
    print("=== REPRODUCCION CONTROLADA DEL INCIDENTE ===")
    code = cli.supervise(settings, run=run_session)
    print("=== FIN ===")
    print(f"sesiones construidas: {constructions['n']} (esperado 2)")
    print(f"codigo de salida: {code} (esperado 0)")
    ok = constructions["n"] == 2 and code == 0
    print("RESULTADO:", "CORRECTO - el supervisor sobrevive y reconstruye" if ok else "FALLO")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
