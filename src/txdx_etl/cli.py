from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from txdx_etl.connectors.uptime_kuma.client import (
    MetricsClient,
    MetricsClientConfig,
)
from txdx_etl.connectors.uptime_kuma.detector import ChangeDetector
from txdx_etl.connectors.uptime_kuma.state_store import SqliteStateStore
from txdx_etl.pipeline.cycle_log import SqliteCycleLog
from txdx_etl.pipeline.outbox import SqliteOutbox
from txdx_etl.pipeline.runtime import CycleReport, PipelineRuntime

REQUIRED_KEYS = ("UPTIME_KUMA_URL", "UPTIME_KUMA_USERNAME", "UPTIME_KUMA_PASSWORD")

_ENV_MAP = {
    "UPTIME_KUMA_URL": "url",
    "UPTIME_KUMA_USERNAME": "username",
    "UPTIME_KUMA_PASSWORD": "password",
    "TXDX_ETL_DB": "db",
    "TXDX_ETL_TENANT": "tenant",
    "TXDX_ETL_INSTANCE": "instance",
    "TXDX_ETL_DISPLAY_NAME": "display_name",
    "TXDX_ETL_INTERVAL": "interval",
    "TXDX_ETL_ALLOW_INSECURE": "allow_insecure",
}

_DEFAULTS = {
    "db": "runtime/spool.db",
    "tenant": "1",
    "instance": "kuma-lab",
    "display_name": "Uptime Kuma",
    "interval": "30",
    "allow_insecure": "false",
}


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_env_file(path: str | Path) -> dict[str, str]:
    target = Path(path)
    if not target.exists():
        return {}
    settings: dict[str, str] = {}
    for raw in target.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if key:
            settings[key] = value
    return settings


def load_settings(args: argparse.Namespace) -> tuple[dict[str, str], list[str]]:
    env_path = Path(args.env) if getattr(args, "env", None) else Path(".env")
    file_vars = parse_env_file(env_path) if env_path.exists() else {}

    def resolve(cli_value: object, key: str) -> str | None:
        if isinstance(cli_value, bool):
            if cli_value:
                return "true"
        elif cli_value is not None:
            return str(cli_value)
        from_os = os.environ.get(key)
        if from_os:
            return from_os
        if key in file_vars:
            return file_vars[key]
        return None

    settings = {
        name: resolve(getattr(args, name, None), key)
        for key, name in _ENV_MAP.items()
    }
    for key, value in _DEFAULTS.items():
        if settings.get(key) is None:
            settings[key] = value
    missing = [key for key in REQUIRED_KEYS if not settings.get(_ENV_MAP[key])]
    return settings, missing


def build_runtime(
    *,
    tenant_id: str,
    instance_id: str,
    display_name: str,
    base_url: str,
    username: str | None,
    password: str | None,
    db_path: str,
    allow_insecure: bool = False,
):
    client_config = MetricsClientConfig(
        base_url=base_url,
        username=username,
        password=password,
        allow_insecure_transport=allow_insecure,
    )
    state = SqliteStateStore(db_path)
    detector = ChangeDetector(
        tenant_id=tenant_id,
        instance_id=instance_id,
        state_store=state,
    )
    outbox = SqliteOutbox(db_path)
    cycle_log = SqliteCycleLog(db_path)
    client = MetricsClient(client_config)
    runtime = PipelineRuntime(
        tenant_id=tenant_id,
        instance_id=instance_id,
        client=client,
        detector=detector,
        outbox=outbox,
        sink=lambda envelope: None,
        display_name=display_name,
        cycle_log=cycle_log,
    )
    return runtime, (state, outbox, cycle_log, client)


def _print_cycle(report: CycleReport) -> None:
    scrape = report.scrape_ok and "ok" or f"FALLO({report.scrape_error})"
    print(
        f"[{report.observed_at}] scrape={scrape} "
        f"detectados={report.records_detected} "
        f"encolados={report.records_enqueued} "
        f"entregados={report.drain.delivered} "
        f"pendientes={report.drain.pending_left}",
        flush=True,
    )


def run_session(settings: dict[str, str]) -> int:
    """Abre conexiones y corre ciclos hasta Ctrl+C. Retorna codigo de salida."""
    runtime, resources = build_runtime(
        tenant_id=settings["tenant"],
        instance_id=settings["instance"],
        display_name=settings["display_name"],
        base_url=settings["url"],
        username=settings["username"],
        password=settings["password"],
        db_path=settings["db"],
        allow_insecure=settings["allow_insecure"].lower() in {"1", "true", "yes"},
    )
    interval = max(int(settings["interval"]), 1)
    try:
        while True:
            report = runtime.run_cycle(observed_at=_now_utc())
            _print_cycle(report)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("interrumpido por el usuario", flush=True)
        return 0
    finally:
        for resource in resources:
            resource.close()


def supervise(settings: dict[str, str]) -> int:
    """Reinicia la sesion automaticamente si el proceso interno falla."""
    pause = 5
    while True:
        started = time.monotonic()
        try:
            return run_session(settings)
        except KeyboardInterrupt:
            print("supervisor detenido por el usuario", flush=True)
            return 0
        except Exception as exc:
            lasted = time.monotonic() - started
            if lasted > 300:
                pause = 5
            stamp = _now_utc()
            print(
                f"[{stamp}] sesion termino inesperadamente "
                f"({type(exc).__name__}: {exc}); reiniciando en {pause}s",
                flush=True,
            )
            time.sleep(pause)
            pause = min(pause * 2, 60)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m txdx_etl.cli",
        description=(
            "ETL Uptime Kuma con destino local. La configuracion puede venir "
            "por flags, variables de entorno o archivo .env (en ese orden de "
            "prioridad)."
        ),
    )
    parser.add_argument("--env", help="Ruta al archivo .env (default ./.env)")
    parser.add_argument("--url", help="Base URL de Kuma, ej. http://IP:3001")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--db", help="Ruta del SQLite compartido")
    parser.add_argument("--tenant")
    parser.add_argument("--instance")
    parser.add_argument("--display-name")
    parser.add_argument(
        "--interval", type=int, help="Segundos entre ciclos (default 30)"
    )
    parser.add_argument(
        "--allow-insecure",
        action="store_true",
        help="Permitir HTTP plano (solo red local de laboratorio)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Ejecutar un solo ciclo y salir",
    )
    parser.add_argument(
        "--supervise",
        action="store_true",
        help="Reiniciar automaticamente si la sesion falla",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = create_parser().parse_args(argv)
    settings, missing = load_settings(args)
    if missing:
        print(
            "Faltan datos obligatorios: "
            + ", ".join(missing)
            + ". Provealos con flags (--url/--username/--password), "
            "variables de entorno o un archivo .env.",
            file=sys.stderr,
            flush=True,
        )
        return 2

    if args.once:
        try:
            report = run_single_cycle(settings)
        except KeyboardInterrupt:
            print("interrumpido por el usuario", flush=True)
            return 0
        _print_cycle(report)
        return 0
    if args.supervise:
        return supervise(settings)
    return run_session(settings)


def run_single_cycle(settings: dict[str, str]) -> CycleReport:
    runtime, resources = build_runtime(
        tenant_id=settings["tenant"],
        instance_id=settings["instance"],
        display_name=settings["display_name"],
        base_url=settings["url"],
        username=settings["username"],
        password=settings["password"],
        db_path=settings["db"],
        allow_insecure=settings["allow_insecure"].lower() in {"1", "true", "yes"},
    )
    try:
        return runtime.run_cycle(observed_at=_now_utc())
    finally:
        for resource in resources:
            resource.close()


if __name__ == "__main__":
    sys.exit(main())
