from __future__ import annotations

import argparse
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

from agents.unified_agent import UnifiedAgent
from models.normalize import build_insightvm_report, normalize_unified
from reports.assets_export import build_assets_table, write_assets_csv, write_assets_json
from snapshot import build_snapshot_signature
from mad_common.collector_delivery import private_json, run_snapshot_cycle
from types import SimpleNamespace
from utils.state_manager import StateManager
from clients.backend_client import BackendClient
from config.insightvm_config import load_backend_settings, load_general_settings

INSIGHTVM_BANNER = r"""
  ___           _       _     _   __     ___  __
 |_ _|_ __  ___(_) __ _| |__ | |_/ /    / / |/ /
  | || '_ \/ __| |/ _` | '_ \| __| |   / /| ' /
  | || | | \__ \ | (_| | | | | |_| |  / / | . \
 |___|_| |_|___/_|\__, |_| |_|\__|_| /_/  |_|\_\
                   |___/
"""

ARTIFACTS_DIR = Path(__file__).resolve().parent.parent / "runtime" / "insightvm"


def setup_logging(level: str, log_file: Optional[str]) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(lvl)

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)

    if log_file:
        fh = RotatingFileHandler(log_file, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)


def save_json(path: str, data: dict) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Agente InsightVM Snapshot v1.0")

    p.add_argument("--env", default=None, help="Ruta opcional de un .env especifico")
    p.add_argument("--once", action="store_true", help="Run one cycle and exit")
    p.add_argument("--output", default=str(ARTIFACTS_DIR / "security_data.json"), help="Salida JSON cruda")
    p.add_argument("--normalized-output", default=str(ARTIFACTS_DIR / "security_data_normalized.json"), help="Salida JSON normalizada")

    p.add_argument("--assets-csv", default=str(ARTIFACTS_DIR / "assets_table.csv"), help="CSV tipo tabla de assets")
    p.add_argument("--assets-json", default=str(ARTIFACTS_DIR / "assets_table.json"), help="JSON tipo tabla de assets")
    p.add_argument("--export-assets", action="store_true", help="Generar assets_table.csv y assets_table.json")

    p.add_argument("--page-size", type=int, default=200, help="Tamaño de página para InsightVM")
    p.add_argument("--insight-timeout", type=int, default=None, help="Override timeout")
    p.add_argument("--insight-verify-ssl", choices=["true", "false"], default=None)

    p.add_argument("--log-level", default="INFO", help="DEBUG/INFO/WARNING/ERROR")
    p.add_argument("--log-file", default=None, help="Archivo de log")
    p.add_argument("--summary", action="store_true", help="Imprime resumen final")
    p.add_argument("--interval", type=int, default=0, help="Segundos entre ejecuciones (sobreescribe INTERVAL del .env)")

    return p


def main() -> None:
    args = build_parser().parse_args()
    setup_logging(args.log_level, args.log_file)
    log = logging.getLogger("main")
    log.info("Starting InsightVM Snapshot Agent...")
    log.info("\n%s", INSIGHTVM_BANNER)

    root_env = Path(__file__).resolve().parent.parent / ".env"
    load_dotenv(dotenv_path=root_env, override=True)
    if args.env:
        load_dotenv(dotenv_path=Path(args.env), override=True)

    general_cfg = load_general_settings()
    backend_cfg = load_backend_settings()
    state_manager = StateManager(state_file=general_cfg.state_file)

    interval = args.interval if args.interval > 0 else general_cfg.interval

    while True:
        try:
            execute_run(args, log, general_cfg, backend_cfg, state_manager)
        except Exception as e:
            log.error("Cycle failure: %s", e)
            if args.once:
                log.error("Single-run mode failed. Exiting.")
                raise
            time.sleep(5)
            continue

        if args.once:
            log.info("Single-run mode completed. Exiting.")
            break

        log.info("Modo servicio: Esperando %s segundos...", interval)
        time.sleep(interval)


def _build_scan_id(window_start: str, window_end: str) -> str:
    return f"insightvm-{window_start}-{window_end}-{uuid.uuid4().hex[:8]}"


def execute_run(args, log, general_cfg, backend_cfg, state_manager) -> None:
    def collect():
        raw = UnifiedAgent(state_manager=state_manager).run(
            page_size=args.page_size, insight_timeout=args.insight_timeout,
            insight_verify_ssl=args.insight_verify_ssl)
        ins_raw = raw.get("insightvm") or {}
        error = ins_raw.get("error") or (ins_raw.get("assets", {}).get("error") if isinstance(ins_raw.get("assets"), dict) else None)
        if error:
            raise RuntimeError(f"InsightVM collection failed: {error}")
        save_json(args.output, raw)
        normalized = normalize_unified(raw)
        save_json(args.normalized_output, normalized)
        if args.export_assets:
            rows = build_assets_table(normalized.get("insightvm", {}))
            write_assets_csv(args.assets_csv, rows)
            write_assets_json(args.assets_json, rows)
        return normalized.get("insightvm", {})

    if not backend_cfg.url:
        collect()
        log.info("Backend disabled; no delivery state changed")
        return
    cfg = SimpleNamespace(
        queue_dir=getattr(backend_cfg, "queue_dir", ARTIFACTS_DIR / "queue"),
        queue_flush_max=getattr(backend_cfg, "queue_flush_max", 20),
        output_mode="webhook", delivery_policy=getattr(backend_cfg, "delivery_policy", None),
        debug_report_path=ARTIFACTS_DIR / "debug_report.json",
        last_payload_path=ARTIFACTS_DIR / "last_payload_sent.json",
        delivery_meta_path=ARTIFACTS_DIR / "last_delivery_meta.json")
    def signature(data):
        return build_snapshot_signature({}, data.get("assets", []), data.get("findings", []))

    def prepare(data, baseline, decision):
        assets, findings = data.get("assets", []), data.get("findings", [])
        report = build_insightvm_report(
            scan_id=str(uuid.uuid4()), company_id=backend_cfg.company_id, api_key=backend_cfg.api_key or "",
            idempotency_key="", assets=assets, findings=findings,
            asset_ip_map={a["id"]: a.get("ip") for a in assets if a.get("id")},
            snapshot_signature=signature(data), snapshot_mode=decision["snapshot_mode"],
            send_reason=decision["reason"], snapshot_changed=decision["changed"],
            mad_version=backend_cfg.mad_version, integration_version=backend_cfg.integration_version,
            source=backend_cfg.source)
        return report, {}

    def send(report, key):
        backend = BackendClient(ingest_url=backend_cfg.url, tenant_id=backend_cfg.tenant_id,
                                api_key=backend_cfg.api_key, verify_ssl=backend_cfg.verify)
        return backend.send_data(data=report, idempotency_key=key, retries=3,
                                 backoff_seconds=5, timeout=60, queue_enabled=False)

    def persist(value):
        state_manager.state = dict(value)
        state_manager.save()

    state_manager.state = run_snapshot_cycle(
        integration="insightvm", cfg=cfg, state=state_manager.state, collect=collect,
        signature=signature, prepare=prepare, send=send, persist=persist)


if __name__ == "__main__":
    main()
