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
from snapshot import build_idempotency_key, build_snapshot_signature, decide_snapshot_send
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
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Agente InsightVM Snapshot v1.0")

    p.add_argument("--env", default=".env", help="Ruta del archivo .env (default: .env)")
    p.add_argument("--once", action="store_true", help="Run one cycle and exit")
    p.add_argument("--output", default="security_data.json", help="Salida JSON cruda")
    p.add_argument("--normalized-output", default="security_data_normalized.json", help="Salida JSON normalizada")

    p.add_argument("--assets-csv", default="assets_table.csv", help="CSV tipo tabla de assets")
    p.add_argument("--assets-json", default="assets_table.json", help="JSON tipo tabla de assets")
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

    env_path = Path(args.env)
    load_dotenv(dotenv_path=env_path, override=True)

    general_cfg = load_general_settings()
    backend_cfg = load_backend_settings()
    state_manager = StateManager(state_file=general_cfg.state_file)

    interval = args.interval if args.interval > 0 else general_cfg.interval

    while True:
        try:
            execute_run(args, log, general_cfg, backend_cfg, state_manager)
        except Exception as e:
            log.error("Cycle failure: %s", e)
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
    log.info("Iniciando ciclo de recolección...")

    agent = UnifiedAgent(state_manager=state_manager)
    raw = agent.run(
        page_size=args.page_size,
        insight_timeout=args.insight_timeout,
        insight_verify_ssl=args.insight_verify_ssl,
    )

    save_json(args.output, raw)
    normalized = normalize_unified(raw)
    save_json(args.normalized_output, normalized)

    if args.export_assets:
        rows = build_assets_table(normalized.get("insightvm", {}))
        write_assets_csv(args.assets_csv, rows)
        write_assets_json(args.assets_json, rows)

    ins_data = normalized.get("insightvm", {})
    assets = ins_data.get("assets", []) or []
    findings = ins_data.get("findings", []) or []

    if not backend_cfg.url:
        log.info("No backend URL configured. Skipping delivery.")
        return

    asset_ip_map: dict = {}
    for a in assets:
        a_id = a.get("id")
        a_ip = a.get("ip")
        if a_id:
            asset_ip_map[a_id] = a_ip

    current_signature = build_snapshot_signature(
        assets_raw=raw.get("insightvm", {}),
        normalized_assets=assets,
        normalized_findings=findings,
    )
    prev_signature = str(state_manager.state.get("snapshot_signature", ""))
    unchanged_cycles = int(state_manager.state.get("unchanged_cycles", 0) or 0)
    has_sent_once = bool(state_manager.state.get("has_sent_once", False))

    snapshot_decision = decide_snapshot_send(
        current_signature=current_signature,
        previous_signature=prev_signature,
        unchanged_cycles=unchanged_cycles,
        has_sent_once=has_sent_once,
        force_send_every_cycles=int(backend_cfg.force_send_every_cycles),
        snapshot_always_send=bool(backend_cfg.snapshot_always_send),
    )
    send_reason = str(snapshot_decision.get("reason", "snapshot_changed"))
    should_send = bool(snapshot_decision.get("should_send", False))
    snapshot_changed = bool(snapshot_decision.get("changed", False))
    unchanged_cycles = int(snapshot_decision.get("unchanged_cycles", 0))
    snapshot_mode = "always" if backend_cfg.snapshot_always_send else "delta_with_periodic_forced"

    state_manager.state["snapshot_signature"] = current_signature
    state_manager.state["unchanged_cycles"] = unchanged_cycles

    if not should_send:
        state_manager.state["last_send_result"] = "skipped_no_change"
        log.info(
            "Snapshot sin cambios (ciclo=%s/%s) reason=%s",
            unchanged_cycles,
            backend_cfg.force_send_every_cycles,
            send_reason,
        )
        state_manager.save()
        return

    now_utc = datetime.now(timezone.utc)
    window_start = now_utc.strftime("%Y%m%dT%H%M%SZ")
    window_end = window_start

    scan_id = _build_scan_id(window_start, window_end)
    idempotency_key = build_idempotency_key(
        backend_cfg.company_id, "insightvm", general_cfg.event_type, current_signature
    )

    report = build_insightvm_report(
        scan_id=scan_id,
        company_id=backend_cfg.company_id,
        api_key=backend_cfg.api_key or "",
        idempotency_key=idempotency_key,
        assets=assets,
        findings=findings,
        asset_ip_map=asset_ip_map,
        snapshot_signature=current_signature,
        snapshot_mode=snapshot_mode,
        send_reason=send_reason,
        snapshot_changed=snapshot_changed,
        mad_version=backend_cfg.mad_version,
        integration_version=backend_cfg.integration_version,
        source=backend_cfg.source,
    )

    log.info(
        "Prepared %s findings for delivery (reason=%s signatures=%s)",
        len(report["findings"]),
        send_reason,
        current_signature[:16],
    )

    save_json("last_payload_sent.json", report)

    backend = BackendClient(
        ingest_url=backend_cfg.url,
        api_key=backend_cfg.api_key,
        verify_ssl=backend_cfg.verify,
    )

    delivery_result = backend.send_data(
        data=report,
        idempotency_key=idempotency_key,
        retries=3,
        backoff_seconds=5,
        timeout=60,
        queue_enabled=backend_cfg.queue_enabled,
        queue_dir=backend_cfg.queue_dir,
        queue_flush_max=backend_cfg.queue_flush_max,
    )

    state_manager.state["snapshot_signature"] = current_signature
    state_manager.state["unchanged_cycles"] = 0
    state_manager.state["has_sent_once"] = True
    state_manager.state["last_idempotency_key"] = idempotency_key
    state_manager.state["last_send_result"] = "sent" if delivery_result.get("sent") else "queued"
    state_manager.save()

    log.info(
        "Report sent | findings=%s sent=%s queued=%s flushed=%s reason=%s",
        len(report["findings"]),
        delivery_result.get("sent"),
        delivery_result.get("queued"),
        delivery_result.get("flushed_from_queue"),
        send_reason,
    )

    if args.summary:
        log.info(
            "Resumen | assets=%s findings=%s",
            len(assets),
            len(findings),
        )


if __name__ == "__main__":
    main()
