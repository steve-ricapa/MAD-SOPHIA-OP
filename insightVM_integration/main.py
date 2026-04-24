from __future__ import annotations

import argparse
import json
import logging
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from dotenv import load_dotenv

from agents.unified_agent import UnifiedAgent
from models.normalize import normalize_unified
from reports.assets_export import build_assets_table, write_assets_csv, write_assets_json
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
    p = argparse.ArgumentParser(description="Agente InsightVM Unificado")

    p.add_argument("--env", default=".env", help="Ruta del archivo .env (default: .env)")
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
    p.add_argument("--interval", type=int, default=0, help="Segundos entre ejecuciones")

    return p


def main() -> None:
    args = build_parser().parse_args()
    setup_logging(args.log_level, args.log_file)
    log = logging.getLogger("main")
    log.info("Starting InsightVM Real-time Agent...")
    log.info("\n%s", INSIGHTVM_BANNER)
    
    while True:
        execute_run(args, log)
        if args.interval <= 0:
            break
        log.info("Modo servicio: Esperando %s segundos...", args.interval)
        time.sleep(args.interval)


def execute_run(args, log) -> None:
    env_path = Path(args.env)
    load_dotenv(dotenv_path=env_path, override=True)
    log.info("Iniciando ciclo de recolección...")

    general_cfg = load_general_settings()
    backend_cfg = load_backend_settings()
    state_manager = StateManager(state_file=general_cfg.state_file)

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

    if backend_cfg.url:
        log.info("Preparando envío unificado al backend...")
        ins_data = normalized.get("insightvm", {})
        original_assets = ins_data.get("assets", [])
        
        new_assets = []
        for a in original_assets:
            aid = a.get("raw", {}).get("id")
            l_scan = a.get("raw", {}).get("history", [{}])[-1].get("scanId") if a.get("raw", {}).get("history") else None
            if not state_manager.is_asset_processed(aid, l_scan):
                new_assets.append(a)
                state_manager.mark_asset_processed(aid, l_scan)

        if not new_assets:
            log.info("No hay activos nuevos o actualizados.")
        else:
            log.info("Enviando %s activos nuevos al backend.", len(new_assets))
            
            new_asset_ids = {a.get("id") for a in new_assets}
            all_normalized_findings = ins_data.get("findings", [])
            delta_findings = []
            
            asset_id_to_ip = {a.get("id"): a.get("ip") for a in original_assets}

            for f in all_normalized_findings:
                if f.get("asset_id") in new_asset_ids:
                    raw_vuln = f.get("raw", {})
                    # InsightVM devuelve objetos para descripción y solución
                    desc_obj = raw_vuln.get("description", "No description available")
                    sol_obj = raw_vuln.get("solution", "No solution available")
                    
                    description = desc_obj
                    if isinstance(desc_obj, dict):
                        description = desc_obj.get("text") or desc_obj.get("html") or str(desc_obj)
                    
                    solution = sol_obj
                    if isinstance(sol_obj, dict):
                        solution = sol_obj.get("text") or sol_obj.get("html") or str(sol_obj)

                    delta_findings.append({
                        "name": f.get("title"),
                        "severity": f.get("severity"),
                        "cvss": f.get("cvss"),
                        "risk_score": f.get("risk_score"),
                        "cve": f.get("cve"),
                        "host": asset_id_to_ip.get(f.get("asset_id")),
                        "description": str(description),
                        "solution": str(solution),
                        "impact": str(f.get("impact") or "No impact information")
                    })

            counts = {
                "critical": sum(1 for f in all_normalized_findings if f.get("severity") == "critical"),
                "high": sum(1 for f in all_normalized_findings if f.get("severity") == "high"),
                "medium": sum(1 for f in all_normalized_findings if f.get("severity") == "medium"),
                "low": sum(1 for f in all_normalized_findings if f.get("severity") == "low"),
                "info": sum(1 for f in all_normalized_findings if f.get("severity") == "info"),
            }

            scanned_at = datetime.now(timezone.utc).isoformat()
            scan_id = f"IVM-{int(time.time())}"

            delta_report = {
                "scan_id": scan_id,
                "company_id": int(backend_cfg.company_id) if str(backend_cfg.company_id).isdigit() else backend_cfg.company_id,
                "api_key": backend_cfg.api_key,
                "scanned_at": scanned_at,
                "event_type": "vuln_scan_report",
                "scanner_type": "insightvm",
                "agent_type": "insightvm", # Enviamos ambos por compatibilidad
                
                "scan_summary": {
                    "scan_id": scan_id,
                    "scan_name": f"InsightVM Scan - {scanned_at}",
                    "status": "completed",
                    "total_hosts": len(original_assets),
                    "scanned_at": scanned_at,
                    "cvss_max": max([f.get("cvss") or 0.0 for f in all_normalized_findings] + [0.0]),
                    "critical_count": counts["critical"],
                    "high_count": counts["high"],
                    "medium_count": counts["medium"],
                    "low_count": counts["low"],
                    "info_count": counts["info"],
                    "scanner_type": "insightvm"
                },
                "findings": delta_findings,
            }
            
            save_json("last_payload_sent.json", delta_report)
            
            backend = BackendClient(ingest_url=backend_cfg.url, api_key=backend_cfg.api_key, verify_ssl=backend_cfg.verify)
            if backend.send_data(delta_report):
                log.info("Reporte enviado exitosamente.")
                state_manager.save()
            else:
                log.warning("Fallo al enviar al backend.")
    else:
        for a in normalized.get("insightvm", {}).get("assets", []):
            aid = a.get("raw", {}).get("id")
            l_scan = a.get("raw", {}).get("history", [{}])[-1].get("scanId") if a.get("raw", {}).get("history") else None
            state_manager.mark_asset_processed(aid, l_scan)
        state_manager.save()

    if args.summary:
        ins = normalized.get("insightvm") or {}
        log.info("Resumen | assets=%s findings=%s", len(ins.get("assets") or []), len(ins.get("findings") or []))
    log.info("Finalizado.")


if __name__ == "__main__":
    main()
