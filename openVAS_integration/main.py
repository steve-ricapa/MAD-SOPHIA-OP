import os
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

import argparse
import hashlib
import json
import time
import socket
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any
from collections import Counter
from pathlib import Path
import traceback

from config import (
    OUTPUT_MODE, TXDXAI_INGEST_URL, TXDXAI_COMPANY_ID, TXDXAI_API_KEY,
    COLLECTOR, POLL_SECONDS, FORCE_SEND_EVERY_CYCLES, SNAPSHOT_ALWAYS_SEND, STATE_PATH, META_MAX_KB,
    GVM_HOST, GVM_PORT, GVM_USERNAME, GVM_PASSWORD, GVM_SOCKET, GVM_TRANSPORT,
    GVM_TLS_CAFILE, GVM_TLS_CERTFILE, GVM_TLS_KEYFILE, GVM_TIMEOUT,
    DEBUG, MAX_ERROR_REPEAT, DETAIL_LEVEL, TOP_N, REPORT_MAX_KB, FINDING_TEXT_MAX,
    STATE_TTL_DAYS, STATE_MAX_ITEMS,
    MAD_VERSION, OPENVAS_INTEGRATION_VERSION, SOURCE,
    validate_config,
)

from snapshot import build_snapshot_signature, decide_snapshot_send

from services import (
    FileLock, load_state, save_state, purge_sent,
    extract_severities, extract_report_stats, extract_findings,
    emit_payload, format_exception
)

OPENVAS_BANNER = r"""
   ___                   __     ___    ____
  / _ \ _ __   ___ _ __  \ \   / / \  / ___|
 | | | | '_ \ / _ \ '_ \  \ \ / / _ \ \___ \
 | |_| | |_) |  __/ | | |  \ V / ___ \ ___) |
  \___/| .__/ \___|_| |_|   \_/_/   \_\____/
       |_|
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="OpenVAS real-time integration agent")
    parser.add_argument("--once", action="store_true", help="Run one cycle and exit")
    parser.add_argument("--cycles", type=int, default=0, help="Run N cycles and exit (0=infinite)")
    return parser.parse_args()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


_error_counts: dict[tuple, int] = {}


def _signature(step: str, e: BaseException) -> tuple:
    return (step, type(e).__name__, str(e)[:200])


def _is_win_error(e: BaseException, code: int) -> bool:
    s = str(e)
    return f"WinError {code}" in s or f"[WinError {code}]" in s


def _suggestion(step: str, e: BaseException, context: dict) -> str:
    if isinstance(e, ModuleNotFoundError):
        if "gvm" in str(e).lower():
            return "Falta python-gvm en ESTE entorno/venv. Instala deps o usa COLLECTOR=simulated."
        return "Falta un mÃ³dulo. Verifica requirements y que el venv estÃ© activo."

    if isinstance(e, socket.gaierror):
        return "Error DNS (no resuelve host). Revisa nombre, DNS, o usa IP."

    if isinstance(e, TimeoutError):
        if _is_win_error(e, 10060):
            return "Host/puerto no responde (WinError 10060). Verifica IP/puerto/firewall/gvmd."
        return "Timeout: el host/servicio no respondiÃ³."

    if isinstance(e, ConnectionRefusedError):
        return "ConexiÃ³n rechazada: puerto cerrado o servicio caÃ­do."
    if _is_win_error(e, 10061):
        return "WinError 10061: conexiÃ³n rechazada."

    if "ssl" in type(e).__name__.lower() or "certificate" in str(e).lower():
        return "Problema TLS/certificado."

    if isinstance(e, ET.ParseError) or "ParseError" in type(e).__name__:
        return "XML invÃ¡lido. Revisa META_MAX_KB/REPORT_MAX_KB o reporte."

    if isinstance(e, PermissionError):
        return "Permiso denegado: revisa permisos."

    return "Revisa logs, variables y servicio gvmd."


def handle_exception(step: str, e: BaseException, context: dict):
    sig = _signature(step, e)
    _error_counts[sig] = _error_counts.get(sig, 0) + 1
    n = _error_counts[sig]

    if n > MAX_ERROR_REPEAT:
        if n == MAX_ERROR_REPEAT + 1:
            print(f"[{now()}] ERROR @ {step} repetido >{MAX_ERROR_REPEAT} veces. Se silenciarÃ¡.")
        return

    print("\n" + "!" * 90)
    print(format_exception(step, e, context))
    print(f"Sugerencia: {_suggestion(step, e, context)}")

    if step.startswith("cycle.gvm"):
        if GVM_SOCKET:
            print(f"Tip: usando socket GMP: {GVM_SOCKET}")
        else:
            print("Tip: valida conectividad al puerto GMP (9390 tÃ­picamente).")

    print("!" * 90 + "\n")


def _lname(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _iter_by_lname(root: ET.Element, name: str):
    for el in root.iter():
        if _lname(el.tag) == name:
            yield el


def _extract_report_id(task: ET.Element) -> str:
    report_id = ""
    for lr in _iter_by_lname(task, "last_report"):
        rid = (lr.get("id") or "").strip()
        if rid:
            report_id = rid
            break
        for rp in lr.iter():
            if _lname(rp.tag) == "report":
                rid2 = (rp.get("id") or "").strip()
                if rid2:
                    report_id = rid2
                    break
            if report_id:
                break
        if report_id:
            break
    return report_id


def _extract_task_snapshot_rows(tasks: list[ET.Element]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for task in tasks:
        task_id = (task.get("id") or "").strip()
        task_name = ""
        status = ""
        modification_time = ""
        for el in list(task):
            tag = _lname(el.tag)
            if tag == "name":
                task_name = (el.text or "").strip()
            elif tag == "status":
                status = (el.text or "").strip()
            elif tag == "modification_time":
                modification_time = (el.text or "").strip()

        rows.append(
            {
                "task_id": task_id,
                "task_name": task_name,
                "report_id": _extract_report_id(task),
                "status": status,
                "modification_time": modification_time,
            }
        )
    return rows


def simulated_tasks_xml() -> str:
    # con namespace para validar que el parser ya es robusto
    return """
    <get_tasks_response xmlns="urn:gmp">
      <tasks>
        <task id="sim-task-1"><name>Sim Task</name><last_report><report id="sim-report-1"/></last_report></task>
        <task id="sim-task-2"><name>Sim Task 2</name><last_report><report id="sim-report-2"/></last_report></task>
      </tasks>
    </get_tasks_response>
    """.strip()


def simulated_report_xml(report_id: str) -> str:
    return f"""
    <get_report_response xmlns="urn:gmp">
      <report id="{report_id}">
        <hosts><count>2</count></hosts>
        <vulns><count>4</count></vulns>
        <results>
          <result>
            <name>Vulnerabilidad CrÃ­tica</name>
            <severity>10.0</severity>
            <host>192.168.1.10</host>
            <port>22/tcp</port>
            <nvt oid="1.3.6.1.4.1.25623.1.0.12345">
              <description>DescripciÃ³n detallada de la vulnerabilidad crÃ­tica.</description>
              <impact>Impacto severo en la confidencialidad.</impact>
              <solution>Actualizar el servicio inmediatamente.</solution>
              <ref type="cve" id="CVE-2024-0001"/>
            </nvt>
          </result>
          <result><severity>7.5</severity><name>High sample</name><host>10.0.0.6</host><port>22/tcp</port></result>
          <result><severity>5.0</severity><name>Medium sample</name><host>10.0.0.7</host><port>80/tcp</port></result>
          <result><severity>3.2</severity><name>Low sample</name><host>10.0.0.8</host><port>53/udp</port></result>
          <result><severity>0.0</severity><name>Info sample</name><host>10.0.0.9</host><port>general</port></result>
        </results>
      </report>
    </get_report_response>
    """.strip()


def _parse_result_count(task_node: ET.Element) -> dict[str, int] | None:
    # Busca result_count ignorando namespace
    rc = None
    for el in task_node.iter():
        if _lname(el.tag) == "result_count":
            rc = el
            break
    if rc is None:
        return None

    def _get(tag: str) -> int:
        for ch in list(rc):
            if _lname(ch.tag) == tag:
                try:
                    # En GVM 20.08+ a veces existen estos tags dentro de result_count
                    return int(((ch.text or "0").strip()))
                except Exception:
                    return 0
        return 0

    out = {
        "critical": _get("critical"),
        "high": _get("high"),
        "medium": _get("medium"),
        "low": _get("low"),
        "info": _get("info") or _get("log"), # Fallback log/info
    }

    if all(v == 0 for v in out.values()):
        return None

    return out


def _should_include_findings(detail: str) -> bool:
    d = (detail or "summary").strip().lower()
    return d in {"findings", "full", "all"}


def _should_include_stats(detail: str) -> bool:
    d = (detail or "summary").strip().lower()
    return d in {"stats", "findings", "full", "all"}


def build_dashboard_blocks(
    results: dict[str, int] | None,
    findings: list[dict[str, Any]] | None,
    report_stats: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    r = results or {"critical": 0, "high": 0, "medium": 0, "low": 0}

    risk_score = (
        10 * int(r.get("critical", 0))
        + 5 * int(r.get("high", 0))
        + 2 * int(r.get("medium", 0))
        + 1 * int(r.get("low", 0))
    )

    if int(r.get("critical", 0)) > 0:
        risk_label = "critical"
    elif int(r.get("high", 0)) > 0:
        risk_label = "high"
    elif int(r.get("medium", 0)) > 0:
        risk_label = "medium"
    else:
        risk_label = "low"

    hosts = Counter()
    ports = Counter()
    cves = Counter()

    max_sev = 0.0
    sum_sev = 0.0
    cnt_sev = 0

    if findings:
        for f in findings:
            h = str(f.get("host", "") or "").strip()
            p = str(f.get("port", "") or "").strip()

            if h:
                hosts[h] += 1
            if p:
                ports[p] += 1

            for c in (f.get("cves") or []):
                c = str(c).strip()
                if c:
                    cves[c] += 1

            try:
                sev = float(f.get("severity", 0.0))
            except Exception:
                sev = 0.0

            if sev > max_sev:
                max_sev = sev
            sum_sev += sev
            cnt_sev += 1

    entities = {
        "assetsTop": hosts.most_common(10),
        "portsTop": ports.most_common(10),
        "cvesTop": cves.most_common(10),
    }

    metrics: dict[str, Any] = {
        "riskScore": risk_score,
        "riskLabel": risk_label,
        "findingsInPayload": len(findings or []),
        "uniqueHostsInPayload": len(hosts),
        "uniquePortsInPayload": len(ports),
        "uniqueCvesInPayload": len(cves),
        "maxSeverityInPayload": max_sev,
        "avgSeverityInPayload": (sum_sev / cnt_sev) if cnt_sev else 0.0,
    }

    if report_stats:
        try:
            metrics["hostsCount"] = int(report_stats.get("hosts_count", 0) or 0)
            metrics["vulnsCount"] = int(report_stats.get("vulns_count", 0) or 0)
        except Exception:
            pass

    return metrics, entities


print("[INFO] Starting OpenVAS Real-time Agent...")
print(OPENVAS_BANNER)

# âœ… valida config al arranque (falla rÃ¡pido con mensaje claro)
try:
    validate_config()
except Exception as e:
    handle_exception("startup.validate_config", e, {})
    raise

print(f"[{now()}] OUTPUT_MODE={OUTPUT_MODE} | COLLECTOR={COLLECTOR} | POLL_SECONDS={POLL_SECONDS}s")
print(f"[{now()}] STATE_PATH={STATE_PATH} | META_MAX_KB={META_MAX_KB}KB")
print(f"[{now()}] GVM_HOST={GVM_HOST}:{GVM_PORT}")
if GVM_SOCKET:
    print(f"[{now()}] GVM_SOCKET={GVM_SOCKET}")
print(f"[{now()}] GVM_TRANSPORT={GVM_TRANSPORT}")
print(f"[{now()}] DETAIL_LEVEL={DETAIL_LEVEL} | TOP_N={TOP_N} | REPORT_MAX_KB={REPORT_MAX_KB}KB | FINDING_TEXT_MAX={FINDING_TEXT_MAX}")
print(f"[{now()}] SNAPSHOT_ALWAYS_SEND={SNAPSHOT_ALWAYS_SEND} | FORCE_SEND_EVERY_CYCLES={FORCE_SEND_EVERY_CYCLES}")

lock_path = f"{STATE_PATH}.lock"
args = parse_args()
cycle_count = 0
cycle_errors_file = Path("artifacts") / "logs" / "cycle_errors.jsonl"
cycle_errors_file.parent.mkdir(parents=True, exist_ok=True)
had_cycle_error = False

while True:
    cycle_count += 1
    print(f"\n[{now()}] Nuevo ciclo")

    try:
        with FileLock(lock_path):
            state = load_state(STATE_PATH)
            sent_map = state.get("sent", {})
            if not isinstance(sent_map, dict):
                sent_map = {}
            sent_map = purge_sent(sent_map, max_age_days=int(STATE_TTL_DAYS), max_items=int(STATE_MAX_ITEMS))
            prev_signature = str(state.get("snapshot_signature", ""))
            unchanged_cycles = int(state.get("unchanged_cycles", 0) or 0)
            has_sent_once = bool(state.get("has_sent_once", False))

            tasks_xml = None
            active_collector = (COLLECTOR or "simulated").strip().lower()

            if active_collector == "gmp":
                from gvm_client import GVMClient
                with GVMClient(
                    GVM_HOST, GVM_PORT, GVM_USERNAME, GVM_PASSWORD,
                    socket_path=GVM_SOCKET,
                    transport=GVM_TRANSPORT,
                    cafile=GVM_TLS_CAFILE,
                    certfile=GVM_TLS_CERTFILE,
                    keyfile=GVM_TLS_KEYFILE,
                    timeout=GVM_TIMEOUT,
                ) as client:
                    print(f"[{now()}] GMP session established | transport={GVM_TRANSPORT} | collector=gmp")
                    tasks_xml = client.get_tasks()

            elif active_collector == "simulated":
                tasks_xml = simulated_tasks_xml()
            else:
                raise ValueError("COLLECTOR invÃ¡lido. Usa 'gmp' o 'simulated'.")

            if len(tasks_xml.encode("utf-8", errors="ignore")) > (META_MAX_KB * 1024):
                raise ValueError("XML de tasks excede META_MAX_KB")

            root = ET.fromstring(tasks_xml)
            tasks = list(_iter_by_lname(root, "task"))
            print(f"[{now()}] Tareas detectadas: {len(tasks)}")

            task_rows = _extract_task_snapshot_rows(tasks)
            current_signature = build_snapshot_signature(task_rows)
            snapshot_decision = decide_snapshot_send(
                current_signature=current_signature,
                previous_signature=prev_signature,
                unchanged_cycles=unchanged_cycles,
                has_sent_once=has_sent_once,
                force_send_every_cycles=int(FORCE_SEND_EVERY_CYCLES),
                snapshot_always_send=bool(SNAPSHOT_ALWAYS_SEND),
            )
            send_reason = str(snapshot_decision.get("reason", "snapshot_changed"))
            should_send = bool(snapshot_decision.get("should_send", False))
            snapshot_changed = bool(snapshot_decision.get("changed", False))
            unchanged_cycles = int(snapshot_decision.get("unchanged_cycles", 0))

            idempotency_digest = hashlib.sha256(current_signature.encode("utf-8")).hexdigest()
            idempotency_key = f"openvas-snapshot-{idempotency_digest}"

            next_state = dict(state)
            next_state["sent"] = sent_map
            next_state["snapshot_signature"] = current_signature
            next_state["unchanged_cycles"] = unchanged_cycles
            next_state["last_idempotency_key"] = idempotency_key

            if not should_send:
                next_state["last_send_result"] = "skipped_no_change"
                save_state(STATE_PATH, next_state)
                print(
                    f"[{now()}] Snapshot sin cambios "
                    f"(ciclo={unchanged_cycles}/{FORCE_SEND_EVERY_CYCLES}) "
                    f"reason={send_reason} sig={current_signature[:16]}"
                )
            else:
                send_all_reports = send_reason in {"always_snapshot", "force_send_cycle", "first_snapshot"}
                sent_in_cycle = 0

                for idx, task in enumerate(tasks):
                    try:
                        report_id = _extract_report_id(task)

                        if not report_id:
                            if DEBUG:
                                print(f"[{now()}] task[{idx}] sin report_id")
                            continue

                        if not send_all_reports and report_id in sent_map:
                            continue

                        task_id = (task.get("id") or "").strip()
                        task_name = ""
                        task_status = ""
                        for el in list(task):
                            tag = _lname(el.tag)
                            if tag == "name":
                                task_name = (el.text or "").strip()
                            elif tag == "status":
                                task_status = (el.text or "").strip().lower()

                        severities = _parse_result_count(task)

                        report_xml: str | None = None
                        report_stats: dict[str, Any] | None = None
                        findings: list[dict[str, Any]] | None = None

                        need_report = (
                            (severities is None)
                            or _should_include_stats(DETAIL_LEVEL)
                            or _should_include_findings(DETAIL_LEVEL)
                        )

                        if need_report:
                            if active_collector == "simulated":
                                report_xml = simulated_report_xml(report_id)
                            else:
                                from gvm_client import GVMClient
                                with GVMClient(
                                    GVM_HOST, GVM_PORT, GVM_USERNAME, GVM_PASSWORD,
                                    socket_path=GVM_SOCKET,
                                    transport=GVM_TRANSPORT,
                                    cafile=GVM_TLS_CAFILE,
                                    certfile=GVM_TLS_CERTFILE,
                                    keyfile=GVM_TLS_KEYFILE,
                                    timeout=GVM_TIMEOUT,
                                ) as client:
                                    report_xml = client.get_report(report_id)

                            if severities is None:
                                severities = extract_severities(report_xml, max_kb=REPORT_MAX_KB)

                            if _should_include_stats(DETAIL_LEVEL):
                                report_stats = extract_report_stats(report_xml, max_kb=REPORT_MAX_KB)

                            if _should_include_findings(DETAIL_LEVEL):
                                findings = extract_findings(
                                    report_xml,
                                    top_n=int(TOP_N),
                                    text_max=int(FINDING_TEXT_MAX),
                                    max_kb=REPORT_MAX_KB,
                                )

                        metrics, entities = build_dashboard_blocks(severities, findings, report_stats)

                        counts = severities or {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                        total_hosts = int(report_stats.get("hosts_count", 0)) if report_stats else 0
                        if total_hosts == 0 and findings:
                            total_hosts = len(set(f.get("host") for f in findings if f.get("host")))

                        cvss_max = 0.0
                        if findings:
                            cvss_max = max((float(f.get("cvss", 0.0)) for f in findings), default=0.0)

                        scanned_at = now()

                        payload: dict[str, Any] = {
                            "scan_id": report_id,
                            "company_id": TXDXAI_COMPANY_ID,
                            "api_key": TXDXAI_API_KEY,
                            "idempotency_key": idempotency_key,
                            "scanned_at": scanned_at,
                            "event_type": "vuln_scan_report",
                            "scan_summary": {
                                "scanner_type": "openvas",
                                "scan_id": report_id,
                                "scan_name": task_name,
                                "status": task_status or "completed",
                                "total_hosts": total_hosts,
                                "scanned_at": scanned_at,
                                "cvss_max": cvss_max,
                                "results": {
                                    "critical": counts.get("critical", 0),
                                    "high": counts.get("high", 0),
                                    "medium": counts.get("medium", 0),
                                    "low": counts.get("low", 0),
                                    "info": counts.get("info", 0),
                                },
                                "meta": {
                                    "schema_version": "1.0",
                                    "mad_version": MAD_VERSION,
                                    "integration_version": OPENVAS_INTEGRATION_VERSION,
                                    "source": SOURCE,
                                    "snapshot_signature": current_signature,
                                    "snapshot_mode": "always" if SNAPSHOT_ALWAYS_SEND else "delta_with_periodic_forced",
                                    "snapshot_changed": snapshot_changed,
                                    "send_reason": send_reason,
                                    "task_id": task_id,
                                    **metrics,
                                },
                                "entities": entities,
                            },
                            "findings": findings or [],
                        }

                        ok = emit_payload(
                            output_mode=OUTPUT_MODE,
                            url=TXDXAI_INGEST_URL,
                            api_key=TXDXAI_API_KEY,
                            company_id=TXDXAI_COMPANY_ID,
                            payload=payload,
                            timeout=15,
                            require_https=True,
                        )

                        if ok:
                            sent_map[report_id] = int(time.time())
                            sent_in_cycle += 1

                    except Exception as e:
                        handle_exception(f"cycle.task[{idx}].process", e, {"hint": "Fallo procesando task/report"})
                        continue

                next_state["sent"] = sent_map
                next_state["has_sent_once"] = bool(has_sent_once or sent_in_cycle > 0)
                next_state["last_send_result"] = "sent" if sent_in_cycle > 0 else "no_payload_sent"
                if sent_in_cycle > 0:
                    next_state["last_sent_at"] = now()
                save_state(STATE_PATH, next_state)
                print(
                    f"[{now()}] Snapshot process | sent_reports={sent_in_cycle} "
                    f"reason={send_reason} changed={snapshot_changed} sig={current_signature[:16]}"
                )

    except KeyboardInterrupt:
        print(f"\n[{now()}] Detenido por usuario (Ctrl+C).")
        break
    except Exception as e:
        had_cycle_error = True
        try:
            with open(cycle_errors_file, "a", encoding="utf-8") as ef:
                ef.write(json.dumps({
                    "timestamp_utc": now(),
                    "cycle": cycle_count,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "collector": COLLECTOR,
                    "gvm_transport": GVM_TRANSPORT,
                    "gvm_host": GVM_HOST,
                    "gvm_port": GVM_PORT,
                    "gvm_socket": GVM_SOCKET,
                    "traceback": traceback.format_exc(),
                }, ensure_ascii=False) + "\n")
        except Exception:
            pass
        handle_exception("cycle.top_level", e, {"accion": "Se continuarÃ¡ el siguiente ciclo"})

    if args.once:
        print(f"[{now()}] Modo single-run completado. Saliendo.")
        raise SystemExit(1 if had_cycle_error else 0)
    if args.cycles and cycle_count >= args.cycles:
        print(f"[{now()}] Modo cycles={args.cycles} completado. Saliendo.")
        raise SystemExit(1 if had_cycle_error else 0)

    print(f"[{now()}] Esperando {POLL_SECONDS}s")
    time.sleep(POLL_SECONDS)
