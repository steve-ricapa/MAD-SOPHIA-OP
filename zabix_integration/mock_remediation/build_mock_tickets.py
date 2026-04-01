import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_REPORT_PATH = BASE_DIR / "debug_report.json"
DEFAULT_OUTPUT_PATH = BASE_DIR / "mock_remediation" / "mock_tickets.json"


@dataclass
class TicketContext:
    company_id: int
    created_by_user_id: int = 42
    assigned_to_agent: str = "victor"
    action_plan_version: str = "v1"
    dry_run: bool = True


def load_report(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def parse_host(raw_host: str) -> Dict[str, str]:
    if " (" in raw_host and raw_host.endswith(")"):
        host_name, host_ip = raw_host[:-1].split(" (", 1)
        return {"name": host_name.strip(), "ip": host_ip.strip()}
    return {"name": raw_host.strip(), "ip": "N/A"}


def normalize_status(finding: Dict[str, Any]) -> str:
    finding_type = finding.get("finding_type")
    if finding_type == "active_trigger":
        return "PENDING"
    if finding_type == "informational_trigger":
        return "PENDING"
    return "IGNORED"


def build_action_plan(finding: Dict[str, Any], host_data: Dict[str, str]) -> Optional[Dict[str, Any]]:
    finding_type = finding.get("finding_type")
    oid = finding.get("oid")

    if finding_type == "active_trigger":
        return {
            "strategy": "triage_and_contain",
            "summary": "Validar trigger activo, obtener contexto del host y ejecutar contencion operativa en Zabbix si aplica.",
            "candidate_mcp_tools": [
                "trigger_get",
                "problem_get",
                "host_get",
                "event_acknowledge",
                "maintenance_create",
            ],
            "steps": [
                {
                    "order": 1,
                    "tool": "trigger_get",
                    "purpose": "Obtener el trigger exacto y validar severidad/estado.",
                    "params": {"search": {"description": finding.get("name")}, "limit": 10},
                },
                {
                    "order": 2,
                    "tool": "host_get",
                    "purpose": "Resolver el host afectado y confirmar si sigue habilitado/monitoreado.",
                    "params": {"search": {"name": host_data["name"]}, "limit": 5},
                },
                {
                    "order": 3,
                    "tool": "problem_get",
                    "purpose": "Confirmar que el problema sigue activo antes de actuar.",
                    "params": {"search": {"name": finding.get("name")}, "limit": 10},
                },
                {
                    "order": 4,
                    "tool": "event_acknowledge",
                    "purpose": "Registrar la accion tomada y dejar trazabilidad operativa.",
                    "params": {"eventids": [], "message": f"Victor procesa ticket para {oid}"},
                    "requires_runtime_values": ["eventids"],
                },
                {
                    "order": 5,
                    "tool": "maintenance_create",
                    "purpose": "Aislar temporalmente el activo en mantenimiento si la respuesta requiere contencion.",
                    "params": {"name": f"Victor remediation {host_data['name']}", "active_since": 0, "active_till": 0, "hostids": []},
                    "requires_runtime_values": ["active_since", "active_till", "hostids"],
                    "optional": True,
                },
            ],
            "success_criteria": [
                "El trigger y el problema fueron confirmados.",
                "La accion queda registrada en Zabbix.",
                "El ticket puede pasar a COMPLETED o PARTIAL_SUCCESS con evidencia.",
            ],
        }

    if finding_type == "informational_trigger":
        return {
            "strategy": "validate_change_and_document",
            "summary": "Validar el cambio detectado, levantar contexto del activo y documentar si requiere accion fuera de Zabbix.",
            "candidate_mcp_tools": [
                "trigger_get",
                "host_get",
                "item_get",
                "event_get",
                "event_acknowledge",
            ],
            "steps": [
                {
                    "order": 1,
                    "tool": "trigger_get",
                    "purpose": "Confirmar el trigger informativo y su ultima modificacion.",
                    "params": {"search": {"description": finding.get("name")}, "limit": 10},
                },
                {
                    "order": 2,
                    "tool": "host_get",
                    "purpose": "Resolver el activo afectado.",
                    "params": {"search": {"name": host_data["name"]}, "limit": 5},
                },
                {
                    "order": 3,
                    "tool": "item_get",
                    "purpose": "Buscar items relacionados para identificar el valor que cambio.",
                    "params": {"search": {"name": "App-ID"}, "limit": 10},
                },
                {
                    "order": 4,
                    "tool": "event_acknowledge",
                    "purpose": "Dejar constancia del analisis o derivacion.",
                    "params": {"eventids": [], "message": f"Victor revisa cambio observado en {oid}"},
                    "requires_runtime_values": ["eventids"],
                },
            ],
            "success_criteria": [
                "El trigger fue validado y clasificado.",
                "Existe evidencia de revision o derivacion.",
                "Si no hay accion directa en Zabbix, el ticket queda documentado para otra capa de remediacion.",
            ],
        }

    return None


def build_ticket(ticket_id: int, report: Dict[str, Any], finding: Dict[str, Any], ctx: TicketContext) -> Optional[Dict[str, Any]]:
    status = normalize_status(finding)
    if status == "IGNORED":
        return None

    host_data = parse_host(finding.get("host", "Unknown (N/A)"))
    finding_id = finding.get("oid", f"finding-{ticket_id}")
    action_plan = build_action_plan(finding, host_data)
    severity = finding.get("severity", "information").upper()
    subject = f"[{severity}] Remediacion Zabbix para {host_data['name']} - {finding.get('name', 'finding')}"
    now = datetime.now(timezone.utc).isoformat()

    return {
        "id": ticket_id,
        "company_id": report.get("company_id", ctx.company_id),
        "created_by_user_id": ctx.created_by_user_id,
        "assigned_to_agent": ctx.assigned_to_agent,
        "source": "zabbix",
        "scanner_type": report.get("scanner_type", "zabbix"),
        "scan_id": report.get("scan_id"),
        "finding_id": finding_id,
        "dedup_key": f"zabbix:{finding_id}",
        "subject": subject,
        "description": finding.get("description", ""),
        "status": status,
        "executed_at": None,
        "created_at": now,
        "action_plan": action_plan,
        "action_plan_version": ctx.action_plan_version,
        "approved_by_user_id": None,
        "approved_at": None,
        "rejected_by_user_id": None,
        "rejected_at": None,
        "execution_status": "NOT_STARTED",
        "execution_logs": [],
        "verification_status": "NOT_VERIFIED",
        "verification_logs": [],
        "requires_approval": finding.get("finding_type") == "active_trigger",
        "dry_run": ctx.dry_run,
        "severity": severity,
        "risk_score": finding.get("cvss", 0.0),
        "finding_type": finding.get("finding_type"),
        "asset": {
            "host": host_data["name"],
            "ip": host_data["ip"],
            "port": finding.get("port", "0"),
            "protocol": finding.get("protocol", "unknown"),
        },
        "finding": finding,
        "remediation_context": {
            "cve": finding.get("cve"),
            "impact": finding.get("impact"),
            "solution_hint": finding.get("solution"),
        },
    }


def build_tickets(report: Dict[str, Any], ctx: TicketContext) -> List[Dict[str, Any]]:
    tickets: List[Dict[str, Any]] = []
    next_id = 1000
    for finding in report.get("findings", []):
        ticket = build_ticket(next_id, report, finding, ctx)
        if ticket:
            tickets.append(ticket)
            next_id += 1
    return tickets


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)


def main() -> None:
    report = load_report(DEFAULT_REPORT_PATH)
    ctx = TicketContext(company_id=int(report.get("company_id", 1)))
    tickets = build_tickets(report, ctx)
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_report": str(DEFAULT_REPORT_PATH),
        "ticket_count": len(tickets),
        "tickets": tickets,
    }
    save_json(DEFAULT_OUTPUT_PATH, output)
    print(f"Generated {len(tickets)} mock tickets at {DEFAULT_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
