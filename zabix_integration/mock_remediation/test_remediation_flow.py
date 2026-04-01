import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_TICKETS_PATH = BASE_DIR / "mock_remediation" / "mock_tickets.json"
DEFAULT_RESULTS_PATH = BASE_DIR / "mock_remediation" / "mock_execution_results.json"


def load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)


def build_log(level: str, message: str, extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "message": message,
    }
    if extra:
        payload["extra"] = extra
    return payload


def simulate_ticket(ticket: Dict[str, Any]) -> Dict[str, Any]:
    logs: List[Dict[str, Any]] = []
    logs.append(build_log("INFO", "Victor toma el ticket en estado pending.", {"ticket_id": ticket["id"]}))
    logs.append(build_log("INFO", "Se valida el finding origen.", {"finding_id": ticket["finding_id"], "finding_type": ticket["finding_type"]}))

    action_plan = ticket.get("action_plan") or {}
    for step in action_plan.get("steps", []):
        params = dict(step.get("params", {}))
        if step.get("tool") == "maintenance_create":
            params["active_since"] = int(datetime.now(timezone.utc).timestamp())
            params["active_till"] = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
            params["hostids"] = ["resolved-at-runtime"]
        elif step.get("tool") == "event_acknowledge":
            params["eventids"] = ["resolved-at-runtime"]

        logs.append(build_log(
            "INFO",
            f"Dry-run MCP preparado para {step['tool']}.",
            {"purpose": step.get("purpose"), "params": params},
        ))

    verification_logs = [
        build_log("INFO", "Validacion simulada completada.", {
            "success_criteria": action_plan.get("success_criteria", []),
        })
    ]

    status = "COMPLETED" if ticket.get("finding_type") == "informational_trigger" else "READY_FOR_APPROVAL"
    execution_status = "DRY_RUN_SUCCESS"
    verification_status = "SIMULATED_PASS"

    ticket_result = dict(ticket)
    ticket_result["status"] = status
    ticket_result["execution_status"] = execution_status
    ticket_result["verification_status"] = verification_status
    ticket_result["executed_at"] = datetime.now(timezone.utc).isoformat()
    ticket_result["execution_logs"] = logs
    ticket_result["verification_logs"] = verification_logs
    return ticket_result


def main() -> None:
    payload = load_json(DEFAULT_TICKETS_PATH)
    tickets = payload.get("tickets", [])
    processed = [simulate_ticket(ticket) for ticket in tickets if ticket.get("status") == "PENDING"]
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_tickets": str(DEFAULT_TICKETS_PATH),
        "processed_count": len(processed),
        "results": processed,
    }
    save_json(DEFAULT_RESULTS_PATH, output)
    print(f"Simulated remediation flow for {len(processed)} tickets at {DEFAULT_RESULTS_PATH}")


if __name__ == "__main__":
    main()
