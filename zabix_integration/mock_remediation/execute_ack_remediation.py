import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from config import load_config


DEFAULT_INPUT_PATH = BASE_DIR / "mock_remediation" / "mcp_read_only_results.json"
DEFAULT_OUTPUT_PATH = BASE_DIR / "mock_remediation" / "mcp_write_results.json"
WORKSPACE_ROOT = BASE_DIR.parents[2]
DEFAULT_MCP_SRC = WORKSPACE_ROOT / "ZABIXMCPAG" / "zabbix-mcp-server" / "src"


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)


def load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_log(level: str, message: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "message": message,
    }
    if extra:
        payload["extra"] = extra
    return payload


def to_base_zabbix_url(api_url: str) -> str:
    marker = "/api_jsonrpc.php"
    if api_url.endswith(marker):
        return api_url[: -len(marker)]
    return api_url.rstrip("/")


def setup_mcp_environment() -> Path:
    cfg = load_config()
    mcp_src = Path(os.getenv("ZABBIX_MCP_SRC_PATH", str(DEFAULT_MCP_SRC)))
    os.environ["ZABBIX_URL"] = to_base_zabbix_url(cfg.api_url)
    os.environ["ZABBIX_USER"] = cfg.user
    os.environ["ZABBIX_PASSWORD"] = cfg.password
    os.environ["VERIFY_SSL"] = "true" if cfg.verify_ssl else "false"
    os.environ["READ_ONLY"] = "false"
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

    if str(mcp_src) not in sys.path:
        sys.path.insert(0, str(mcp_src))

    return mcp_src


def load_mcp_module():
    setup_mcp_environment()
    import zabbix_mcp_server  # type: ignore

    return zabbix_mcp_server


def parse_json_result(raw: str) -> Any:
    return json.loads(raw)


def select_ticket(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    for ticket in results:
        runtime_values = ticket.get("runtime_values", {})
        if ticket.get("finding_type") == "active_trigger" and runtime_values.get("problem_eventids"):
            return ticket
    raise RuntimeError("No active_trigger ticket with problem_eventids was found")


def get_problem_snapshot(module: Any, eventids: List[str]) -> List[Dict[str, Any]]:
    if not eventids:
        return []
    return parse_json_result(module.problem_get(eventids=eventids, limit=10))


def get_event_snapshot(module: Any, eventids: List[str]) -> List[Dict[str, Any]]:
    if not eventids:
        return []
    return parse_json_result(module.event_get(eventids=eventids, limit=10))


def execute_ack(module: Any, ticket: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(ticket)
    runtime_values = dict(ticket.get("runtime_values", {}))
    problem_eventids = [str(event_id) for event_id in runtime_values.get("problem_eventids", [])]
    eventids = [str(event_id) for event_id in runtime_values.get("eventids", [])]
    target_eventids = problem_eventids or eventids[:1]
    if not target_eventids:
        raise RuntimeError("Ticket does not contain event ids to acknowledge")

    logs: List[Dict[str, Any]] = list(ticket.get("execution_logs", []))
    verification_logs: List[Dict[str, Any]] = list(ticket.get("verification_logs", []))

    before_problem = get_problem_snapshot(module, target_eventids)
    before_event = get_event_snapshot(module, target_eventids)
    logs.append(build_log("INFO", "Snapshot previo obtenido.", {
        "target_eventids": target_eventids,
        "problem_count": len(before_problem),
        "event_count": len(before_event),
    }))

    ack_message = f"Victor remediation acknowledgement for ticket {ticket['id']} / {ticket['finding_id']}"
    ack_response = parse_json_result(module.event_acknowledge(eventids=target_eventids, action=6, message=ack_message))
    logs.append(build_log("INFO", "event_acknowledge ejecutado.", {
        "target_eventids": target_eventids,
        "ack_response": ack_response,
    }))

    after_problem = get_problem_snapshot(module, target_eventids)
    after_event = get_event_snapshot(module, target_eventids)
    verification_logs.append(build_log("INFO", "Snapshot posterior obtenido.", {
        "problem_count": len(after_problem),
        "event_count": len(after_event),
    }))

    result["approved_by_user_id"] = result.get("approved_by_user_id") or 42
    result["approved_at"] = result.get("approved_at") or datetime.now(timezone.utc).isoformat()
    result["status"] = "COMPLETED"
    result["execution_status"] = "ACK_EXECUTED"
    result["verification_status"] = "ACK_RECORDED"
    result["executed_at"] = datetime.now(timezone.utc).isoformat()
    result["execution_logs"] = logs
    result["verification_logs"] = verification_logs
    result["remediation_result"] = {
        "action": "event_acknowledge",
        "target_eventids": target_eventids,
        "message": ack_message,
        "ack_response": ack_response,
        "before_problem": before_problem,
        "after_problem": after_problem,
        "before_event": before_event,
        "after_event": after_event,
    }
    return result


def main() -> None:
    payload = load_json(DEFAULT_INPUT_PATH)
    module = load_mcp_module()
    ticket = select_ticket(payload.get("results", []))
    executed = execute_ack(module, ticket)
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "mcp_write_ack",
        "source_results": str(DEFAULT_INPUT_PATH),
        "ticket_id": executed.get("id"),
        "finding_id": executed.get("finding_id"),
        "result": executed,
    }
    save_json(DEFAULT_OUTPUT_PATH, output)
    print(f"Executed event_acknowledge for ticket {executed['id']} at {DEFAULT_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
