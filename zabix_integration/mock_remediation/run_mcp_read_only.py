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

DEFAULT_TICKETS_PATH = BASE_DIR / "mock_remediation" / "mock_tickets.json"
DEFAULT_RESULTS_PATH = BASE_DIR / "mock_remediation" / "mcp_read_only_results.json"
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
    os.environ["READ_ONLY"] = "true"
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


def resolve_host(module: Any, host_name: str) -> List[Dict[str, Any]]:
    return parse_json_result(module.host_get(search={"name": host_name}, limit=5))


def resolve_trigger(module: Any, description: str, hostids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    kwargs: Dict[str, Any] = {
        "search": {"description": description},
        "limit": 10,
    }
    if hostids:
        kwargs["hostids"] = hostids
    return parse_json_result(module.trigger_get(**kwargs))


def resolve_problem(module: Any, triggerids: List[str]) -> List[Dict[str, Any]]:
    if not triggerids:
        return []
    return parse_json_result(module.problem_get(objectids=triggerids, recent=True, limit=10))


def resolve_event(module: Any, triggerids: List[str]) -> List[Dict[str, Any]]:
    if not triggerids:
        return []
    return parse_json_result(module.event_get(objectids=triggerids, limit=10))


def resolve_items(module: Any, hostids: List[str], item_name: str) -> List[Dict[str, Any]]:
    if not hostids:
        return []
    return parse_json_result(module.item_get(hostids=hostids, search={"name": item_name}, limit=10))


def process_ticket(module: Any, ticket: Dict[str, Any]) -> Dict[str, Any]:
    ticket_result = dict(ticket)
    logs: List[Dict[str, Any]] = list(ticket.get("execution_logs", []))
    verification_logs: List[Dict[str, Any]] = list(ticket.get("verification_logs", []))

    host_name = ticket.get("asset", {}).get("host", "")
    finding_name = ticket.get("finding", {}).get("name", "")
    finding_type = ticket.get("finding_type")

    logs.append(build_log("INFO", "Victor inicia enriquecimiento con MCP real en modo read-only.", {
        "ticket_id": ticket.get("id"),
        "finding_id": ticket.get("finding_id"),
    }))

    hosts = resolve_host(module, host_name)
    hostids = [str(host["hostid"]) for host in hosts if host.get("hostid")]
    logs.append(build_log("INFO", "host_get ejecutado.", {
        "matched_hosts": len(hosts),
        "hostids": hostids,
    }))

    triggers = resolve_trigger(module, finding_name, hostids=hostids or None)
    triggerids = [str(trigger["triggerid"]) for trigger in triggers if trigger.get("triggerid")]
    logs.append(build_log("INFO", "trigger_get ejecutado.", {
        "matched_triggers": len(triggers),
        "triggerids": triggerids,
    }))

    problems = resolve_problem(module, triggerids)
    problem_eventids = [str(problem["eventid"]) for problem in problems if problem.get("eventid")]
    logs.append(build_log("INFO", "problem_get ejecutado.", {
        "matched_problems": len(problems),
        "problem_eventids": problem_eventids,
    }))

    events = resolve_event(module, triggerids)
    eventids = [str(event["eventid"]) for event in events if event.get("eventid")]
    logs.append(build_log("INFO", "event_get ejecutado.", {
        "matched_events": len(events),
        "eventids": eventids,
    }))

    items: List[Dict[str, Any]] = []
    if finding_type == "informational_trigger":
        item_hint = finding_name.split(" version ")[0] if " version " in finding_name else finding_name.split(" has changed ")[0]
        items = resolve_items(module, hostids, item_hint)
        logs.append(build_log("INFO", "item_get ejecutado.", {
            "matched_items": len(items),
            "itemids": [item.get("itemid") for item in items if item.get("itemid")],
            "search_hint": item_hint,
        }))

    runtime_values = {
        "hostids": hostids,
        "triggerids": triggerids,
        "problem_eventids": problem_eventids,
        "eventids": eventids,
        "items": items,
    }

    verification_logs.append(build_log("INFO", "Contexto resuelto desde MCP read-only.", {
        "hostids": hostids,
        "triggerids": triggerids,
        "problem_eventids": problem_eventids,
        "eventids": eventids,
    }))

    ticket_result["status"] = "READY_FOR_APPROVAL" if ticket.get("requires_approval") else "READY_FOR_EXECUTION"
    ticket_result["execution_status"] = "READ_ONLY_VALIDATED"
    ticket_result["verification_status"] = "CONTEXT_RESOLVED"
    ticket_result["executed_at"] = datetime.now(timezone.utc).isoformat()
    ticket_result["execution_logs"] = logs
    ticket_result["verification_logs"] = verification_logs
    ticket_result["runtime_values"] = runtime_values
    return ticket_result


def main() -> None:
    payload = load_json(DEFAULT_TICKETS_PATH)
    module = load_mcp_module()
    processed = [process_ticket(module, ticket) for ticket in payload.get("tickets", []) if ticket.get("status") == "PENDING"]
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "mcp_read_only",
        "mcp_src": str(Path(os.getenv("ZABBIX_MCP_SRC_PATH", str(DEFAULT_MCP_SRC)))),
        "source_tickets": str(DEFAULT_TICKETS_PATH),
        "processed_count": len(processed),
        "results": processed,
    }
    save_json(DEFAULT_RESULTS_PATH, output)
    print(f"Validated {len(processed)} tickets with MCP read-only at {DEFAULT_RESULTS_PATH}")


if __name__ == "__main__":
    main()
