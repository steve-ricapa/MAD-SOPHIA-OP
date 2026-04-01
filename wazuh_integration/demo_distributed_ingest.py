import argparse
import asyncio
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

from src.sender import Sender


SEVERITY_TO_LEVEL = {
    "critical": 15,
    "high": 12,
    "medium": 8,
    "low": 3,
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Genera y envia un payload demo distribuido para poblar el dashboard."
    )
    parser.add_argument("--critical", type=int, default=13)
    parser.add_argument("--high", type=int, default=7)
    parser.add_argument("--medium", type=int, default=2)
    parser.add_argument("--low", type=int, default=2)
    parser.add_argument("--send", action="store_true")
    return parser.parse_args()


def build_finding(severity, index, base_time):
    timestamp = (base_time + timedelta(minutes=index)).isoformat()
    rule_level = SEVERITY_TO_LEVEL[severity]
    suffix = f"{severity}-{index + 1:03d}"

    mitre = {
        "critical": {
            "ids": ["T1486"],
            "techniques": ["Data Encrypted for Impact"],
            "tactics": ["Impact"],
        },
        "high": {
            "ids": ["T1110"],
            "techniques": ["Brute Force"],
            "tactics": ["Credential Access"],
        },
        "medium": {
            "ids": ["T1078"],
            "techniques": ["Valid Accounts"],
            "tactics": ["Defense Evasion", "Persistence"],
        },
        "low": {
            "ids": [],
            "techniques": [],
            "tactics": [],
        },
    }

    titles = {
        "critical": "Demo ransomware behavior detected",
        "high": "Demo brute force activity detected",
        "medium": "Demo suspicious authentication pattern",
        "low": "Demo informational agent event",
    }

    groups = {
        "critical": ["ransomware", "malware", "demo"],
        "high": ["authentication_failures", "bruteforce", "demo"],
        "medium": ["authentication", "anomaly", "demo"],
        "low": ["inventory", "info", "demo"],
    }

    return {
        "dedup_id": f"demo-wazuh-{suffix}",
        "timestamp": timestamp,
        "severity": severity,
        "name": f"{titles[severity]} #{index + 1}",
        "host": f"demo-host-{(index % 4) + 1}",
        "description": f"Synthetic Wazuh demo finding for dashboard validation ({severity}).",
        "rule": {
            "id": f"demo-{severity[:1].upper()}{index + 1:03d}",
            "level": rule_level,
            "description": f"{titles[severity]} #{index + 1}",
            "groups": groups[severity],
        },
        "agent": {
            "id": f"D{(index % 4) + 1:03d}",
            "name": f"demo-agent-{(index % 4) + 1}",
            "ip": f"10.10.0.{(index % 4) + 10}",
        },
        "mitre": mitre[severity],
        "compliance": {
            "pci_dss": ["10.6.1"],
            "nist_800_53": ["AU.6"],
        },
    }


def build_report(company_id, api_key, counts):
    now = datetime.now(timezone.utc)
    base_time = now - timedelta(minutes=sum(counts.values()))
    findings = []

    for severity in ("critical", "high", "medium", "low"):
        for index in range(counts[severity]):
            findings.append(build_finding(severity, len(findings), base_time))

    scan_id = str(uuid.uuid4())
    scanned_at = now.isoformat()

    top_agents = []
    agent_counts = {}
    for finding in findings:
        agent_name = finding["agent"]["name"]
        agent_counts[agent_name] = agent_counts.get(agent_name, 0) + 1
    for agent_name, count in sorted(agent_counts.items(), key=lambda item: item[1], reverse=True):
        top_agents.append({"name": agent_name, "count": count})

    top_rules = [
        {"desc": f"Demo {severity} findings", "count": counts[severity]}
        for severity in ("critical", "high", "medium", "low") if counts[severity] > 0
    ]

    return {
        "scan_id": scan_id,
        "company_id": company_id,
        "api_key": api_key,
        "scanned_at": scanned_at,
        "event_type": "wazuh_alerts_report",
        "scanner_type": "wazuh",
        "scan_summary": {
            "scan_id": scan_id,
            "scan_name": "Wazuh Demo Distributed Payload",
            "status": "completed",
            "total_hosts": len(agent_counts),
            "scanned_at": scanned_at,
            "cvss_max": 9.8,
            "scanner_type": "wazuh",
            "disaster_count": counts["critical"],
            "high_count": counts["high"],
            "average_count": counts["medium"],
            "warning_count": counts["low"],
            "information_count": 0,
            "not_classified_count": 0,
            "metrics": {
                "trends": {
                    "severity_levels": {
                        "critical": counts["critical"],
                        "high": counts["high"],
                        "medium": counts["medium"],
                        "low": counts["low"],
                    }
                },
                "tops": {
                    "top_rules": top_rules,
                    "top_agents": top_agents[:5],
                }
            }
        },
        "findings": findings,
    }


async def main():
    args = parse_args()
    load_dotenv()

    company_id = int(os.getenv("TXDXAI_COMPANY_ID", 0))
    api_key = os.getenv("TXDXAI_API_KEY")
    ingest_url = os.getenv("TXDXAI_INGEST_URL")

    counts = {
        "critical": args.critical,
        "high": args.high,
        "medium": args.medium,
        "low": args.low,
    }
    report = build_report(company_id, api_key, counts)

    debug_dir = Path("debug_output")
    debug_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    full_path = debug_dir / f"demo_distributed_ingest_{stamp}.json"
    sample_path = debug_dir / f"demo_distributed_ingest_sample_{stamp}.json"

    with open(full_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=4, ensure_ascii=False)

    sample = dict(report)
    sample["api_key"] = "***REDACTED***"
    sample["findings"] = report["findings"][:5]

    with open(sample_path, "w", encoding="utf-8") as fh:
        json.dump(sample, fh, indent=4, ensure_ascii=False)

    print(json.dumps(
        {
            "scan_id": report["scan_id"],
            "counts": counts,
            "total_findings": len(report["findings"]),
            "full_file": str(full_path),
            "sample_file": str(sample_path),
            "target": ingest_url,
        },
        indent=4,
        ensure_ascii=False,
    ))

    if args.send:
        sender = Sender(ingest_url)
        success = await sender.send_report(report)
        print(json.dumps({"sent": success, "scan_id": report["scan_id"]}, indent=4))


if __name__ == "__main__":
    asyncio.run(main())
