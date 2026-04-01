from datetime import datetime, timezone
import hashlib
from loguru import logger

class Aggregator:
    def __init__(self, tenant_id):
        self.tenant_id = tenant_id

    def normalize_alert(self, raw_alert):
        """Transforms a raw Wazuh alert into the backend 'finding' format."""
        # Create a unique ID for idempotency
        alert_id = raw_alert.get('_id', str(hashlib.md5(str(raw_alert).encode()).hexdigest()))
        timestamp = raw_alert.get('timestamp', datetime.now(timezone.utc).isoformat())
        
        rule = raw_alert.get('rule', {})
        agent = raw_alert.get('agent', {})
        
        # Mapping Wazuh levels to generic severities (Aligned with Wazuh Dashboard UI)
        # Critical: 15+, High: 12-14, Medium: 7-11, Low: 0-6
        level = int(rule.get('level', 0))
        if level >= 15:
            severity = "critical"
        elif level >= 12:
            severity = "high"
        elif level >= 7:
            severity = "medium"
        else:
            severity = "low"

        # MITRE ATT&CK Enrichment — full context (ids, technique names, tactics)
        mitre_info = rule.get('mitre', {})
        mitre_block = {"ids": [], "techniques": [], "tactics": []}
        if isinstance(mitre_info, dict):
            ids = mitre_info.get('id', [])
            mitre_block["ids"] = [ids] if isinstance(ids, str) else ids
            techs = mitre_info.get('technique', [])
            mitre_block["techniques"] = [techs] if isinstance(techs, str) else techs
            tacs = mitre_info.get('tactic', [])
            mitre_block["tactics"] = [tacs] if isinstance(tacs, str) else tacs

        # Compliance frameworks — forwarded for SOC/audit dashboards
        compliance = {}
        for fw in ('pci_dss', 'hipaa', 'nist_800_53', 'gdpr', 'tsc'):
            val = rule.get(fw)
            if val:
                compliance[fw] = val

        return {
            "dedup_id": f"wazuh-{alert_id}",
            "timestamp": timestamp,
            "severity": severity,
            # Flat fields required by backend DB (scan_findings table)
            "name": rule.get('description', 'Wazuh Alert'),
            "host": agent.get('name', 'unknown'),
            "description": rule.get('description', ''),
            # Enriched nested structure for VICTOR/Sophia
            "rule": {
                "id": rule.get('id'),
                "level": level,
                "description": rule.get('description', 'Wazuh Alert'),
                "groups": rule.get('groups', []),
            },
            "agent": {
                "id": agent.get('id'),
                "name": agent.get('name', 'unknown'),
                "ip": agent.get('ip', ''),
            },
            "mitre": mitre_block,
            "compliance": compliance,
        }

    def create_report(self, processed_alerts, agent_summary, config):
        """Creates the final unified report envelope."""
        now = datetime.now(timezone.utc).isoformat()
        
        # Calculate trends and tops from the batch
        trends = self.calculate_trends(processed_alerts)
        tops = self.calculate_tops(processed_alerts)

        scan_summary = {
            "scan_id": config['scan_id'],
            "scan_name": "WazuhC Real-time Sync",
            "status": "completed",
            "total_hosts": agent_summary.get('total', 0) if agent_summary else 0,
            "scanned_at": now,
            "cvss_max": 0.0,
            "scanner_type": "wazuh",
            "disaster_count": trends['severity_levels'].get('critical', 0),
            "high_count": trends['severity_levels'].get('high', 0),
            "average_count": trends['severity_levels'].get('medium', 0),
            "warning_count": trends['severity_levels'].get('low', 0),
            "information_count": 0,
            "not_classified_count": 0,
            "metrics": {
                "trends": trends,
                "tops": tops
            }
        }

        return {
            "scan_id": config['scan_id'],
            "company_id": config['company_id'],
            "api_key": config['api_key'],
            "scanned_at": now,
            "event_type": "wazuh_alerts_report",
            "scanner_type": "wazuh",
            "scan_summary": scan_summary,
            "findings": processed_alerts
        }

    def calculate_trends(self, alerts):
        """Calculates severity counts for the current alert batch."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for alert in alerts:
            sev = alert.get('severity', 'low')
            if sev in severity_counts:
                severity_counts[sev] += 1
        return {"severity_levels": severity_counts}

    def calculate_tops(self, alerts, top_limit=5):
        """Calculates Top Rules and Top Agents from the batch."""
        rule_counts = {}
        agent_counts = {}

        for alert in alerts:
            # Rule Top (nested structure)
            rule_info = alert.get('rule', {})
            r_id = rule_info.get('id')
            r_desc = rule_info.get('description')
            rule_counts[r_id] = rule_counts.get(r_id, {"count": 0, "desc": r_desc})
            rule_counts[r_id]["count"] += 1

            # Agent Top (nested structure)
            agent_info = alert.get('agent', {})
            a_name = agent_info.get('name')
            agent_counts[a_name] = agent_counts.get(a_name, 0) + 1

        # Sort and limit
        top_rules = sorted(rule_counts.values(), key=lambda x: x['count'], reverse=True)[:top_limit]
        top_agents = sorted([{"name": k, "count": v} for k, v in agent_counts.items()], key=lambda x: x['count'], reverse=True)[:top_limit]

        return {
            "top_rules": top_rules,
            "top_agents": top_agents
        }

    def detect_agent_changes(self, current_agents, previous_agents_map):
        """
        Compares current agent list with previous state to find status changes.
        """
        changes = []
        current_map = {a['id']: a for a in current_agents}

        for agent_id, current_agent in current_map.items():
            prev_agent = previous_agents_map.get(agent_id)
            if prev_agent and prev_agent['status'] != current_agent['status']:
                changes.append({
                    "agent_id": agent_id,
                    "name": current_agent['name'],
                    "old_status": prev_agent['status'],
                    "new_status": current_agent['status'],
                    "last_seen": current_agent.get('lastKeepAlive')
                })
        
        return changes, current_map
