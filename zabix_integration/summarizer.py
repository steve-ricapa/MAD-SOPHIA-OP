from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import hashlib
import json

SEVERITY_LABEL = {
    0: "Not classified",
    1: "Information",
    2: "Warning",
    3: "Average",
    4: "High",
    5: "Disaster",
}

SEVERITY_MAPPING = {
    5: "disaster",
    4: "high",
    3: "average",
    2: "warning",
    1: "information",
    0: "not_classified",
}

def build_fingerprint(payload: Dict[str, Any]) -> str:
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def summarize(scan_id: str, company_id: int, api_key: str, api_version: str, problems: List[Dict[str, Any]], events: List[Dict[str, Any]], all_hosts: Optional[List[Dict[str, Any]]] = None, all_triggers: Optional[List[Dict[str, Any]]] = None, state: Optional[Dict[str, Any]] = None) -> tuple[Dict[str, Any], Dict[str, str]]:
    counts = Counter()
    findings = []
    all_hosts = all_hosts or []
    all_triggers = all_triggers or []
    state = state or {}
    processed_findings = state.get("processed_findings", {})
    new_findings_state = {}

    # Mapear cuáles Triggers tienen problemas activos ahora mismo
    active_trigger_ids = {p.get("objectid") for p in problems}

    # Agrupar triggers por host para resumir
    host_summary = {}

    # 1. Clasificación Inteligente
    for t in all_triggers:
        hosts = t.get("hosts") or []
        host_name = hosts[0].get("name") if hosts else "Zabbix System"
        trigger_id = t.get("triggerid")
        is_active = trigger_id in active_trigger_ids
        
        # Extraer tags para decidir si es "especial"
        tags = {tag.get("tag").lower(): tag.get("value") for tag in (t.get("tags") or [])}
        has_custom_info = any(k in tags for k in ["cve", "cvss", "solution", "impact"])

        if host_name not in host_summary:
            host_summary[host_name] = {"active_or_special": [], "healthy_count": 0, "ip": "N/A", "port": "0"}
        
        # Guardar IP/Puerto del host
        interfaces = t.get("interfaces") or []
        main_interface = next((i for i in interfaces if i.get("main") == "1"), interfaces[0]) if interfaces else {}
        host_summary[host_name]["ip"] = main_interface.get("ip", "N/A")
        host_summary[host_name]["port"] = main_interface.get("port", "0")

        # Si está activo O tiene info personalizada (CVE), lo mostramos individual
        if is_active or has_custom_info:
            host_summary[host_name]["active_or_special"].append(t)
        else:
            host_summary[host_name]["healthy_count"] += 1

    # 2. Construir Findings (Prioridad: Datos reales de Zabbix)
    for host_name, data in host_summary.items():
        # A. ALERTAS ACTIVAS O REGLAS CON INFO ESPECIAL (CVE, etc.)
        for t in data["active_or_special"]:
            trigger_id = t.get("triggerid")
            last_change = t.get("lastchange", "0")
            
            is_active = trigger_id in active_trigger_ids
            sev_num = int(t.get("priority", 0))
            sev_label = SEVERITY_MAPPING.get(sev_num, "not_classified")
            
            if is_active:
                counts[sev_label] += 1
            
            tags = {tag.get("tag").lower(): tag.get("value") for tag in (t.get("tags") or [])}
            description = t.get("description", "").replace("{HOST.NAME}", host_name)
            
            # Buscar CVE en tags o texto
            cve_val = tags.get("cve", "INTERNAL-ZBX")
            if cve_val == "INTERNAL-ZBX" and "CVE-" in description.upper():
                import re
                found = re.search(r'(CVE-\d{4}-\d+)', description, re.IGNORECASE)
                if found: cve_val = found.group(1).upper()

            finding = {
                "name": description,
                "severity": sev_label,
                "cvss": float(tags.get("cvss", sev_num * 2.0 if sev_num > 0 else 1.0)),
                "cve": cve_val,
                "oid": f"zbx-trig-{t['triggerid']}",
                "host": f"{host_name} ({data['ip']})",
                "port": tags.get("port", data["port"] if data["port"] != "0" else "161"),
                "protocol": tags.get("protocol", "snmp/agent"),
                "description": f"{'ALERTA ACTIVA' if is_active else 'ESTADO OK'}: {description}",
                "solution": tags.get("solution", "Accion requerida en consola Zabbix."),
                "impact": tags.get("impact", "Monitoreo activo o recurso afectado."),
                "finding_type": "active_trigger" if is_active else "informational_trigger",
            }
            finding_state_key = f"trigger_{trigger_id}"
            finding_fingerprint = build_fingerprint({
                "last_change": last_change,
                "finding": finding,
            })

            new_findings_state[finding_state_key] = finding_fingerprint
            if processed_findings.get(finding_state_key) == finding_fingerprint:
                continue

            findings.append(finding)

        # B. RESUMEN DE REGLAS (Heartbeat de salud - Se cuenta globalmente pero no siempre se envía el finding)
        displayed_ids = {t.get("triggerid") for t in data["active_or_special"]}
        trigger_by_sev = Counter([int(t.get("priority", 0)) for t in all_triggers 
                                 if t.get("triggerid") not in displayed_ids 
                                 and (t.get("hosts") or [{}])[0].get("name") == host_name])
        
        for sev_num, count in trigger_by_sev.items():
            if count == 0: continue
            sev_label = SEVERITY_MAPPING.get(sev_num, "not_classified")
            
            # El resumen lo enviamos solo si cambia el conteo total por host
            summary_id = f"summary_{host_name}_{data['ip']}_{sev_num}"
            summary_payload = {
                "name": f"Rule Group ({sev_label}): {host_name}",
                "severity": sev_label,
                "cvss": float(sev_num * 1.5 if sev_num > 0 else 1.0),
                "cve": "N/A",
                "oid": f"zbx-chk-{host_name}-{sev_num}",
                "host": f"{host_name} ({data['ip']})",
                "port": data["port"] if data["port"] != "0" else "161",
                "protocol": "snmp/agent",
                "description": f"Monitoreando con exito {count} reglas de nivel {sev_label}.",
                "solution": "No se requiere accion, estado estable.",
                "impact": "Proteccion activa.",
                "finding_type": "health_summary",
            }
            summary_val = build_fingerprint({"count": count, "summary": summary_payload})
            
            if processed_findings.get(summary_id) != summary_val:
                findings.append(summary_payload)
            
            new_findings_state[summary_id] = summary_val

    scanned_at = datetime.now(timezone.utc).isoformat()
    cvss_max = max([f["cvss"] for f in (findings if findings else [{"cvss": 0.0}])])
    
    report = {
        "scan_id": scan_id,
        "company_id": int(company_id),
        "api_key": api_key,
        "scanned_at": scanned_at,
        "event_type": "vuln_scan_report",
        "scanner_type": "zabbix",
        "scan_summary": {
            "scan_id": scan_id,
            "scan_name": f"Zabbix Real-time Sync (v{api_version})",
            "status": "completed",
            "total_hosts": len(all_hosts),
            "scanned_at": scanned_at,
            "cvss_max": cvss_max,
            "scanner_type": "zabbix",
            "disaster_count": counts["disaster"],
            "high_count": counts["high"],
            "average_count": counts["average"],
            "warning_count": counts["warning"],
            "information_count": counts["information"],
            "not_classified_count": counts["not_classified"],
            "event_count": len(events),
        },
        "findings": findings
    }
    
    return report, new_findings_state
