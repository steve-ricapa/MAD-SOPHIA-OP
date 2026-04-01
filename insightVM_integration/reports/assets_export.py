from __future__ import annotations

import csv
from typing import Any, Dict, List, Optional


def _get_nested(d: Dict[str, Any], path: List[str]) -> Optional[Any]:
    cur: Any = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def _pick(d: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def _as_int(x: Any) -> int:
    try:
        return int(x)
    except Exception:
        return 0


def _extract_counts(raw: Dict[str, Any]) -> Dict[str, int]:
    """
    Intentamos encontrar conteos por severidad en varias formas comunes.
    Si no existen, devuelve 0s.
    """
    candidates = [
        ["vulnerabilities"],
        ["vulnerability_counts"],
        ["vulnerabilityCounts"],
        ["vuln_counts"],
        ["risk", "vulnerabilities"],
    ]

    block = None
    for p in candidates:
        v = _get_nested(raw, p)
        if isinstance(v, dict):
            block = v
            break

    if not isinstance(block, dict):
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}

    critical = _as_int(_pick(block, "critical", "crit"))
    high = _as_int(_pick(block, "high", "severe"))
    medium = _as_int(_pick(block, "medium", "moderate"))
    low = _as_int(_pick(block, "low"))

    total = _as_int(_pick(block, "total", "all"))
    if total == 0:
        total = critical + high + medium + low

    return {"critical": critical, "high": high, "medium": medium, "low": low, "total": total}


def _extract_last_scan(raw: Dict[str, Any]) -> Optional[str]:
    return _pick(
        raw,
        "last_assessed",
        "lastAssessed",
        "last_scan_date",
        "lastScanDate",
        "last_scan",
        "lastScan",
        "assessed",
    )


def _extract_risk(raw: Dict[str, Any]) -> Optional[Any]:
    return _pick(raw, "riskScore", "risk_score", "risk", "risk_score_total")


def build_assets_table(insightvm_normalized: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Recibe normalized["insightvm"] (SourceResult como dict) y devuelve rows tipo tabla.
    Cada asset normalizado trae `raw` con lo que devuelva la API.
    """
    assets = insightvm_normalized.get("assets") or []
    rows: List[Dict[str, Any]] = []

    for a in assets:
        raw = a.get("raw") or {}
        counts = _extract_counts(raw)

        row = {
            "ip": a.get("ip"),
            "hostname": a.get("hostname") or _pick(raw, "host_name", "hostname", "name"),
            "os": a.get("os") or _pick(raw, "os", "operating_system", "os_name"),
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "total": counts["total"],
            "risk_score": _extract_risk(raw),
            "last_seen_or_scan": _extract_last_scan(raw),
        }
        rows.append(row)

    # Orden sugerido como UI: por risk_score desc si existe, si no por total desc
    def keyfn(r: Dict[str, Any]):
        rs = r.get("risk_score")
        try:
            rsf = float(rs)
        except Exception:
            rsf = -1.0
        return (rsf, r.get("total", 0))

    rows.sort(key=keyfn, reverse=True)
    return rows


def write_assets_csv(path: str, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        # crea csv vacío con headers estándar
        headers = ["ip", "hostname", "os", "critical", "high", "medium", "low", "total", "risk_score", "last_seen_or_scan"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=headers)
            w.writeheader()
        return

    headers = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        w.writerows(rows)


def write_assets_json(path: str, rows: List[Dict[str, Any]]) -> None:
    import json
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)
