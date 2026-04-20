import re
import sqlite3
import time
import json
from pathlib import Path
from typing import Any, Dict, Optional

import requests

from config import Config

METRIC_LINE_PATTERN = re.compile(
    r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)$"
)
LABEL_PATTERN = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"])*)"')


def _unescape_prometheus_value(value: str) -> str:
    return value.replace(r"\\", "\\").replace(r"\"", "\"").replace(r"\n", "\n")


def _normalize_port(raw_port: Any) -> str:
    if raw_port is None:
        return "0"
    value = str(raw_port).strip()
    if not value or value.lower() in {"null", "none", "nan"}:
        return "0"
    return value


def parse_prometheus_labels(raw_labels: str) -> Dict[str, str]:
    labels: Dict[str, str] = {}
    if not raw_labels:
        return labels

    for match in LABEL_PATTERN.finditer(raw_labels):
        key = match.group(1)
        val = _unescape_prometheus_value(match.group(2))
        labels[key] = val

    return labels


def parse_metrics(metrics_text: str) -> Dict[str, Dict[str, Any]]:
    monitors: Dict[str, Dict[str, Any]] = {}

    for raw_line in metrics_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        metric_match = METRIC_LINE_PATTERN.match(line)
        if not metric_match:
            continue

        metric_name = metric_match.group(1)
        labels = parse_prometheus_labels(metric_match.group(2) or "")
        value = float(metric_match.group(3))

        monitor_id = labels.get("monitor_id")
        if metric_name.startswith("monitor_") and not monitor_id:
            continue

        if metric_name.startswith("monitor_"):
            monitor = monitors.setdefault(
                monitor_id,
                {
                    "id": monitor_id,
                    "name": labels.get("monitor_name", f"monitor-{monitor_id}"),
                    "type": labels.get("monitor_type", ""),
                    "url": labels.get("monitor_url", ""),
                    "hostname": labels.get("monitor_hostname", ""),
                    "port": labels.get("monitor_port", ""),
                    "status": None,
                    "response_time_ms": None,
                    "response_time_seconds_1d": None,
                    "response_time_seconds_30d": None,
                    "response_time_seconds_365d": None,
                    "uptime_1d": None,
                    "uptime_30d": None,
                    "uptime_365d": None,
                    "cert_days_remaining": None,
                    "cert_is_valid": None,
                    "db": {},
                },
            )

            for key in ("monitor_name", "monitor_type", "monitor_url", "monitor_hostname", "monitor_port"):
                value_from_label = labels.get(key)
                if value_from_label:
                    monitor_key = key.replace("monitor_", "")
                    if monitor_key == "port":
                        monitor[monitor_key] = _normalize_port(value_from_label)
                    else:
                        monitor[monitor_key] = value_from_label

            if metric_name == "monitor_status":
                monitor["status"] = int(value)
            elif metric_name == "monitor_response_time":
                monitor["response_time_ms"] = float(value)
            elif metric_name == "monitor_uptime_ratio":
                window = labels.get("window")
                if window == "1d":
                    monitor["uptime_1d"] = float(value)
                elif window == "30d":
                    monitor["uptime_30d"] = float(value)
                elif window == "365d":
                    monitor["uptime_365d"] = float(value)
            elif metric_name == "monitor_response_time_seconds":
                window = labels.get("window")
                if window == "1d":
                    monitor["response_time_seconds_1d"] = float(value)
                elif window == "30d":
                    monitor["response_time_seconds_30d"] = float(value)
                elif window == "365d":
                    monitor["response_time_seconds_365d"] = float(value)
            elif metric_name == "monitor_cert_days_remaining":
                monitor["cert_days_remaining"] = float(value)
            elif metric_name == "monitor_cert_is_valid":
                monitor["cert_is_valid"] = bool(int(value))

    parsed = {mid: m for mid, m in monitors.items() if m.get("status") is not None}
    if not parsed:
        raise ValueError("No se encontraron metricas monitor_status en /metrics.")

    return parsed


def _safe_json_loads(raw: Optional[str]) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        loaded = json.loads(raw)
        if isinstance(loaded, dict):
            return loaded
    except (json.JSONDecodeError, TypeError):
        return {}
    return {}


def enrich_with_db(monitors: Dict[str, Dict[str, Any]], db_path: Path) -> Dict[str, Dict[str, Any]]:
    if not db_path.exists():
        return monitors

    monitor_ids = [int(mid) for mid in monitors.keys() if str(mid).isdigit()]
    if not monitor_ids:
        return monitors

    placeholders = ",".join(["?"] * len(monitor_ids))
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    try:
        rows = cur.execute(
            f"""
            SELECT
                id, active, interval, maxretries, retry_interval, timeout, method, keyword,
                upside_down, ignore_tls, parent, description, created_date
            FROM monitor
            WHERE id IN ({placeholders})
            """,
            monitor_ids,
        ).fetchall()
        monitor_details = {str(r["id"]): dict(r) for r in rows}

        heartbeat_rows = cur.execute(
            f"""
            SELECT h.monitor_id, h.status, h.msg, h.ping, h.time, h.duration, h.retries, h.response
            FROM heartbeat h
            JOIN (
              SELECT monitor_id, MAX(id) AS max_id
              FROM heartbeat
              WHERE monitor_id IN ({placeholders})
              GROUP BY monitor_id
            ) latest ON latest.max_id = h.id
            """,
            monitor_ids,
        ).fetchall()
        latest_heartbeat = {str(r["monitor_id"]): dict(r) for r in heartbeat_rows}

        recent_rows = cur.execute(
            f"""
            SELECT h.monitor_id, h.status, h.msg, h.ping, h.time, h.duration, h.retries
            FROM heartbeat h
            WHERE h.monitor_id IN ({placeholders})
              AND h.id IN (
                SELECT id
                FROM heartbeat h2
                WHERE h2.monitor_id = h.monitor_id
                ORDER BY id DESC
                LIMIT 20
              )
            ORDER BY h.monitor_id, h.id DESC
            """,
            monitor_ids,
        ).fetchall()
        recent_by_monitor: Dict[str, list[Dict[str, Any]]] = {}
        for row in recent_rows:
            monitor_id = str(row["monitor_id"])
            recent_by_monitor.setdefault(monitor_id, []).append(
                {
                    "status": row["status"],
                    "message": row["msg"],
                    "ping_ms": row["ping"],
                    "checked_at": row["time"],
                    "duration_seconds": row["duration"],
                    "retries": row["retries"],
                }
            )

        tag_rows = cur.execute(
            f"""
            SELECT mt.monitor_id, t.name, t.color, mt.value
            FROM monitor_tag mt
            JOIN tag t ON t.id = mt.tag_id
            WHERE mt.monitor_id IN ({placeholders})
            ORDER BY mt.monitor_id, t.name
            """,
            monitor_ids,
        ).fetchall()
        tags_by_monitor: Dict[str, list[Dict[str, Any]]] = {}
        for row in tag_rows:
            monitor_id = str(row["monitor_id"])
            tags_by_monitor.setdefault(monitor_id, []).append(
                {"name": row["name"], "color": row["color"], "value": row["value"]}
            )

        tls_rows = cur.execute(
            f"""
            SELECT mti.monitor_id, mti.info_json
            FROM monitor_tls_info mti
            JOIN (
              SELECT monitor_id, MAX(id) AS max_id
              FROM monitor_tls_info
              WHERE monitor_id IN ({placeholders})
              GROUP BY monitor_id
            ) latest ON latest.max_id = mti.id
            """,
            monitor_ids,
        ).fetchall()
        tls_by_monitor = {str(r["monitor_id"]): _safe_json_loads(r["info_json"]) for r in tls_rows}

        hourly_rows = cur.execute(
            f"""
            SELECT
                monitor_id,
                SUM(up) AS up_24h,
                SUM(down) AS down_24h,
                AVG(ping) AS avg_ping_24h,
                MIN(ping_min) AS min_ping_24h,
                MAX(ping_max) AS max_ping_24h
            FROM stat_hourly
            WHERE monitor_id IN ({placeholders})
              AND timestamp >= CAST(strftime('%s','now') AS INTEGER) - (24 * 3600)
            GROUP BY monitor_id
            """,
            monitor_ids,
        ).fetchall()
        hourly_by_monitor = {str(r["monitor_id"]): dict(r) for r in hourly_rows}

        daily_rows = cur.execute(
            f"""
            SELECT
                monitor_id,
                SUM(up) AS up_30d,
                SUM(down) AS down_30d,
                AVG(ping) AS avg_ping_30d
            FROM stat_daily
            WHERE monitor_id IN ({placeholders})
              AND timestamp >= CAST(strftime('%s','now') AS INTEGER) - (30 * 86400)
            GROUP BY monitor_id
            """,
            monitor_ids,
        ).fetchall()
        daily_by_monitor = {str(r["monitor_id"]): dict(r) for r in daily_rows}

        for monitor_id, monitor in monitors.items():
            details = {
                "monitor_config": monitor_details.get(monitor_id, {}),
                "latest_heartbeat": latest_heartbeat.get(monitor_id, {}),
                "recent_heartbeats": recent_by_monitor.get(monitor_id, []),
                "tags": tags_by_monitor.get(monitor_id, []),
                "latest_tls_info": tls_by_monitor.get(monitor_id, {}),
                "stats_24h": hourly_by_monitor.get(monitor_id, {}),
                "stats_30d": daily_by_monitor.get(monitor_id, {}),
            }
            monitor["db"] = details

        return monitors
    finally:
        con.close()


class UptimeKumaCollector:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def _auth(self) -> Optional[tuple[str, str]]:
        if self.cfg.kuma_api_key_id and self.cfg.kuma_api_key:
            return self.cfg.kuma_api_key_id, self.cfg.kuma_api_key
        if self.cfg.kuma_user and self.cfg.kuma_password:
            return self.cfg.kuma_user, self.cfg.kuma_password
        return None

    def fetch_metrics_text(self) -> str:
        auth = self._auth()
        last_error: Optional[Exception] = None

        for attempt in range(1, max(self.cfg.http_retries, 1) + 1):
            try:
                response = requests.get(
                    self.cfg.metrics_url,
                    timeout=self.cfg.request_timeout,
                    verify=self.cfg.verify_ssl,
                    auth=auth,
                )
                response.raise_for_status()
                return response.text
            except Exception as exc:
                last_error = exc
                if attempt < max(self.cfg.http_retries, 1):
                    time.sleep(self.cfg.backoff_seconds)

        raise RuntimeError(f"No fue posible leer metricas desde {self.cfg.metrics_url}: {last_error}")

    def collect(self) -> Dict[str, Dict[str, Any]]:
        monitors = parse_metrics(self.fetch_metrics_text())
        if self.cfg.kuma_db_path:
            monitors = enrich_with_db(monitors, self.cfg.kuma_db_path)
        return monitors
