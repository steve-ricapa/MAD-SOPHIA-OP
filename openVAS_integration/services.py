import json
import os
import time
import traceback
from typing import Any, Optional
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

try:
    from defusedxml import ElementTree as SafeET  # type: ignore
except Exception:
    SafeET = None

import xml.etree.ElementTree as StdET
import requests


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


DEBUG = _bool_env("DEBUG", False)


def _collect_string_lengths(payload: Any) -> dict[str, int]:
    lengths: dict[str, int] = {}

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                next_path = f"{path}.{k}" if path else str(k)
                walk(v, next_path)
            return
        if isinstance(node, list):
            for idx, v in enumerate(node):
                walk(v, f"{path}[{idx}]")
            return
        if isinstance(node, str):
            lengths[path or "$"] = len(node)

    walk(payload, "")
    return lengths


def _save_payload_debug(
    payload: dict[str, Any],
    status_code: int | None,
    response_excerpt: str,
    error_text: str | None = None,
) -> None:
    if not _bool_env("OPENVAS_PAYLOAD_DEBUG", False):
        return

    base_dir = os.getenv("OPENVAS_PAYLOAD_DEBUG_DIR", "").strip() or "runtime/payload_debug/openvas"
    out_dir = Path(base_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    scan_id = str(payload.get("scan_id") or payload.get("scanId") or "no_scan_id")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    suffix = uuid4().hex[:8]
    base_name = f"{stamp}_{scan_id}_{suffix}".replace("/", "_").replace("\\", "_").replace(" ", "_")

    payload_path = out_dir / f"payload_{base_name}.json"
    meta_path = out_dir / f"meta_{base_name}.json"

    string_lengths = _collect_string_lengths(payload)
    top_lengths = sorted(string_lengths.items(), key=lambda kv: kv[1], reverse=True)[:40]
    over_255 = [{"path": k, "length": v} for k, v in top_lengths if v > 255]

    meta = {
        "saved_at_utc": datetime.now(timezone.utc).isoformat(),
        "status_code": status_code,
        "response_excerpt": (response_excerpt or "")[:1000],
        "error_text": (error_text or "")[:1000],
        "scan_id": scan_id,
        "payload_bytes": len(json.dumps(payload, ensure_ascii=False).encode("utf-8")),
        "max_string_length": max(string_lengths.values()) if string_lengths else 0,
        "top_string_lengths": [{"path": k, "length": v} for k, v in top_lengths],
        "strings_over_255": over_255,
    }

    with open(payload_path, "w", encoding="utf-8") as pf:
        json.dump(payload, pf, ensure_ascii=False, indent=2)
    with open(meta_path, "w", encoding="utf-8") as mf:
        json.dump(meta, mf, ensure_ascii=False, indent=2)


def _root_cause(e: BaseException) -> str:
    if getattr(e, "__cause__", None) is not None:
        c = e.__cause__
        return f"{type(c).__name__}: {c}"
    if getattr(e, "__context__", None) is not None:
        c = e.__context__
        return f"{type(c).__name__}: {c}"
    return ""


def format_exception(step: str, e: BaseException, context: Optional[dict[str, Any]] = None) -> str:
    parts = []
    parts.append(f"[{_now()}] ERROR @ {step}")
    parts.append(f"Tipo: {type(e).__name__}")
    parts.append(f"Motivo: {str(e) if str(e) else '(sin mensaje)'}")

    rc = _root_cause(e)
    if rc:
        parts.append(f"Causa raÃ­z: {rc}")

    if context:
        parts.append("Contexto:")
        for k, v in context.items():
            parts.append(f"  - {k}: {v}")

    if DEBUG:
        parts.append("Stacktrace:")
        parts.append(traceback.format_exc())

    return "\n".join(parts)


def map_status(raw_status: str) -> str:
    value = (raw_status or "").strip().lower()
    if value in {"running", "run", "in progress", "in_progress"}:
        return "running"
    if value in {"pending", "queued", "requested"}:
        return "pending"
    if value in {"completed", "done", "finished"}:
        return "completed"
    return value or "unknown"


class FileLock:
    def __init__(self, lock_path: str):
        self.lock_path = lock_path
        self.f = None

    def __enter__(self):
        self.f = open(self.lock_path, "a+", encoding="utf-8")
        try:
            import fcntl  # type: ignore
            fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
        except Exception:
            # Windows / fallback best effort
            pass
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            import fcntl  # type: ignore
            fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            if self.f:
                self.f.close()
        except Exception:
            pass


# -------------------------
# STATE (compatible con main.py actual)
# -------------------------

def load_state(path: str) -> dict[str, Any]:
    """
    Soporta 2 formatos:
      - Nuevo: {"sent": {"<report_id>": <unix_ts>, ...}}
      - Antiguo: {"sent": ["id1","id2",...]} -> migra a dict con ts=0
    """
    step = "services.load_state"
    try:
        if not os.path.exists(path):
            return {"sent": {}}

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            raise ValueError("state.json no es dict")

        sent = data.get("sent", {})

        # Formato nuevo: dict
        if isinstance(sent, dict):
            out: dict[str, int] = {}
            for k, v in sent.items():
                if k is None:
                    continue
                rid = str(k).strip()
                if not rid:
                    continue
                try:
                    out[rid] = int(v)
                except Exception:
                    out[rid] = 0
            data["sent"] = out
            return data

        # Formato viejo: lista -> migra a dict(ts=0)
        if isinstance(sent, list):
            out2: dict[str, int] = {}
            for x in sent:
                if x is None:
                    continue
                rid = str(x).strip()
                if rid:
                    out2[rid] = 0
            data["sent"] = out2
            return data

        # Raro -> reset
        data["sent"] = {}
        return data

    except json.JSONDecodeError as e:
        print(format_exception(step, e, {"path": path, "accion": "estado reiniciado"}))
        return {"sent": {}}
    except Exception as e:
        _save_payload_debug(payload, None, "", str(e))
        print(format_exception(step, e, {"path": path, "accion": "estado reiniciado"}))
        return {"sent": {}}


def save_state(path: str, data: dict[str, Any]) -> None:
    """
    Guarda SOLO formato nuevo:
      {"sent": {"report_id": unix_ts, ...}}
    """
    step = "services.save_state"
    tmp = f"{path}.tmp"
    try:
        sent = data.get("sent", {})
        if not isinstance(sent, dict):
            raise ValueError("data['sent'] debe ser dict {report_id: timestamp}")

        clean: dict[str, int] = {}
        for k, v in sent.items():
            if k is None:
                continue
            rid = str(k).strip()
            if not rid:
                continue
            try:
                clean[rid] = int(v)
            except Exception:
                clean[rid] = 0

        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"sent": clean}, f, indent=2, ensure_ascii=False)

        os.replace(tmp, path)

    except Exception as e:
        _save_payload_debug(payload, None, "", str(e))
        print(format_exception(step, e, {"path": path, "tmp": tmp}))
        raise
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass


def purge_sent(
    sent_map: dict[str, Any],
    *,
    max_age_days: int = 30,
    max_items: int = 5000
) -> dict[str, int]:
    """
    Limpia el mapa de reportes ya enviados:
      sent_map = { report_id: unix_ts }

    - max_age_days: elimina entradas mÃ¡s viejas que N dÃ­as (si ts>0)
    - max_items: si hay demasiadas, conserva solo las mÃ¡s recientes

    Retorna dict[str,int] limpio.
    """
    step = "services.purge_sent"
    try:
        if not isinstance(sent_map, dict):
            return {}

        now_ts = int(time.time())
        cutoff = now_ts - max(0, int(max_age_days)) * 86400

        cleaned: dict[str, int] = {}
        for rid, ts in sent_map.items():
            if rid is None:
                continue
            rid_s = str(rid).strip()
            if not rid_s:
                continue

            try:
                ts_i = int(ts)
            except Exception:
                ts_i = 0

            # ts=0 (migrado/legacy) -> se conserva
            if ts_i == 0 or ts_i >= cutoff:
                cleaned[rid_s] = ts_i

        mi = int(max_items)
        if mi > 0 and len(cleaned) > mi:
            items = sorted(cleaned.items(), key=lambda kv: kv[1], reverse=True)[:mi]
            cleaned = {k: v for k, v in items}

        return cleaned

    except Exception as e:
        _save_payload_debug(payload, None, "", str(e))
        print(format_exception(step, e, {"max_age_days": max_age_days, "max_items": max_items}))
        try:
            return {str(k): int(v) for k, v in (sent_map or {}).items() if k is not None}
        except Exception:
            return {}


# -------------------------
# XML parsing helpers
# -------------------------

def _clip(s: str, n: int) -> str:
    s = (s or "").strip()
    if n <= 0:
        return s
    return s[:n]


def _clean_text(text: str) -> str:
    """
    Elimina etiquetas HTML residuales, saltos de lÃ­nea innecesarios (\n) 
    y espacios dobles para legibilidad en producciÃ³n.
    """
    if not text:
        return ""
    import re
    # 1. Eliminar etiquetas HTML/XML (con mayor precisiÃ³n)
    text = re.sub(r"<[^>]+>", " ", text)
    # 2. Reemplazar saltos de lÃ­nea y tabulaciones con espacios
    text = text.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    # 3. Colapsar espacios mÃºltiples a uno solo
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def get_severity_label(cvss_score: float) -> str:
    """Normaliza el string de severidad segÃºn el estÃ¡ndar del proyecto."""
    s = float(cvss_score)
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0.0:
        return "low"
    return "info"


def _parse_xml(xml_text: str, max_kb: int) -> Any:
    if not isinstance(xml_text, str) or not xml_text:
        raise ValueError("XML vacÃ­o o no str")

    max_bytes = int(max_kb) * 1024
    size = len(xml_text.encode("utf-8", errors="ignore"))
    if size > max_bytes:
        raise ValueError(f"XML excede lÃ­mite: {size} bytes > {max_bytes} bytes")

    ET = SafeET if SafeET is not None else StdET
    root = ET.fromstring(xml_text)  # type: ignore

    # Quita namespaces: "{...}severity" -> "severity"
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]

    return root


def _result_nodes(root: Any) -> list[Any]:
    """
    Tomar resultados preferentemente del reporte:
      report/results/result
    Evita capturar otros <result> que no son findings reales.
    """
    nodes = root.findall(".//report//results//result")
    if nodes:
        return nodes
    nodes = root.findall(".//results//result")
    if nodes:
        return nodes
    return root.findall(".//result")


def _safe_float(s: str, default: float = 0.0) -> float:
    try:
        return float((s or "").strip())
    except Exception:
        return default


def _safe_int(s: str, default: int = 0) -> int:
    try:
        return int((s or "").strip())
    except Exception:
        return default


# -------------------------
# Extractors
# -------------------------

def extract_severities(xml_text: str, max_kb: int = 256) -> dict[str, int]:
    step = "services.extract_severities"
    try:
        root = _parse_xml(xml_text, max_kb=max_kb)

        out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in _result_nodes(root):
            sev = _safe_float(r.findtext("severity", "") or "0", 0.0)

            if sev >= 9.0:
                out["critical"] += 1
            elif sev >= 7.0:
                out["high"] += 1
            elif sev >= 4.0:
                out["medium"] += 1
            elif sev > 0.0:
                out["low"] += 1
            else:
                out["info"] += 1

        return out

    except (StdET.ParseError,) as e:
        print(format_exception(step, e, {"hint": "XML mal formado"}))
        raise
    except Exception as e:
        _save_payload_debug(payload, None, "", str(e))
        print(format_exception(step, e, {"max_kb": max_kb}))
        raise


def extract_report_stats(xml_text: str, max_kb: int = 4096) -> dict[str, int]:
    if not xml_text:
        return {}

    root = _parse_xml(xml_text, max_kb=max_kb)

    def _int(path: str) -> int:
        return _safe_int(root.findtext(path, "0") or "0", 0)

    return {
        "hosts_count": _int(".//report//hosts//count"),
        "vulns_count": _int(".//report//vulns//count"),
        "apps_count": _int(".//report//apps//count"),
        "os_count": _int(".//report//os//count"),
        "ssl_certs_count": _int(".//report//ssl_certs//count"),
    }


def _extract_severity_from_result(r: Any) -> float:
    """
    Preferimos el severity del <result>.
    Si viene vacÃ­o, intentamos fallback a NVT severities/value.
    """
    sev = _safe_float(r.findtext("severity", "") or "", 0.0)
    if sev > 0.0:
        return sev

    nvt = r.find("nvt")
    if nvt is None:
        return 0.0

    v = (nvt.findtext(".//severities//severity//value", "") or "").strip()
    return _safe_float(v, 0.0)


def extract_findings(
    xml_text: str,
    *,
    top_n: int = 50,
    text_max: int = 300,
    max_kb: int = 4096
) -> list[dict[str, Any]]:
    """
    Extrae findings (vulns) desde <result>:
    name, severity, cvss, cve, host, port, description, solution, impact.
    Ordena por severity desc y retorna top_n.
    """
    if not xml_text:
        return []

    root = _parse_xml(xml_text, max_kb=max_kb)

    findings: list[dict[str, Any]] = []

    for r in _result_nodes(root):
        try:
            name = (r.findtext("name", "") or "").strip()
            host = (r.findtext("host", "") or "").strip()
            port = (r.findtext("port", "") or "").strip()

            nvt = r.find("nvt")
            nvt_oid = (nvt.get("oid") or "").strip() if nvt is not None else ""

            # filtro anti-basura
            if (not host and not port and not nvt_oid) or (name.lower() == "product"):
                continue

            cvss = _extract_severity_from_result(r)
            severity_str = get_severity_label(cvss)

            # CVEs: solo capturamos el primero para el campo 'cve' del contrato
            cve_id = None
            if nvt is not None:
                for ref in nvt.findall(".//ref"):
                    t = (ref.get("type") or "").lower()
                    if t == "cve":
                        cid = (ref.get("id") or "").strip()
                        if cid:
                            cve_id = cid
                            break
                
                if not cve_id:
                    cve_text = (nvt.findtext("cve", "") or "").strip()
                    if cve_text:
                        parts = cve_text.replace(",", " ").split()
                        for part in parts:
                            if part.upper().startswith("CVE-"):
                                cve_id = part.strip()
                                break
            
            # Null handling para CVE
            if not cve_id:
                cve_id = "No CVE assigned"

            description_raw = (nvt.findtext("description", "") or "").strip() if nvt is not None else ""
            summary_raw = (nvt.findtext("summary", "") or "").strip() if nvt is not None else ""
            
            # Si description estÃ¡ vacÃ­o, usamos summary como fallback
            raw_desc = description_raw if description_raw else summary_raw
            final_desc = _clean_text(raw_desc) or "No description available"
            
            solution_raw = (nvt.findtext("solution", "") or "").strip() if nvt is not None else ""
            final_solution = _clean_text(solution_raw) or "No solution provided"
            
            impact_raw = (nvt.findtext("impact", "") or "").strip() if nvt is not None else ""
            final_impact = _clean_text(impact_raw) or "No impact information"

            # Protocolo: suele venir en 'port' como '80/tcp'
            protocol = ""
            if "/" in port:
                port_parts = port.split("/", 1)
                port_val = port_parts[0]
                protocol = port_parts[1]
            else:
                port_val = port

            finding = {
                "name": _clip(name, text_max),
                "severity": severity_str,
                "cvss": float(cvss),
                "cve": cve_id,
                "oid": nvt_oid,
                "host": host,
                "port": port_val,
                "protocol": protocol,
                "description": final_desc,  # Quitamos clip para no truncar info crÃ­tica segÃºn prompt
                "solution": final_solution,
                "impact": final_impact,
            }

            if finding["name"] and (finding["host"] or nvt_oid):
                findings.append(finding)

        except Exception:
            continue

    findings.sort(key=lambda x: float(x.get("cvss", 0.0)), reverse=True)
    return findings[: max(0, int(top_n))]


# -------------------------
# Emit payload
# -------------------------

def emit_payload(
    *,
    output_mode: str,
    url: str,
    api_key: str,
    company_id: int,
    payload: dict[str, Any],
    timeout: int = 15,
    require_https: bool = True
) -> bool:
    step = "services.emit_payload"
    mode = (output_mode or "console").strip().lower()

    tls_verify_env = os.getenv("BACKEND_TLS_VERIFY", "true").strip().lower()
    tls_verify = tls_verify_env in {"1", "true", "yes", "y", "on"}

    try:
        if mode == "console":
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            print("\n" + "=" * 90)
            print(f"[{_now()}] TXDXAI INGEST (console-only)")
            print(f"[{_now()}] Payload size: {len(raw)/1024:.1f} KB")
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            print("=" * 90 + "\n")
            return True

        if not url:
            raise ValueError("TXDXAI_INGEST_URL vacÃ­o")

        if require_https and not url.startswith("https://"):
            raise ValueError("Backend URL debe ser HTTPS (o usa OUTPUT_MODE=console)")

        # âœ… EstandarizaciÃ³n a snake_case segÃºn requerimiento
        if isinstance(payload, dict):
            payload = dict(payload)  # copia para no mutar original
            if api_key:
                payload["api_key"] = api_key
            if company_id:
                payload["company_id"] = company_id

        headers = {"Content-Type": "application/json"}

        # Idempotency-Key para dedup a nivel HTTP
        idem_key = payload.get("idempotency_key", "")
        if idem_key:
            headers["Idempotency-Key"] = idem_key

        # Fallbacks: por si backend tambiÃ©n acepta header
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
            headers["X-API-Key"] = api_key

        if not tls_verify:
            try:
                import urllib3  # type: ignore
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass

        r = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=timeout,
            verify=tls_verify,
        )
        _save_payload_debug(payload, r.status_code, (r.text or "")[:1000])

        if 200 <= r.status_code < 300 or r.status_code == 409:
            print(f"[{_now()}] OK backend ({r.status_code})")
            return True

        snippet = (r.text or "")[:300]
        raise RuntimeError(f"Backend rechazÃ³: HTTP {r.status_code}. Respuesta: {snippet}")

    except requests.exceptions.SSLError as e:
        _save_payload_debug(payload, None, "", str(e))
        print(format_exception(step, e, {"url": url, "tls_verify": tls_verify, "hint": "TLS/certificados"}))
        return False
    except requests.exceptions.ConnectionError as e:
        _save_payload_debug(payload, None, "", str(e))
        print(format_exception(step, e, {"url": url, "hint": "DNS/ruta/firewall"}))
        return False
    except requests.exceptions.Timeout as e:
        _save_payload_debug(payload, None, "", str(e))
        print(format_exception(step, e, {"url": url, "timeout": timeout, "hint": "Backend lento/caÃ­do"}))
        return False
    except requests.exceptions.RequestException as e:
        _save_payload_debug(payload, None, "", str(e))
        print(format_exception(step, e, {"url": url, "hint": "Error HTTP genÃ©rico"}))
        return False
    except Exception as e:
        _save_payload_debug(payload, None, "", str(e))
        print(format_exception(step, e, {"mode": mode, "url": url}))
        return False
