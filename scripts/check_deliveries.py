#!/usr/bin/env python3
"""Verify fresh delivery evidence without running collectors or uploading data."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from io import StringIO
import json
from pathlib import Path
import re
from typing import Mapping

from dotenv import dotenv_values
from dotenv.parser import parse_stream

from check_integrations import INTEGRATIONS, resolve_paths


def timestamp(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.utcoffset() is None:
        raise ValueError("timezone required")
    return result


def verify_deliveries(repo: Path, cfg: Mapping[str, str], since: datetime,
                      now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    paths = resolve_paths(repo, cfg)
    evidence = {name: paths[name]["delivery_meta"].resolve() for name in INTEGRATIONS}
    results = []
    for name in INTEGRATIONS:
        row = {"integration": name, "status": "FAIL"}
        if sum(path == evidence[name] for path in evidence.values()) > 1:
            row["detail"] = "shared_delivery_metadata_path"
            results.append(row)
            continue
        try:
            meta = json.loads(evidence[name].read_text(encoding="utf-8"))
            if not isinstance(meta, dict):
                raise ValueError("invalid metadata")
            saved = timestamp(meta["saved_at_utc"])
            if saved < since:
                row["detail"] = "no_delivery_evidence_since_validation_started"
            elif saved > now + timedelta(minutes=5):
                row["detail"] = "delivery_timestamp_in_future"
            else:
                if name in {"nessus", "uptimekuma", "zabbix"}:
                    prefix = {"nessus": "NESSUS", "uptimekuma": "UPTIME", "zabbix": "ZABBIX"}[name]
                    mode = cfg.get(prefix + "_OUTPUT_MODE") or cfg.get("OUTPUT_MODE", "all")
                    success = (meta.get("sent") is True and meta.get("queued") is not True
                               and mode in {"all", "webhook"})
                elif name == "insightvm":
                    delivery = meta.get("delivery_result", {})
                    success = (isinstance(delivery, dict) and delivery.get("sent") is True
                               and delivery.get("queued") is not True)
                elif name == "openvas":
                    mode = cfg.get("OPENVAS_OUTPUT_MODE") or cfg.get("OUTPUT_MODE", "http")
                    success = (meta.get("delivery_success") is True and mode == "http"
                               and meta.get("output_mode") == "http" and meta.get("collector") == "gmp")
                else:
                    dry_run = cfg.get("DRY_RUN", "false").lower() in {"1", "true", "yes", "on"}
                    success = (meta.get("delivery_success") is True and meta.get("status_code") == 200
                               and not dry_run)
                if success:
                    row.update(status="PASS", detail="fresh_delivery_or_deduplication_recorded", saved_at=saved.isoformat())
                    scan_id = str(meta.get("scan_id", ""))
                    if re.fullmatch(r"[A-Za-z0-9._:-]{1,180}", scan_id):
                        row["scan_id"] = scan_id
                else:
                    row["detail"] = "latest_record_does_not_confirm_delivery"
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            row["detail"] = "delivery_metadata_missing_unreadable_or_invalid"
        results.append(row)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    repo = Path(__file__).resolve().parents[1]
    parser.add_argument("--env", type=Path, default=repo / ".env")
    parser.add_argument("--since", required=True, help="Validation start time, ISO 8601 with timezone")
    args = parser.parse_args()
    try:
        since = timestamp(args.since)
        if since > datetime.now(timezone.utc):
            raise ValueError("validation start in future")
        text = args.env.read_text(encoding="utf-8-sig")
        if any(binding.error for binding in parse_stream(StringIO(text))):
            raise ValueError("invalid env")
        cfg = {key: value for key, value in dotenv_values(stream=StringIO(text)).items() if value is not None}
    except (OSError, ValueError, TypeError):
        print("FAIL configuration_or_since_invalid; no credentials or metadata contents printed")
        return 2
    results = verify_deliveries(repo, cfg, since)
    for result in results:
        print(json.dumps(result, ensure_ascii=True))
    print("Read-only evidence check. Receipts do not distinguish a fresh S3 PUT from HTTP 409 deduplication.")
    print("AWS processing must be confirmed separately using scan_id.")
    return 0 if all(result["status"] == "PASS" for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
