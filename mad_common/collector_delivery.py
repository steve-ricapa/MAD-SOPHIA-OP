"""One durable delivery workflow for synchronous snapshot collectors."""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .delivery import DeliveryJournal, DeliveryPolicy, resolve_delivery_policy
from .artifacts import archive_bundle, maintain_history
from .fs import atomic_replace
from .logs import append_jsonl


def private_json(path: Path, value: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".mad-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        atomic_replace(temporary, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def run_snapshot_cycle(*, integration, cfg, state, collect, signature, prepare, send, persist=None):
    """Retry durable events first; acknowledge state only after a confirmed delivery.

    prepare(data, effective_domain_state, decision) returns (payload, domain_state_patch).
    send(payload, key) returns the existing transport's result dictionary.
    """
    policy = getattr(cfg, "delivery_policy", None) or resolve_delivery_policy({}, integration)
    maintain_history(Path(cfg.debug_report_path).parent, integration)
    queue = Path(cfg.queue_dir)
    if queue.exists() and any(queue.glob("*.json")):
        raise RuntimeError("Legacy pending payloads require the documented migration before delivery-v2")
    result = dict(state)
    network_mode = getattr(cfg, "output_mode", "webhook") in {"webhook", "all"}
    if not network_mode:
        data = collect()
        decision = {"reason": "dry_run", "snapshot_mode": policy.mode, "changed": True}
        payload, _ = prepare(data, result, decision)
        private_json(Path(cfg.debug_report_path), payload)
        result["last_check_result"] = "dry_run"
        return result

    valid_baseline = state.get("has_sent_once") is True and state.get("last_send_result") in {"sent", "skipped_no_change", "interval_not_due"}
    journal_dir = queue / "delivery-v2"
    with DeliveryJournal(journal_dir, integration, policy,
                         baseline_signature=state.get("snapshot_signature") if valid_baseline else None,
                         baseline_sent_at=state.get("last_sent_at") if valid_baseline else None) as journal:
        print(f"[POLICY] integration={integration} mode={policy.mode} interval_seconds={policy.interval_seconds}")
        attempted = set()

        def acknowledge(event):
            result.update((event.get("context") or {}).get("state_patch", {}))
            result.update(snapshot_signature=event["signature"], has_sent_once=True,
                          last_idempotency_key=event["key"], last_send_result="sent",
                          last_sent_at=datetime.now(timezone.utc).isoformat(),
                          delivered_generation=event["generation"], unchanged_cycles=0)
            if persist is not None:
                persist(result)

        def transmit(payload, key):
            if key in attempted:
                return False
            attempted.add(key)
            delivery = {"sent": False, "queued": False, "flushed_from_queue": 0}
            try:
                private_json(Path(cfg.last_payload_path), payload)
                private_json(Path(cfg.debug_report_path), payload)
                delivery = send(payload, key)
                return delivery.get("sent") is True and delivery.get("queued") is not True
            finally:
                receipt = {
                    "schema_version": 2, "integration": integration,
                    "saved_at_utc": datetime.now(timezone.utc).isoformat(),
                    "scan_id": payload.get("scan_id"), "idempotency_key": key,
                    "mode": cfg.output_mode, "sent": delivery.get("sent") is True,
                    "queued": delivery.get("queued") is True, "flushed_from_queue": 0,
                    "delivery_policy": policy.mode,
                }
                private_json(Path(cfg.delivery_meta_path), receipt)
                append_jsonl(Path(cfg.delivery_meta_path).parent / "delivery_receipts.jsonl", receipt)

        # A transport failure must not prevent observing a new transition. The pending
        # payload stays durable; the cycle still exits nonzero after observation.
        pending_error = None
        try:
            journal.drain(transmit, on_ack=acknowledge, limit=cfg.queue_flush_max)
        except Exception as exc:
            pending_error = exc
        try:
            data = collect()
        except Exception as exc:
            private_json(Path(cfg.debug_report_path).parent / "last_check.json", {
                "integration": integration, "checked_at": datetime.now(timezone.utc).isoformat(),
                "policy": policy.mode, "decision": "collection_failed", "error_type": type(exc).__name__,
                "pending_count": len(journal.state["pending"]),
            })
            raise
        current = signature(data)
        decision = journal.decision(current)
        print(f"[DELIVERY] integration={integration} reason={decision['reason']} unchanged={decision['unchanged_cycles']}/{policy.backup_cycles}")
        effective_state = dict(result)
        for event in journal.state["pending"]:
            effective_state.update((event.get("context") or {}).get("state_patch", {}))
        if decision["should_send"]:
            payload, patch = prepare(data, effective_state, decision)
            event = journal.enqueue(current, payload, context={"state_patch": patch})
            archive_bundle(Path(cfg.debug_report_path).parent, integration,
                           {"raw.json": data, "payload.json": event["payload"]})
        else:
            # enqueue's no-send branch durably records a successful observation.
            journal.enqueue(current, {})
        if pending_error is None:
            journal.drain(transmit, on_ack=acknowledge, limit=cfg.queue_flush_max)
        result["last_observed_signature"] = current
        result["last_check_at"] = datetime.now(timezone.utc).isoformat()
        private_json(Path(cfg.debug_report_path).parent / "last_check.json", {
            "integration": integration, "checked_at": result["last_check_at"],
            "policy": policy.mode, "decision": decision["reason"],
            "unchanged_cycles": journal.state["unchanged_cycles"], "backup_cycles": policy.backup_cycles,
            "pending_count": len(journal.state["pending"]),
        })
        if journal.state["pending"]:
            if pending_error is not None:
                raise RuntimeError("Delivery remains pending; durable event retained") from pending_error
            raise RuntimeError("Delivery remains pending; durable event retained")
        if not decision["should_send"]:
            result["last_send_result"] = decision["reason"]
            result["unchanged_cycles"] = decision.get("unchanged_cycles", 0)
            print(f"[DELIVERY] integration={integration} omitted reason={decision['reason']}")
        if persist is not None:
            persist(result)
        return result
