"""Durable, transport-independent snapshot delivery scheduling.

Use a journal as a context manager for the entire collection/delivery cycle.
The sender receives the original persisted payload and key and must return True
only after the backend acknowledges it. Acknowledgment callbacks may be replayed
after a crash and must therefore be idempotent.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import json
import math
import os
import re
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping
from .fs import atomic_replace


@dataclass(frozen=True)
class DeliveryPolicy:
    mode: str = "change_or_backup"
    interval_seconds: float = 3600
    source: str | None = None
    backup_cycles: int = 6

    def __post_init__(self):
        if self.mode not in {"change_or_backup", "on_change", "periodic", "always"}:
            raise ValueError("Delivery mode must be change_or_backup, on_change, periodic, or always")
        if type(self.backup_cycles) is not int or self.backup_cycles < 1:
            raise ValueError("Delivery backup cycles must be a positive integer")
        try:
            interval = float(self.interval_seconds)
        except (TypeError, ValueError) as exc:
            raise ValueError("Delivery interval seconds must be a finite positive number") from exc
        if isinstance(self.interval_seconds, bool) or not math.isfinite(interval) or interval <= 0:
            raise ValueError("Delivery interval seconds must be a finite positive number")
        object.__setattr__(self, "interval_seconds", interval)


def resolve_delivery_policy(env: Mapping[str, str], integration: str) -> DeliveryPolicy:
    name = integration.lower().replace("-", "").replace("_", "")
    prefix = {"uptimekuma": "UPTIME", "openvas": "OPENVAS", "insightvm": "INSIGHTVM"}.get(name, integration.upper())
    legacy = [key for key in ("FORCE_SEND_EVERY_CYCLES", "SNAPSHOT_ALWAYS_SEND", f"{prefix}_FORCE_SEND_EVERY_CYCLES", f"{prefix}_SNAPSHOT_ALWAYS_SEND") if key in env]
    if legacy:
        raise ValueError(f"Legacy delivery settings {', '.join(legacy)} are unsupported; migrate to MAD_DELIVERY_MODE=change_or_backup and MAD_DELIVERY_BACKUP_CYCLES=6; remove obsolete per-integration overrides")
    mode_key = next((key for key in (f"{prefix}_DELIVERY_MODE", "MAD_DELIVERY_MODE") if env.get(key, "").strip()), None)
    interval_key = next((key for key in (f"{prefix}_DELIVERY_INTERVAL_SECONDS", "MAD_DELIVERY_INTERVAL_SECONDS") if env.get(key, "").strip()), None)
    mode = env[mode_key].strip().lower() if mode_key else "change_or_backup"
    cycles_key = next((key for key in (f"{prefix}_DELIVERY_BACKUP_CYCLES", "MAD_DELIVERY_BACKUP_CYCLES") if env.get(key, "").strip()), None)
    try:
        cycles = int(env[cycles_key]) if cycles_key else 6
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid delivery backup cycles in {cycles_key}") from exc
    try:
        interval = float(env[interval_key]) if interval_key else 3600
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid delivery interval in {interval_key}") from exc
    return DeliveryPolicy(mode, interval, mode_key or "default", cycles)


def _timestamp(value=None) -> float:
    if value is None:
        value = time.time()
    if isinstance(value, bool):
        raise ValueError("Timestamp must not be a boolean")
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamp must include an explicit timezone")
        value = value.timestamp()
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Timestamp must be finite")
    return number


class DeliveryJournal:
    def __init__(self, directory, integration, policy, baseline_signature=None, baseline_sent_at=None, max_pending=1000, delivery_confirmed_this_cycle=False):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", integration):
            raise ValueError("Invalid integration name")
        if isinstance(max_pending, bool) or int(max_pending) != max_pending or max_pending < 1:
            raise ValueError("max_pending must be a positive integer")
        self.directory = Path(directory)
        self.integration = integration
        self.policy = policy
        self.max_pending = max_pending
        self._acknowledged_in_cycle = delivery_confirmed_this_cycle
        self.path = self.directory / f"{integration}.json"
        self.lock_path = self.directory / f"{integration}.lock"
        self.state: dict[str, Any] = {}
        self._lock = None
        self._unusable = False
        self._baseline_signature = baseline_signature
        self._baseline_sent_at = baseline_sent_at

    def __enter__(self):
        if self._lock is not None:
            raise RuntimeError("Journal is already open")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        self._lock = os.fdopen(fd, "r+b")
        try:
            os.chmod(self.lock_path, 0o600)
            if os.name == "nt":
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    self._lock.write(b"\0")
                    self._lock.flush()
                self._lock.seek(0)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._lock.close()
            self._lock = None
            raise RuntimeError(f"Delivery journal is locked: {self.lock_path}") from exc
        try:
            self._unusable = False
            if self.path.exists():
                os.chmod(self.path, 0o600)
                try:
                    loaded = json.loads(self.path.read_text(encoding="utf-8"), parse_constant=self._invalid_constant)
                    self._validate(loaded)
                except (OSError, ValueError, TypeError, KeyError) as exc:
                    raise ValueError(f"Corrupt delivery journal: {self.path}") from exc
                self.state = loaded
            else:
                baseline = self._baseline_signature
                baseline_time = _timestamp(self._baseline_sent_at) if self._baseline_sent_at not in (None, "") else None
                if baseline_time is not None and baseline_time > _timestamp():
                    raise ValueError("Baseline delivery timestamp must not be in the future")
                initial = {
                    "schema_version": 1, "integration": self.integration,
                    "observed_signature": baseline,
                    "last_delivered_signature": baseline,
                    "last_delivered_at": baseline_time,
                    "last_delivered_generation": 0,
                    "next_generation": 1, "last_enqueued_at": baseline_time,
                    "unchanged_cycles": 0, "pending": [],
                }
                self._persist(initial)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        if self._lock is not None:
            try:
                if os.name == "nt":
                    import msvcrt
                    self._lock.seek(0)
                    msvcrt.locking(self._lock.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self._lock.fileno(), fcntl.LOCK_UN)
            finally:
                self._lock.close()
                self._lock = None

    def _require_open(self):
        if self._lock is None:
            raise RuntimeError("Use DeliveryJournal inside a context manager")
        if self._unusable:
            raise RuntimeError("Delivery journal durability is uncertain; close and reopen before retrying")

    @staticmethod
    def _invalid_constant(value):
        raise ValueError(f"Invalid JSON constant: {value}")

    def _validate(self, state):
        if not isinstance(state, dict) or type(state.get("schema_version")) is not int or state.get("schema_version") != 1 or state.get("integration") != self.integration:
            raise ValueError("Invalid journal schema")
        for key in ("observed_signature", "last_delivered_signature"):
            if key not in state or (state[key] is not None and not isinstance(state[key], str)):
                raise ValueError(f"Invalid {key}")
        for key in ("last_delivered_generation", "next_generation", "unchanged_cycles"):
            if type(state.get(key)) is not int or state[key] < (1 if key == "next_generation" else 0):
                raise ValueError(f"Invalid {key}")
        for key in ("last_delivered_at", "last_enqueued_at"):
            if key not in state or (state[key] is not None and (isinstance(state[key], bool) or not isinstance(state[key], (int, float)) or not math.isfinite(state[key]))):
                raise ValueError(f"Invalid {key}")
        if not isinstance(state.get("pending"), list):
            raise ValueError("Invalid pending queue")
        if len(state["pending"]) > self.max_pending:
            raise ValueError("Pending queue exceeds configured max_pending")
        previous = state["last_delivered_generation"]
        ids = set()
        keys = set()
        for event in state["pending"]:
            if not isinstance(event, dict) or any(key not in event for key in ("event_id", "key", "signature", "generation", "created_at", "payload", "context")):
                raise ValueError("Invalid pending event")
            if any(not isinstance(event[k], str) or not event[k] for k in ("event_id", "key")) or not isinstance(event["signature"], str):
                raise ValueError("Invalid event identity")
            if event["key"] in keys or event["key"] != self._event_key(event["event_id"]):
                raise ValueError("Invalid or duplicate event key")
            if type(event["generation"]) is not int or not previous < event["generation"] < state["next_generation"] or event["event_id"] in ids:
                raise ValueError("Invalid event generation")
            if isinstance(event["created_at"], bool) or not isinstance(event["created_at"], (int, float)) or not math.isfinite(event["created_at"]):
                raise ValueError("Invalid event timestamp")
            if not isinstance(event["payload"], dict) or event["payload"].get("idempotency_key") != event["key"]:
                raise ValueError("Invalid event payload")
            previous = event["generation"]
            ids.add(event["event_id"])
            keys.add(event["key"])
        if state["last_delivered_generation"] >= state["next_generation"]:
            raise ValueError("Invalid delivered generation")
        if state["last_delivered_generation"] > 0 and (state["last_delivered_signature"] is None or state["last_delivered_at"] is None):
            raise ValueError("Delivered generation requires acknowledgment metadata")
        if state["last_delivered_signature"] is None and state["last_delivered_at"] is not None:
            raise ValueError("Delivered timestamp requires an acknowledged signature")

    def _event_key(self, event_id):
        digest = hashlib.sha256(f"delivery-v2:{self.integration}:{event_id}".encode("utf-8")).hexdigest()
        return f"sha256:{digest}"

    def _sync_directory(self):
        if os.name != "nt":
            directory_fd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

    def _persist(self, candidate):
        self._require_open()
        self._validate(candidate)
        if self.state and (candidate["last_delivered_generation"] < self.state["last_delivered_generation"] or candidate["next_generation"] < self.state["next_generation"]):
            raise ValueError("Journal generations must not regress")
        encoded = json.dumps(candidate, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        fd, name = tempfile.mkstemp(prefix=f".{self.integration}.", suffix=".tmp", dir=self.directory)
        replaced = False
        try:
            with os.fdopen(fd, "wb") as output:
                os.chmod(name, 0o600)
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            atomic_replace(name, self.path)
            replaced = True
            self._sync_directory()
            self.state = candidate
        except BaseException:
            if replaced:
                self._unusable = True
            raise
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def decision(self, signature, now=None):
        self._require_open()
        self._validate(self.state)
        timestamp = _timestamp(now)
        if not isinstance(signature, str):
            raise ValueError("Snapshot signature must be a string")
        changed = signature != self.state["observed_signature"]
        cycles = 0 if changed else self.state["unchanged_cycles"] + 1
        if self.policy.mode == "change_or_backup" and (changed or self.state["pending"] or self._acknowledged_in_cycle):
            cycles = self.state["unchanged_cycles"]
        anchor = self.state["last_enqueued_at"]
        if self.policy.mode == "always":
            send, reason = True, "always_snapshot"
        elif self.policy.mode == "periodic":
            send = anchor is None or timestamp - anchor >= self.policy.interval_seconds
            reason = "first_snapshot" if anchor is None else ("periodic_due" if send else "interval_not_due")
        else:
            first = self.state["observed_signature"] is None
            backup = (self.policy.mode == "change_or_backup" and not self.state["pending"]
                      and not self._acknowledged_in_cycle and cycles >= self.policy.backup_cycles)
            send = first or changed or backup
            reason = "first_snapshot" if first else ("snapshot_changed" if changed else ("backup_cycle" if backup else "no_change"))
        return {"changed": changed, "should_send": send, "reason": reason,
                "snapshot_mode": self.policy.mode, "unchanged_cycles": cycles}

    def enqueue(self, signature, payload, context=None, now=None):
        timestamp = _timestamp(now)
        decision = self.decision(signature, timestamp)
        candidate = copy.deepcopy(self.state)
        candidate["observed_signature"] = signature
        candidate["unchanged_cycles"] = decision["unchanged_cycles"]
        if not decision["should_send"]:
            self._persist(candidate)
            return None
        if len(candidate["pending"]) >= self.max_pending:
            raise RuntimeError(f"Delivery journal backlog limit ({self.max_pending}) reached")
        if not isinstance(payload, dict):
            raise ValueError("Delivery payload must be a dictionary")
        event_id = str(uuid.uuid4())
        key = self._event_key(event_id)
        body = copy.deepcopy(payload)
        body["idempotency_key"] = key
        event = {"event_id": event_id, "key": key, "signature": signature,
                 "generation": candidate["next_generation"], "created_at": timestamp,
                 "payload": body, "context": copy.deepcopy(context)}
        candidate["next_generation"] += 1
        candidate["last_enqueued_at"] = timestamp
        candidate["pending"].append(event)
        self._persist(candidate)
        return copy.deepcopy(event)

    def commit_observation(self, signature, now=None):
        if self.decision(signature, now)["should_send"]:
            raise ValueError("Snapshot requires a durable event; call enqueue first")
        candidate = copy.deepcopy(self.state)
        candidate["observed_signature"] = signature
        candidate["unchanged_cycles"] = self.decision(signature, now)["unchanged_cycles"]
        self._persist(candidate)

    def drain(self, send, on_ack=None, limit=20, now=None):
        self._require_open()
        self._validate(self.state)
        if now is not None:
            now = _timestamp(now)
        count = 0
        for _ in range(max(0, int(limit))):
            if not self.state["pending"]:
                break
            event = copy.deepcopy(self.state["pending"][0])
            if send(copy.deepcopy(event["payload"]), event["key"]) is not True:
                break
            if on_ack is not None:
                on_ack(copy.deepcopy(event))
            self._acknowledge(event, now)
            count += 1
        return count

    def _acknowledge(self, event, now):
        candidate = copy.deepcopy(self.state)
        candidate["pending"].pop(0)
        candidate["last_delivered_signature"] = event["signature"]
        candidate["last_delivered_at"] = _timestamp(now)
        candidate["last_delivered_generation"] = event["generation"]
        candidate["unchanged_cycles"] = 0
        self._persist(candidate)
        self._acknowledged_in_cycle = True

    async def drain_async(self, send, on_ack=None, limit=20, now=None):
        """Async counterpart; accepts synchronous or awaitable sender/callback."""
        self._require_open()
        self._validate(self.state)
        if now is not None:
            now = _timestamp(now)
        count = 0
        for _ in range(max(0, int(limit))):
            if not self.state["pending"]:
                break
            event = copy.deepcopy(self.state["pending"][0])
            result = send(copy.deepcopy(event["payload"]), event["key"])
            if inspect.isawaitable(result):
                result = await result
            if result is not True:
                break
            if on_ack is not None:
                result = on_ack(copy.deepcopy(event))
                if inspect.isawaitable(result):
                    await result
            self._acknowledge(event, now)
            count += 1
        return count
