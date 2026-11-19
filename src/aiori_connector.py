#!/usr/bin/env python3
"""Local-first AIORI telemetry adapter for PS-007.

The connector is deliberately independent from the monitor and dashboard.  It
can consume their existing JSONL events, normalize allowlisted fields, persist
validated payloads locally, and publish only when explicitly configured.
"""

from __future__ import annotations

import json
import os
import queue
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


_MAC_RE = re.compile(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}")
_MODES = {"local", "staging", "publish"}
_EVENT_TYPES = {
    "IPV6_SECURITY_INCIDENT",
    "IPV6_SLAAC_METRICS",
    "ZERO_MAC_AUDIT",
}
_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"}


class AIORIConfigurationError(ValueError):
    """Raised when publication configuration is incomplete or unsafe."""


class AIORIValidationError(ValueError):
    """Raised when a payload violates the local integration contract."""


class AIORITransportError(RuntimeError):
    """Raised when an upstream request cannot be completed."""


@dataclass(frozen=True)
class ConnectorConfig:
    mode: str = "local"
    endpoint: str = ""
    api_key: str = ""
    anchor_id: str = "AIORI-IN-TC042"
    tenant_id: str = "tc042"
    local_sink: Path = Path("aiori_outbox.jsonl")
    timeout_seconds: float = 3.0
    queue_limit: int = 1000
    max_retries: int = 3

    @classmethod
    def from_env(cls) -> "ConnectorConfig":
        mode = os.getenv("AIORI_MODE", "local").strip().lower()
        return cls(
            mode=mode,
            endpoint=os.getenv("AIORI_ENDPOINT", "").strip(),
            api_key=os.getenv("AIORI_API_KEY", ""),
            anchor_id=os.getenv("AIORI_ANCHOR_ID", "AIORI-IN-TC042").strip(),
            tenant_id=os.getenv("AIORI_TENANT_ID", "tc042").strip(),
            local_sink=Path(os.getenv("AIORI_LOCAL_SINK", "aiori_outbox.jsonl")),
            timeout_seconds=float(os.getenv("AIORI_CONNECT_TIMEOUT_SECONDS", "3")),
            queue_limit=int(os.getenv("AIORI_QUEUE_LIMIT", "1000")),
            max_retries=int(os.getenv("AIORI_MAX_RETRIES", "3")),
        )

    def validate(self) -> None:
        if self.mode not in _MODES:
            raise AIORIConfigurationError(f"Unsupported AIORI_MODE: {self.mode}")
        if not self.anchor_id or not self.tenant_id:
            raise AIORIConfigurationError("AIORI anchor and tenant IDs are required")
        if self.timeout_seconds <= 0 or self.queue_limit <= 0 or self.max_retries < 0:
            raise AIORIConfigurationError("AIORI numeric settings must be positive")
        if self.mode == "local":
            return
        if not self.endpoint or not self.api_key:
            raise AIORIConfigurationError(
                "AIORI_ENDPOINT and AIORI_API_KEY are required outside local mode"
            )
        if not self.endpoint.startswith("https://"):
            parsed_local = self.endpoint.startswith(
                ("http://127.0.0.1", "http://localhost", "http://[::1]")
            )
            if not parsed_local:
                raise AIORIConfigurationError(
                    "AIORI endpoint must use HTTPS outside localhost"
                )


def _contains_mac(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(_contains_mac(k) or _contains_mac(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_mac(item) for item in value)
    return bool(_MAC_RE.search(str(value)))


def _utc_iso(timestamp: Any = None) -> str:
    if isinstance(timestamp, str) and timestamp:
        return timestamp
    value = timestamp if isinstance(timestamp, (int, float)) else time.time()
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _privacy() -> dict[str, Any]:
    return {
        "mac_addresses_transmitted": 0,
        "zero_mac_policy_enforced": True,
    }


def normalize_event(
    event: Mapping[str, Any],
    *,
    anchor_id: str = "AIORI-IN-TC042",
    tenant_id: str = "tc042",
    event_id: str | None = None,
) -> dict[str, Any]:
    """Convert one PS-007 event into an allowlisted AIORI payload."""
    event_type = str(event.get("type", "")).lower()
    envelope: dict[str, Any] = {
        "schema_version": "aiori-imn-v1",
        "event_id": event_id or str(uuid.uuid4()),
        "observed_at": _utc_iso(event.get("ts") or event.get("timestamp")),
        "anchor": {
            "id": anchor_id,
            "project": "A3-PS007-TC042",
            "tenant_id": tenant_id,
            "subnet": "fd00:abcd::/64",
        },
        "privacy": _privacy(),
    }

    if event_type in {"alert", "quarantine"}:
        details = {
            "alert_type": event.get("alert_type", "UNKNOWN"),
            "severity": str(event.get("severity", "INFO")).upper(),
            "session_pseudonym": event.get("pseudonym"),
            "session_anchor": event.get("session_id"),
            "source_ip": event.get("src") or event.get("src_ip"),
            "target_ip": event.get("target") or event.get("target_ip"),
            "evidence": event.get("details") or event.get("reason"),
        }
        details = {key: value for key, value in details.items() if value is not None}
        envelope.update(
            event_type="IPV6_SECURITY_INCIDENT",
            incident=details,
        )
        if event_type == "quarantine":
            envelope["mitigation"] = {
                "action": "OPENFLOW_PORT_QUARANTINE",
                "switch": event.get("switch", "s1"),
                "port": event.get("port"),
            }
    elif event_type == "expiry":
        envelope.update(
            event_type="IPV6_SLAAC_METRICS",
            metrics={
                "active_iot_devices": None,
                "address_rotations": event.get("rotations"),
                "dad_bindings_accepted": None,
                "dad_bindings_rejected": None,
                "security_alerts": None,
                "quarantined_ports": None,
                "current_epoch_id": event.get("epoch_id"),
            },
        )
    elif event_type == "audit":
        envelope.update(
            event_type="ZERO_MAC_AUDIT",
            status="COMPLIANT",
            results={
                "zero_mac_leakage": True,
                "mac_addresses_transmitted": 0,
                "hardware_fingerprinting_disabled": True,
            },
        )
    else:
        raise AIORIValidationError(f"Unsupported PS-007 event type: {event_type or 'empty'}")

    validate_payload(envelope)
    return envelope


def validate_payload(payload: Mapping[str, Any], max_bytes: int = 64 * 1024) -> None:
    """Validate required fields and reject any MAC-shaped data."""
    required = ("schema_version", "event_id", "observed_at", "event_type", "anchor", "privacy")
    missing = [key for key in required if not payload.get(key)]
    if missing:
        raise AIORIValidationError(f"Missing required fields: {', '.join(missing)}")
    if payload["event_type"] not in _EVENT_TYPES:
        raise AIORIValidationError(f"Unsupported event type: {payload['event_type']}")
    if not isinstance(payload["anchor"], Mapping) or not payload["anchor"].get("id"):
        raise AIORIValidationError("anchor.id is required")
    privacy = payload["privacy"]
    if (
        not isinstance(privacy, Mapping)
        or privacy.get("mac_addresses_transmitted") != 0
        or privacy.get("zero_mac_policy_enforced") is not True
    ):
        raise AIORIValidationError("zero-MAC privacy attestation is invalid")
    if payload.get("incident", {}).get("severity") not in _SEVERITIES:
        if payload["event_type"] == "IPV6_SECURITY_INCIDENT":
            raise AIORIValidationError("incident.severity is invalid")
    if _contains_mac(payload):
        raise AIORIValidationError("MAC-shaped data is forbidden in AIORI payloads")
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > max_bytes:
        raise AIORIValidationError("AIORI payload exceeds maximum size")


class AIORIConnector:
    """Bounded asynchronous local sink and opt-in upstream publisher."""

    def __init__(self, config: ConnectorConfig | None = None):
        self.config = config or ConnectorConfig.from_env()
        self.config.validate()
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(
            maxsize=self.config.queue_limit
        )
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._dispatch_loop, daemon=True)
        self.dispatched = 0
        self.failed = 0
        self.dropped = 0
        self.last_error: str | None = None
        self._worker.start()

    def enqueue(self, payload: Mapping[str, Any]) -> None:
        validate_payload(payload)
        try:
            self._queue.put_nowait(dict(payload))
        except queue.Full as exc:
            self.dropped += 1
            self.last_error = "AIORI queue is full"
            raise AIORITransportError(self.last_error) from exc

    def enqueue_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        payload = normalize_event(
            event,
            anchor_id=self.config.anchor_id,
            tenant_id=self.config.tenant_id,
        )
        self.enqueue(payload)
        return payload

    def wait(self, timeout: float | None = None) -> bool:
        """Wait until all currently queued payloads are processed."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while self._queue.unfinished_tasks:
            if deadline is not None and time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True

    def close(self, timeout: float = 5.0) -> None:
        self.wait(timeout)
        self._stop.set()
        self._queue.put(None)
        self._worker.join(timeout=timeout)

    def status(self) -> dict[str, Any]:
        return {
            "mode": self.config.mode,
            "anchor_id": self.config.anchor_id,
            "queued": self._queue.qsize(),
            "dispatched": self.dispatched,
            "failed": self.failed,
            "dropped": self.dropped,
            "last_error": self.last_error,
        }

    def _dispatch_loop(self) -> None:
        while not self._stop.is_set() or not self._queue.empty():
            try:
                payload = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if payload is None:
                self._queue.task_done()
                continue
            try:
                if self.config.mode == "local":
                    self._write_local(payload)
                else:
                    self._publish(payload)
                self.dispatched += 1
            except (OSError, urllib.error.URLError, AIORITransportError) as exc:
                self.failed += 1
                self.last_error = str(exc)
            finally:
                self._queue.task_done()

    def _write_local(self, payload: Mapping[str, Any]) -> None:
        self.config.local_sink.parent.mkdir(parents=True, exist_ok=True)
        with self.config.local_sink.open("a", encoding="utf-8") as output:
            output.write(json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n")

    def _publish(self, payload: Mapping[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        request = urllib.request.Request(
            self.config.endpoint,
            data=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.api_key}",
                "User-Agent": "PS-007-AIORI-IMN/1",
            },
            method="POST",
        )
        last_error: Exception | None = None
        for attempt in range(self.config.max_retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                    if response.status not in {200, 201, 202}:
                        raise AIORITransportError(f"AIORI HTTP {response.status}")
                    return
            except urllib.error.HTTPError as exc:
                if 400 <= exc.code < 500 and exc.code != 429:
                    raise AIORITransportError(f"AIORI HTTP {exc.code}") from exc
                last_error = exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = exc
            if attempt < self.config.max_retries:
                time.sleep(min(2.0 ** attempt, 8.0))
        raise AIORITransportError(f"AIORI dispatch failed: {last_error}")


def read_jsonl(path: str | os.PathLike[str], connector: AIORIConnector) -> int:
    """Normalize and enqueue valid JSONL events; return the accepted count."""
    accepted = 0
    with Path(path).open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                connector.enqueue_event(event)
                accepted += 1
            except (json.JSONDecodeError, AIORIValidationError, AIORITransportError) as exc:
                connector.last_error = f"line {line_number}: {exc}"
    return accepted


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Normalize PS-007 events for AIORI")
    parser.add_argument("--events", default="events.jsonl", help="PS-007 JSONL event file")
    parser.add_argument("--sink", default=None, help="Local output JSONL path")
    args = parser.parse_args()
    config = ConnectorConfig.from_env()
    if args.sink:
        config = ConnectorConfig(**{**config.__dict__, "local_sink": Path(args.sink)})
    connector = AIORIConnector(config)
    try:
        print(f"Accepted {read_jsonl(args.events, connector)} events")
        connector.wait()
        print(json.dumps(connector.status(), indent=2))
    finally:
        connector.close()
