#!/usr/bin/env python3
"""Live PS-007 to AIORI bridge.

Run this beside ``monitor.py``.  It follows the monitor's JSONL event file and
processes only events appended after startup, so the monitor remains unchanged
and the local security path is never coupled to an upstream API.
"""

from __future__ import annotations

import argparse
import json
import signal
import time
from pathlib import Path
from threading import Event

from aiori_connector import (
    AIORIConnector,
    AIORITransportError,
    ConnectorConfig,
)


class EventTailer:
    """Follow a UTF-8 JSONL file, tolerating rotation and partial writes."""

    def __init__(self, path: Path, poll_seconds: float = 0.25):
        self.path = path
        self.poll_seconds = poll_seconds
        self._offset = path.stat().st_size if path.exists() else 0
        self._partial = ""

    def follow(self, stop: Event):
        while not stop.is_set():
            if not self.path.exists():
                stop.wait(self.poll_seconds)
                continue

            try:
                size = self.path.stat().st_size
                if size < self._offset:
                    self._offset = 0
                    self._partial = ""
                with self.path.open("r", encoding="utf-8") as source:
                    source.seek(self._offset)
                    chunk = source.read()
                    self._offset = source.tell()
            except OSError:
                stop.wait(self.poll_seconds)
                continue

            if chunk:
                self._partial += chunk
                lines = self._partial.splitlines(keepends=True)
                self._partial = ""
                for line in lines:
                    if not line.endswith(("\n", "\r")):
                        self._partial = line
                        continue
                    yield line
            stop.wait(self.poll_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Follow monitor.py events and deliver AIORI telemetry live"
    )
    parser.add_argument("--events", type=Path, default=Path("events.jsonl"))
    parser.add_argument("--sink", type=Path, help="Override local AIORI outbox path")
    parser.add_argument("--poll", type=float, default=0.25)
    args = parser.parse_args()

    config = ConnectorConfig.from_env()
    if args.sink:
        config = ConnectorConfig(
            mode=config.mode,
            endpoint=config.endpoint,
            api_key=config.api_key,
            anchor_id=config.anchor_id,
            tenant_id=config.tenant_id,
            local_sink=args.sink,
            timeout_seconds=config.timeout_seconds,
            queue_limit=config.queue_limit,
            max_retries=config.max_retries,
        )

    stop = Event()
    signal.signal(signal.SIGINT, lambda _signum, _frame: stop.set())
    signal.signal(signal.SIGTERM, lambda _signum, _frame: stop.set())
    print(
        f"Following {args.events} for live AIORI telemetry "
        f"(mode={config.mode}, sink={config.local_sink})",
        flush=True,
    )
    accepted = run_live(args.events, config, stop, args.poll)
    print(f"Accepted {accepted} live events", flush=True)


def run_live(
    events_path: Path,
    config: ConnectorConfig,
    stop: Event,
    poll_seconds: float = 0.25,
) -> int:
    """Run the bridge; split out for deterministic integration testing."""
    connector = AIORIConnector(config)
    accepted = 0
    tailer = EventTailer(events_path, poll_seconds)
    try:
        for line in tailer.follow(stop):
            if not line.strip():
                continue
            try:
                payload = connector.enqueue_event(json.loads(line))
                accepted += 1
                print(
                    f"[AIORI] queued {payload['event_type']} "
                    f"event_id={payload['event_id']}",
                    flush=True,
                )
            except (json.JSONDecodeError, ValueError, AIORITransportError) as exc:
                connector.last_error = f"live event rejected: {exc}"
                print(f"[AIORI] rejected event: {exc}", flush=True)
        connector.wait(timeout=config.timeout_seconds)
        status = connector.status()
        if status["failed"] or status["dropped"]:
            print(f"[AIORI] delivery status: {status}", flush=True)
        return accepted
    finally:
        connector.close()


if __name__ == "__main__":
    main()
