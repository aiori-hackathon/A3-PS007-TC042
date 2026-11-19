#!/usr/bin/env python3
"""Offline AIORI ingestion receiver for demonstrations and integration tests."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from aiori_connector import validate_payload


class AIORIRequestHandler(BaseHTTPRequestHandler):
    output_path: Path | None = None

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            validate_payload(payload)
        except (ValueError, UnicodeDecodeError) as exc:
            self.send_error(400, f"invalid AIORI payload: {exc}")
            return

        if self.output_path:
            with self.output_path.open("a", encoding="utf-8") as output:
                output.write(json.dumps(payload, sort_keys=True) + "\n")

        response = json.dumps(
            {"status": "INGESTED", "event_id": payload["event_id"]}
        ).encode("utf-8")
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str, port: int, output: Path | None) -> None:
    AIORIRequestHandler.output_path = output
    server = ThreadingHTTPServer((host, port), AIORIRequestHandler)
    print(f"AIORI local receiver listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the local AIORI receiver")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--output", type=Path, default=Path("aiori_received.jsonl"))
    options = parser.parse_args()
    serve(options.host, options.port, options.output)
