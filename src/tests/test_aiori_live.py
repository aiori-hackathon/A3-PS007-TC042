import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from aiori_connector import ConnectorConfig
from aiori_live import run_live


class TestAIORILive(unittest.TestCase):
    def test_live_events_are_forwarded_after_append(self):
        with tempfile.TemporaryDirectory() as directory:
            events = Path(directory) / "events.jsonl"
            sink = Path(directory) / "aiori.jsonl"
            events.write_text("", encoding="utf-8")
            stop = threading.Event()
            result = {}

            def bridge():
                result["accepted"] = run_live(
                    events,
                    ConnectorConfig(mode="local", local_sink=sink),
                    stop,
                    poll_seconds=0.01,
                )

            worker = threading.Thread(target=bridge)
            worker.start()
            time.sleep(0.03)
            with events.open("a", encoding="utf-8") as output:
                output.write(
                    json.dumps(
                        {
                            "type": "alert",
                            "alert_type": "NDP_ABUSE",
                            "severity": "high",
                        }
                    )
                    + "\n"
                )
            deadline = time.time() + 2
            while not sink.exists() and time.time() < deadline:
                time.sleep(0.01)
            stop.set()
            worker.join(timeout=2)

            self.assertFalse(worker.is_alive())
            self.assertEqual(result["accepted"], 1)
            payload = json.loads(sink.read_text(encoding="utf-8"))
            self.assertEqual(payload["event_type"], "IPV6_SECURITY_INCIDENT")

    def test_existing_history_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            events = Path(directory) / "events.jsonl"
            sink = Path(directory) / "aiori.jsonl"
            events.write_text(
                json.dumps(
                    {
                        "type": "alert",
                        "alert_type": "OLD",
                        "severity": "info",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            stop = threading.Event()
            result = {}

            def bridge():
                result["accepted"] = run_live(
                    events,
                    ConnectorConfig(mode="local", local_sink=sink),
                    stop,
                    poll_seconds=0.01,
                )

            worker = threading.Thread(target=bridge)
            worker.start()
            time.sleep(0.05)
            self.assertFalse(sink.exists())
            stop.set()
            worker.join(timeout=2)
            self.assertEqual(result["accepted"], 0)

    def test_partial_json_line_is_processed_after_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            events = Path(directory) / "events.jsonl"
            sink = Path(directory) / "aiori.jsonl"
            events.write_text("", encoding="utf-8")
            stop = threading.Event()
            result = {}

            def bridge():
                result["accepted"] = run_live(
                    events,
                    ConnectorConfig(mode="local", local_sink=sink),
                    stop,
                    poll_seconds=0.01,
                )

            worker = threading.Thread(target=bridge)
            worker.start()
            time.sleep(0.03)
            event = json.dumps(
                {"type": "alert", "alert_type": "PARTIAL", "severity": "info"}
            )
            with events.open("a", encoding="utf-8") as output:
                output.write(event)
                output.flush()
                time.sleep(0.03)
                output.write("\n")
            deadline = time.time() + 2
            while not sink.exists() and time.time() < deadline:
                time.sleep(0.01)
            stop.set()
            worker.join(timeout=2)

            self.assertFalse(worker.is_alive())
            self.assertEqual(result["accepted"], 1)


if __name__ == "__main__":
    unittest.main()
