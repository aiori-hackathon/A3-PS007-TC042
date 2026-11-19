import json
import tempfile
import unittest
from pathlib import Path

from aiori_connector import (
    AIORIConfigurationError,
    AIORIValidationError,
    AIORIConnector,
    ConnectorConfig,
    normalize_event,
    validate_payload,
)


class TestAIORIIntegration(unittest.TestCase):
    def test_alert_is_normalized_without_mac_data(self):
        payload = normalize_event(
            {
                "type": "alert",
                "ts": 1795062600,
                "alert_type": "NDP_RATE_ABUSE_HYSTERESIS",
                "severity": "high",
                "pseudonym": "A1B2C3D4",
                "session_id": "SES-PORT08",
                "src": "fd00:abcd::cafe",
            }
        )
        self.assertEqual(payload["event_type"], "IPV6_SECURITY_INCIDENT")
        self.assertEqual(payload["privacy"]["mac_addresses_transmitted"], 0)
        validate_payload(payload)

    def test_mac_data_is_rejected(self):
        with self.assertRaises(AIORIValidationError):
            normalize_event(
                {
                    "type": "alert",
                    "alert_type": "TEST",
                    "severity": "INFO",
                    "details": "source aa:bb:cc:dd:ee:ff",
                }
            )

    def test_non_local_mode_requires_credentials_and_https(self):
        with self.assertRaises(AIORIConfigurationError):
            ConnectorConfig(mode="publish").validate()
        with self.assertRaises(AIORIConfigurationError):
            ConnectorConfig(
                mode="publish",
                endpoint="http://example.test/ingest",
                api_key="secret",
            ).validate()

    def test_local_connector_writes_validated_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            sink = Path(directory) / "outbox.jsonl"
            connector = AIORIConnector(
                ConnectorConfig(mode="local", local_sink=sink, queue_limit=2)
            )
            try:
                connector.enqueue_event(
                    {"type": "alert", "alert_type": "ROGUE_RA", "severity": "critical"}
                )
                self.assertTrue(connector.wait(2))
                self.assertEqual(connector.status()["dispatched"], 1)
            finally:
                connector.close()
            record = json.loads(sink.read_text(encoding="utf-8"))
            self.assertEqual(record["event_type"], "IPV6_SECURITY_INCIDENT")


if __name__ == "__main__":
    unittest.main()
