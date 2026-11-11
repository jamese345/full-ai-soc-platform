import unittest

from src.ingestion.alert_loader import load_alerts
from src.ingestion.normalizer import normalize_alert


class TestNormalizer(unittest.TestCase):

    def setUp(self):
        self.alert = load_alerts(
            "data/alerts/sample_alerts.json"
        )[0]

    def test_normalize_alert_id(self):
        normalized = normalize_alert(self.alert)

        self.assertEqual(
            normalized["alert_id"],
            "SOC-0001"
        )

    def test_normalize_severity(self):
        alert = self.alert.copy()
        alert["severity"] = "high"

        normalized = normalize_alert(alert)

        self.assertEqual(
            normalized["severity"],
            "HIGH"
        )

    def test_normalize_status(self):
        alert = self.alert.copy()
        alert["status"] = "new"

        normalized = normalize_alert(alert)

        self.assertEqual(
            normalized["status"],
            "NEW"
        )

    def test_numeric_fields(self):
        normalized = normalize_alert(self.alert)

        self.assertIsInstance(
            normalized["failed_attempts"],
            int
        )

        self.assertIsInstance(
            normalized["successful_logins"],
            int
        )

    def test_timestamp_normalization(self):
        normalized = normalize_alert(self.alert)

        self.assertIn(
            "+00:00",
            normalized["timestamp"]
        )


if __name__ == "__main__":
    unittest.main()