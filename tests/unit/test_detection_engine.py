import unittest

from src.detection.engine import (
    detect_alert,
    detect_alerts,
)


class TestDetectionEngine(unittest.TestCase):

    def test_alert_can_trigger_multiple_rules(self):
        alert = {
            "alert_id": "SOC-001",
            "failed_attempts": 15,
            "successful_logins": 1,
            "event_type": "authentication",
        }

        results = detect_alert(alert)

        detections = {
            result["detection"]
            for result in results
        }

        self.assertIn("BRUTE_FORCE", detections)
        self.assertIn("SUSPICIOUS_LOGIN", detections)

    def test_normal_alert_has_no_detections(self):
        alert = {
            "alert_id": "SOC-002",
            "failed_attempts": 0,
            "successful_logins": 1,
            "event_type": "authentication",
        }

        results = detect_alert(alert)

        self.assertEqual(results, [])

    def test_multiple_alerts(self):
        alerts = [
            {
                "alert_id": "SOC-001",
                "failed_attempts": 15,
                "successful_logins": 1,
                "event_type": "authentication",
            },
            {
                "alert_id": "SOC-002",
                "failed_attempts": 0,
                "successful_logins": 1,
                "event_type": "authentication",
            },
        ]

        results = detect_alerts(alerts)

        self.assertEqual(len(results), 2)
        self.assertGreater(len(results["SOC-001"]), 0)
        self.assertEqual(results["SOC-002"], [])


if __name__ == "__main__":
    unittest.main()