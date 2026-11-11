import unittest

from src.detection.rules import (
    detect_brute_force,
    detect_suspicious_login,
    detect_suspicious_request,
)


class TestDetectionRules(unittest.TestCase):

    def test_brute_force_detection(self):
        alert = {
            "alert_id": "SOC-TEST-001",
            "failed_attempts": 15,
            "successful_logins": 0,
            "event_type": "authentication",
        }

        result = detect_brute_force(alert)

        self.assertIsNotNone(result)
        self.assertEqual(
            result["detection"],
            "BRUTE_FORCE",
        )

    def test_low_failed_attempts_not_brute_force(self):
        alert = {
            "alert_id": "SOC-TEST-002",
            "failed_attempts": 3,
            "successful_logins": 0,
            "event_type": "authentication",
        }

        result = detect_brute_force(alert)

        self.assertIsNone(result)

    def test_suspicious_login_detection(self):
        alert = {
            "alert_id": "SOC-TEST-003",
            "failed_attempts": 5,
            "successful_logins": 1,
            "event_type": "authentication",
        }

        result = detect_suspicious_login(alert)

        self.assertIsNotNone(result)
        self.assertEqual(
            result["detection"],
            "SUSPICIOUS_LOGIN",
        )

    def test_failed_only_login_not_suspicious_login(self):
        alert = {
            "alert_id": "SOC-TEST-004",
            "failed_attempts": 5,
            "successful_logins": 0,
            "event_type": "authentication",
        }

        result = detect_suspicious_login(alert)

        self.assertIsNone(result)

    def test_suspicious_request_detection(self):
        alert = {
            "alert_id": "SOC-TEST-005",
            "failed_attempts": 0,
            "successful_logins": 0,
            "event_type": "suspicious_request",
        }

        result = detect_suspicious_request(alert)

        self.assertIsNotNone(result)
        self.assertEqual(
            result["detection"],
            "SUSPICIOUS_REQUEST",
        )

    def test_normal_request_not_detected(self):
        alert = {
            "alert_id": "SOC-TEST-006",
            "failed_attempts": 0,
            "successful_logins": 0,
            "event_type": "normal_request",
        }

        result = detect_suspicious_request(alert)

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()