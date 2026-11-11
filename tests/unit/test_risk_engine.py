import unittest

from src.triage.risk_engine import (
    calculate_risk_score,
    classify_risk,
    assign_priority,
    determine_confidence,
    recommend_action,
    assess_risk,
)


class TestRiskEngine(unittest.TestCase):

    def setUp(self):
        self.high_risk_alert = {
            "alert_id": "SOC-0001",
            "severity": "HIGH",
            "failed_attempts": 18,
            "successful_logins": 1,
        }

        self.detections = [
            {
                "detection": "BRUTE_FORCE",
            },
            {
                "detection": "SUSPICIOUS_LOGIN",
            },
        ]

        self.anomaly = {
            "is_anomaly": True,
            "anomaly_score": -0.10,
            "classification": "ANOMALY",
        }

    def test_high_risk_score(self):
        score = calculate_risk_score(
            self.high_risk_alert,
            self.detections,
            self.anomaly,
        )

        self.assertEqual(score, 100)

    def test_anomaly_increases_risk(self):
        moderate_alert = {
            "alert_id": "SOC-TEST-001",
            "severity": "MEDIUM",
            "failed_attempts": 2,
            "successful_logins": 0,
        }

        detections = [
            {
                "detection": "SUSPICIOUS_REQUEST",
            }
        ]

        normal_anomaly = {
            "is_anomaly": False,
            "anomaly_score": 0.10,
            "classification": "NORMAL",
        }

        anomalous_result = {
            "is_anomaly": True,
            "anomaly_score": -0.10,
            "classification": "ANOMALY",
        }

        anomaly_score = calculate_risk_score(
            moderate_alert,
            detections,
            anomalous_result,
        )

        normal_score = calculate_risk_score(
            moderate_alert,
            detections,
            normal_anomaly,
        )

        self.assertGreater(
            anomaly_score,
            normal_score,
        )
    def test_risk_classification(self):
        self.assertEqual(
            classify_risk(90),
            "CRITICAL",
        )

        self.assertEqual(
            classify_risk(70),
            "HIGH",
        )

        self.assertEqual(
            classify_risk(40),
            "MEDIUM",
        )

        self.assertEqual(
            classify_risk(10),
            "LOW",
        )

    def test_priority_assignment(self):
        self.assertEqual(
            assign_priority("CRITICAL"),
            "P1",
        )

        self.assertEqual(
            assign_priority("HIGH"),
            "P2",
        )

        self.assertEqual(
            assign_priority("MEDIUM"),
            "P3",
        )

        self.assertEqual(
            assign_priority("LOW"),
            "P4",
        )

    def test_confidence(self):
        confidence = determine_confidence(
            self.detections,
            self.anomaly,
        )

        self.assertEqual(
            confidence,
            "VERY_HIGH",
        )

    def test_recommended_actions(self):
        self.assertEqual(
            recommend_action("CRITICAL"),
            "ESCALATE",
        )

        self.assertEqual(
            recommend_action("HIGH"),
            "INVESTIGATE",
        )

        self.assertEqual(
            recommend_action("MEDIUM"),
            "MONITOR",
        )

        self.assertEqual(
            recommend_action("LOW"),
            "CLOSE",
        )

    def test_complete_risk_assessment(self):
        result = assess_risk(
            self.high_risk_alert,
            self.detections,
            self.anomaly,
        )

        self.assertEqual(
            result["alert_id"],
            "SOC-0001",
        )

        self.assertEqual(
            result["risk_score"],
            100,
        )

        self.assertEqual(
            result["risk_level"],
            "CRITICAL",
        )

        self.assertEqual(
            result["priority"],
            "P1",
        )

        self.assertEqual(
            result["confidence"],
            "VERY_HIGH",
        )

        self.assertEqual(
            result["recommended_action"],
            "ESCALATE",
        )


if __name__ == "__main__":
    unittest.main()