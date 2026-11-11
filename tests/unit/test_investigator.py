import unittest

from src.investigation.investigator import (
    build_investigation,
)


class TestInvestigator(unittest.TestCase):

    def setUp(self):
        self.alert = {
            "alert_id": "SOC-0001",
        }

        self.detections = [
            {
                "detection": "BRUTE_FORCE",
                "severity": "HIGH",
                "confidence": "HIGH",
                "evidence": {
                    "failed_attempts": 18,
                },
            }
        ]

        self.anomaly = {
            "is_anomaly": True,
            "anomaly_score": -0.1078,
            "classification": "ANOMALY",
        }

        self.risk = {
            "risk_level": "CRITICAL",
            "priority": "P1",
            "confidence": "VERY_HIGH",
            "recommended_action": "ESCALATE",
        }

        self.iocs = {
            "ips": ["192.168.1.50"],
            "domains": [],
            "urls": [],
            "hashes": [],
        }

        self.enriched_iocs = {
            "ips": [
                {
                    "indicator": "192.168.1.50",
                    "classification": "PRIVATE",
                    "reputation": "INTERNAL",
                }
            ],
            "domains": [],
            "urls": [],
            "hashes": [],
        }

        self.mitre = [
            {
                "technique_id": "T1110",
                "name": "Brute Force",
                "tactics": ["credential-access"],
            }
        ]

    def test_investigation_contains_required_fields(self):
        result = build_investigation(
            self.alert,
            self.detections,
            self.anomaly,
            self.risk,
            self.iocs,
            self.enriched_iocs,
            self.mitre,
        )

        self.assertIn(
            "alert_id",
            result,
        )

        self.assertIn(
            "summary",
            result,
        )

        self.assertIn(
            "findings",
            result,
        )

        self.assertIn(
            "evidence",
            result,
        )

        self.assertIn(
            "recommended_action",
            result,
        )

    def test_critical_alert_is_identified(self):
        result = build_investigation(
            self.alert,
            self.detections,
            self.anomaly,
            self.risk,
            self.iocs,
            self.enriched_iocs,
            self.mitre,
        )

        self.assertEqual(
            result["risk_level"],
            "CRITICAL",
        )

        self.assertEqual(
            result["priority"],
            "P1",
        )

    def test_anomaly_is_added_to_findings(self):
        result = build_investigation(
            self.alert,
            self.detections,
            self.anomaly,
            self.risk,
            self.iocs,
            self.enriched_iocs,
            self.mitre,
        )

        findings = " ".join(
            result["findings"]
        )

        self.assertIn(
            "anomalous behavior",
            findings,
        )

    def test_mitre_evidence_is_added(self):
        result = build_investigation(
            self.alert,
            self.detections,
            self.anomaly,
            self.risk,
            self.iocs,
            self.enriched_iocs,
            self.mitre,
        )

        mitre_evidence = [
            item
            for item in result["evidence"]
            if item["type"] == "MITRE_ATTACK"
        ]

        self.assertEqual(
            len(mitre_evidence),
            1,
        )

        self.assertEqual(
            mitre_evidence[0]["technique_id"],
            "T1110",
        )

    def test_investigation_summary_uses_natural_language(self):
        result = build_investigation(
            self.alert,
            self.detections,
            self.anomaly,
            self.risk,
            self.iocs,
            self.enriched_iocs,
            self.mitre,
        )

        self.assertEqual(
            result["summary"],
            "CRITICAL risk alert requiring escalation.",
        )


if __name__ == "__main__":
    unittest.main()