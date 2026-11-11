import unittest

from src.investigation.evidence_builder import (
    build_investigation_query,
)


class TestEvidenceBuilder(unittest.TestCase):

    def setUp(self):
        self.alert = {
            "alert_id": "SOC-0001",
            "severity": "HIGH",
            "event_type": "brute_force",
            "src_ip": "192.168.1.50",
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
        }

        self.risk = {
            "risk_level": "CRITICAL",
            "priority": "P1",
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
            },
            {
                "technique_id": "T1078",
                "name": "Valid Accounts",
            },
        ]

    def test_query_contains_alert_context(self):
        query = build_investigation_query(
            self.alert,
            self.detections,
            self.anomaly,
            self.risk,
            self.iocs,
            self.enriched_iocs,
            self.mitre,
        )

        self.assertIn(
            "brute_force",
            query,
        )

        self.assertIn(
            "192.168.1.50",
            query,
        )

    def test_query_contains_rule_detections(self):
        query = build_investigation_query(
            self.alert,
            self.detections,
            self.anomaly,
            self.risk,
            self.iocs,
            self.enriched_iocs,
            self.mitre,
        )

        self.assertIn(
            "BRUTE_FORCE",
            query,
        )

        self.assertIn(
            "SUSPICIOUS_LOGIN",
            query,
        )

    def test_query_contains_anomaly_context(self):
        query = build_investigation_query(
            self.alert,
            self.detections,
            self.anomaly,
            self.risk,
            self.iocs,
            self.enriched_iocs,
            self.mitre,
        )

        self.assertIn(
            "anomalous behavior",
            query,
        )

    def test_query_contains_threat_intelligence(self):
        query = build_investigation_query(
            self.alert,
            self.detections,
            self.anomaly,
            self.risk,
            self.iocs,
            self.enriched_iocs,
            self.mitre,
        )

        self.assertIn(
            "PRIVATE",
            query,
        )

        self.assertIn(
            "INTERNAL",
            query,
        )

    def test_query_contains_mitre_context(self):
        query = build_investigation_query(
            self.alert,
            self.detections,
            self.anomaly,
            self.risk,
            self.iocs,
            self.enriched_iocs,
            self.mitre,
        )

        self.assertIn(
            "T1110",
            query,
        )

        self.assertIn(
            "Brute Force",
            query,
        )

        self.assertIn(
            "T1078",
            query,
        )

    def test_query_contains_investigation_objective(self):
        query = build_investigation_query(
            self.alert,
            self.detections,
            self.anomaly,
            self.risk,
            self.iocs,
            self.enriched_iocs,
            self.mitre,
        )

        self.assertIn(
            "additional evidence",
            query,
        )

        self.assertIn(
            "investigation steps",
            query,
        )


if __name__ == "__main__":
    unittest.main()