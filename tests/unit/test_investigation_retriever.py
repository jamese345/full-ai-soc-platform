import unittest

from src.rag.investigation_retriever import (
    InvestigationRetriever,
)


class TestInvestigationRetriever(unittest.TestCase):

    def setUp(self):
        self.retriever = InvestigationRetriever()

        self.alert = {
            "alert_id": "SOC-0001",
            "severity": "HIGH",
            "event_type": "brute_force",
            "src_ip": "192.168.1.50",
        }

        self.detections = [
            {
                "detection": "BRUTE_FORCE",
                "severity": "HIGH",
                "confidence": "HIGH",
            },
            {
                "detection": "SUSPICIOUS_LOGIN",
                "severity": "HIGH",
                "confidence": "HIGH",
            },
        ]

        self.anomaly = {
            "is_anomaly": True,
            "classification": "ANOMALY",
            "anomaly_score": -0.1078,
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
                "tactics": ["credential-access"],
            }
        ]

    def test_returns_investigation_evidence_pack(self):
        result = self.retriever.retrieve_for_investigation(
            alert=self.alert,
            detections=self.detections,
            anomaly=self.anomaly,
            risk=self.risk,
            iocs=self.iocs,
            enriched_iocs=self.enriched_iocs,
            mitre=self.mitre,
        )

        self.assertIn(
            "alert_id",
            result,
        )

        self.assertIn(
            "query",
            result,
        )

        self.assertIn(
            "results",
            result,
        )

        self.assertIn(
            "result_count",
            result,
        )

    def test_alert_id_is_preserved(self):
        result = self.retriever.retrieve_for_investigation(
            alert=self.alert,
            detections=self.detections,
            anomaly=self.anomaly,
            risk=self.risk,
            iocs=self.iocs,
            enriched_iocs=self.enriched_iocs,
            mitre=self.mitre,
        )

        self.assertEqual(
            result["alert_id"],
            "SOC-0001",
        )

    def test_query_is_generated(self):
        result = self.retriever.retrieve_for_investigation(
            alert=self.alert,
            detections=self.detections,
            anomaly=self.anomaly,
            risk=self.risk,
            iocs=self.iocs,
            enriched_iocs=self.enriched_iocs,
            mitre=self.mitre,
        )

        self.assertGreater(
            len(result["query"]),
            0,
        )

        self.assertIn(
            "BRUTE_FORCE",
            result["query"],
        )

    def test_results_are_retrieved(self):
        result = self.retriever.retrieve_for_investigation(
            alert=self.alert,
            detections=self.detections,
            anomaly=self.anomaly,
            risk=self.risk,
            iocs=self.iocs,
            enriched_iocs=self.enriched_iocs,
            mitre=self.mitre,
            top_k=3,
        )

        self.assertGreater(
            result["result_count"],
            0,
        )

    def test_top_k_is_respected(self):
        result = self.retriever.retrieve_for_investigation(
            alert=self.alert,
            detections=self.detections,
            anomaly=self.anomaly,
            risk=self.risk,
            iocs=self.iocs,
            enriched_iocs=self.enriched_iocs,
            mitre=self.mitre,
            top_k=2,
        )

        self.assertLessEqual(
            result["result_count"],
            2,
        )

    def test_results_have_scores(self):
        result = self.retriever.retrieve_for_investigation(
            alert=self.alert,
            detections=self.detections,
            anomaly=self.anomaly,
            risk=self.risk,
            iocs=self.iocs,
            enriched_iocs=self.enriched_iocs,
            mitre=self.mitre,
        )

        for item in result["results"]:
            self.assertIn(
                "score",
                item,
            )

            self.assertIsInstance(
                item["score"],
                float,
            )


if __name__ == "__main__":
    unittest.main()