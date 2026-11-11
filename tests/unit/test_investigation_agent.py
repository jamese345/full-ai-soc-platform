import unittest

from src.ai.investigation_agent import (
    InvestigationAgent,
)


class TestInvestigationAgent(unittest.TestCase):

    def setUp(self):
        self.agent = InvestigationAgent()

        self.alert = {
            "alert_id": "SOC-0001",
            "timestamp": "2026-11-11T02:00:00+00:00",
            "source": "auth-server",
            "event_type": "brute_force",
            "severity": "HIGH",
            "src_ip": "192.168.1.50",
            "username": "admin",
            "hostname": "server-01",
            "description": (
                "Multiple failed login attempts from "
                "192.168.1.50 targeting admin account"
            ),
            "failed_attempts": 18,
            "successful_logins": 1,
            "status": "OPEN",
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
            },
            {
                "technique_id": "T1078",
                "name": "Valid Accounts",
                "tactics": [
                    "initial-access",
                    "persistence",
                ],
            },
        ]

    def test_context_contains_pipeline_evidence(self):
        context = self.agent.build_context(
            alert=self.alert,
            detections=self.detections,
            anomaly=self.anomaly,
            risk=self.risk,
            iocs=self.iocs,
            enriched_iocs=self.enriched_iocs,
            mitre=self.mitre,
        )

        self.assertIn("alert", context)
        self.assertIn("detections", context)
        self.assertIn("anomaly", context)
        self.assertIn("risk", context)
        self.assertIn("iocs", context)
        self.assertIn("enriched_iocs", context)
        self.assertIn("mitre", context)
        self.assertIn("rag", context)

    def test_prompt_contains_alert_information(self):
        context = self.agent.build_context(
            self.alert,
            self.detections,
            self.anomaly,
            self.risk,
            self.iocs,
            self.enriched_iocs,
            self.mitre,
        )

        prompt = self.agent.build_prompt(context)

        self.assertIn(
            "SOC-0001",
            prompt,
        )

        self.assertIn(
            "brute_force",
            prompt,
        )

        self.assertIn(
            "192.168.1.50",
            prompt,
        )

    def test_prompt_contains_detection_information(self):
        context = self.agent.build_context(
            self.alert,
            self.detections,
            self.anomaly,
            self.risk,
            self.iocs,
            self.enriched_iocs,
            self.mitre,
        )

        prompt = self.agent.build_prompt(context)

        self.assertIn(
            "BRUTE_FORCE",
            prompt,
        )

        self.assertIn(
            "SUSPICIOUS_LOGIN",
            prompt,
        )

    def test_prompt_contains_mitre_information(self):
        context = self.agent.build_context(
            self.alert,
            self.detections,
            self.anomaly,
            self.risk,
            self.iocs,
            self.enriched_iocs,
            self.mitre,
        )

        prompt = self.agent.build_prompt(context)

        self.assertIn(
            "T1110",
            prompt,
        )

        self.assertIn(
            "Brute Force",
            prompt,
        )

    def test_prompt_contains_grounding_instructions(self):
        context = self.agent.build_context(
            self.alert,
            self.detections,
            self.anomaly,
            self.risk,
            self.iocs,
            self.enriched_iocs,
            self.mitre,
        )

        prompt = self.agent.build_prompt(context)

        self.assertIn(
            "Do not invent facts.",
            prompt,
        )

        self.assertIn(
            "evidence is insufficient",
            prompt,
        )

    def test_investigate_does_not_call_llm(self):
        result = self.agent.investigate(
            alert=self.alert,
            detections=self.detections,
            anomaly=self.anomaly,
            risk=self.risk,
            iocs=self.iocs,
            enriched_iocs=self.enriched_iocs,
            mitre=self.mitre,
        )

        self.assertEqual(
            result["status"],
            "READY_FOR_LLM",
        )

        self.assertFalse(
            result["llm_called"],
        )

        self.assertGreater(
            len(result["prompt"]),
            0,
        )


if __name__ == "__main__":
    unittest.main()