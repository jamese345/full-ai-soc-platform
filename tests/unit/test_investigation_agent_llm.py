import unittest
from unittest.mock import Mock

from src.ai.investigation_agent import (
    InvestigationAgent,
    INSUFFICIENT_EVIDENCE,
)


class TestInvestigationAgentLLM(unittest.TestCase):

    def setUp(self):
        self.alert = {
            "alert_id": "SOC-0001",
            "timestamp": "2026-11-11T10:00:00+00:00",
            "source": "authentication",
            "event_type": "login",
            "severity": "HIGH",
            "src_ip": "192.168.1.50",
            "username": "admin",
            "hostname": "workstation-01",
            "description": (
                "Multiple failed login attempts from "
                "192.168.1.50 followed by a successful login."
            ),
            "failed_attempts": 15,
            "successful_logins": 1,
            "status": "FAILED",
        }

        self.detections = [
            {
                "rule_id": "DET-001",
                "rule_name": "Brute Force Detection",
                "alert_id": "SOC-0001",
                "detection": "BRUTE_FORCE",
                "severity": "HIGH",
                "confidence": "HIGH",
                "evidence": {
                    "failed_attempts": 15,
                    "threshold": 10,
                },
                "recommended_action": "INVESTIGATE",
            }
        ]

        self.anomaly = {
            "is_anomaly": True,
            "anomaly_score": -0.12,
            "classification": "ANOMALY",
        }

        self.risk = {
            "alert_id": "SOC-0001",
            "risk_score": 90,
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
                    "type": "IP",
                    "classification": "PRIVATE",
                    "threat_score": 0,
                    "reputation": "INTERNAL",
                    "source": "LOCAL",
                }
            ],
            "domains": [],
            "urls": [],
            "hashes": [],
        }

        self.mitre = [
            {
                "alert_id": "SOC-0001",
                "detection": "BRUTE_FORCE",
                "technique_id": "T1110",
                "name": "Brute Force",
                "description": "Brute force authentication attempts.",
                "tactics": ["credential-access"],
            }
        ]

    def test_successful_llm_investigation(self):
        mock_llm = Mock()

        mock_llm.generate.return_value = {
            "success": True,
            "response": (
                "The alert shows evidence of possible "
                "brute-force activity followed by a successful login."
            ),
            "model": "gpt-test",
            "error": None,
        }

        agent = InvestigationAgent(
            llm_client=mock_llm
        )

        result = agent.investigate_with_llm(
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
            "COMPLETED",
        )

        self.assertTrue(
            result["llm_called"]
        )

        self.assertEqual(
            result["model"],
            "gpt-test",
        )

        self.assertIn(
            "brute-force",
            result["response"].lower(),
        )

        mock_llm.generate.assert_called_once()

    def test_llm_error_is_handled(self):
        mock_llm = Mock()

        mock_llm.generate.return_value = {
            "success": False,
            "response": (
                "The AI investigation request failed. "
                "Review the underlying SOC evidence manually."
            ),
            "model": "gpt-test",
            "error": "API_ERROR",
        }

        agent = InvestigationAgent(
            llm_client=mock_llm
        )

        result = agent.investigate_with_llm(
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
            "LLM_ERROR",
        )

        self.assertTrue(
            result["llm_called"]
        )

        self.assertEqual(
            result["error"],
            "API_ERROR",
        )

        mock_llm.generate.assert_called_once()

    def test_llm_not_called_without_retrieved_evidence(self):
        mock_llm = Mock()

        agent = InvestigationAgent(
            llm_client=mock_llm
        )

        agent.retriever.retrieve_for_investigation = Mock(
            return_value={
                "alert_id": "SOC-0001",
                "query": "investigation query",
                "results": [],
                "result_count": 0,
            }
        )

        result = agent.investigate_with_llm(
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
            "INSUFFICIENT_EVIDENCE",
        )

        self.assertFalse(
            result["llm_called"]
        )

        self.assertEqual(
            result["response"],
            INSUFFICIENT_EVIDENCE,
        )

        mock_llm.generate.assert_not_called()

    def test_prompt_is_sent_to_llm(self):
        mock_llm = Mock()

        mock_llm.generate.return_value = {
            "success": True,
            "response": "Investigation completed.",
            "model": "gpt-test",
            "error": None,
        }

        agent = InvestigationAgent(
            llm_client=mock_llm
        )

        result = agent.investigate_with_llm(
            alert=self.alert,
            detections=self.detections,
            anomaly=self.anomaly,
            risk=self.risk,
            iocs=self.iocs,
            enriched_iocs=self.enriched_iocs,
            mitre=self.mitre,
        )

        prompt = mock_llm.generate.call_args.args[0]

        self.assertEqual(
            result["prompt"],
            prompt,
        )

        self.assertIn(
            "SOC-0001",
            prompt,
        )

        self.assertIn(
            "BRUTE_FORCE",
            prompt,
        )

        self.assertIn(
            "T1110",
            prompt,
        )

        self.assertIn(
            "192.168.1.50",
            prompt,
        )

    def test_grounding_instructions_are_present(self):
        mock_llm = Mock()

        mock_llm.generate.return_value = {
            "success": True,
            "response": "Investigation completed.",
            "model": "gpt-test",
            "error": None,
        }

        agent = InvestigationAgent(
            llm_client=mock_llm
        )

        result = agent.investigate_with_llm(
            alert=self.alert,
            detections=self.detections,
            anomaly=self.anomaly,
            risk=self.risk,
            iocs=self.iocs,
            enriched_iocs=self.enriched_iocs,
            mitre=self.mitre,
        )

        prompt = result["prompt"]

        self.assertIn(
            "Do not invent facts.",
            prompt,
        )

        self.assertIn(
            "Do not claim compromise without supporting evidence.",
            prompt,
        )

        self.assertIn(
            "Clearly distinguish observed evidence from inference.",
            prompt,
        )

        self.assertIn(
            "If evidence is insufficient, say so explicitly.",
            prompt,
        )

    def test_context_is_preserved_in_llm_result(self):
        mock_llm = Mock()

        mock_llm.generate.return_value = {
            "success": True,
            "response": "Investigation completed.",
            "model": "gpt-test",
            "error": None,
        }

        agent = InvestigationAgent(
            llm_client=mock_llm
        )

        result = agent.investigate_with_llm(
            alert=self.alert,
            detections=self.detections,
            anomaly=self.anomaly,
            risk=self.risk,
            iocs=self.iocs,
            enriched_iocs=self.enriched_iocs,
            mitre=self.mitre,
        )

        self.assertIn(
            "alert",
            result["context"],
        )

        self.assertIn(
            "detections",
            result["context"],
        )

        self.assertIn(
            "anomaly",
            result["context"],
        )

        self.assertIn(
            "risk",
            result["context"],
        )

        self.assertIn(
            "iocs",
            result["context"],
        )

        self.assertIn(
            "mitre",
            result["context"],
        )

        self.assertIn(
            "rag",
            result["context"],
        )


if __name__ == "__main__":
    unittest.main()