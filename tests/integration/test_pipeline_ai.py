import unittest
from unittest.mock import patch

from src.pipeline import process_alerts


ALERT_FILE = "data/alerts/sample_alerts.json"


class TestPipelineAI(unittest.TestCase):

    def test_ai_investigation_disabled_by_default(self):
        result = process_alerts(
            ALERT_FILE
        )

        self.assertIn(
            "alerts",
            result
        )

        self.assertIn(
            "investigations",
            result
        )

        self.assertIn(
            "ai_investigations",
            result
        )

        self.assertEqual(
            result["ai_investigations"],
            {}
        )

    @patch("src.pipeline.InvestigationAgent")
    def test_ai_investigation_enabled(self, mock_agent_class):
        mock_agent = mock_agent_class.return_value

        mock_agent.investigate_with_llm.side_effect = (
            lambda **kwargs: {
                "alert_id": kwargs["alert"]["alert_id"],
                "status": "COMPLETED",
                "response": "Mock AI investigation completed.",
                "model": "gpt-test",
                "error": None,
                "llm_called": True,
                "prompt": "mock prompt",
                "context": {},
            }
        )

        result = process_alerts(
            ALERT_FILE,
            run_ai_investigation=True,
        )

        self.assertTrue(
            len(result["ai_investigations"]) > 0
        )

        self.assertEqual(
            len(result["ai_investigations"]),
            len(result["alerts"])
        )

        for alert in result["alerts"]:
            alert_id = alert["alert_id"]

            self.assertIn(
                alert_id,
                result["ai_investigations"]
            )

            self.assertEqual(
                result["ai_investigations"][alert_id]["status"],
                "COMPLETED"
            )

        self.assertTrue(
            mock_agent.investigate_with_llm.called
        )

    @patch("src.pipeline.InvestigationAgent")
    def test_ai_results_are_separate_from_deterministic_results(
        self,
        mock_agent_class,
    ):
        mock_agent = mock_agent_class.return_value

        mock_agent.investigate_with_llm.return_value = {
            "alert_id": "SOC-0001",
            "status": "COMPLETED",
            "response": "AI result",
            "model": "gpt-test",
            "error": None,
            "llm_called": True,
            "prompt": "prompt",
            "context": {},
        }

        result = process_alerts(
            ALERT_FILE,
            run_ai_investigation=True,
        )

        self.assertIn(
            "investigations",
            result
        )

        self.assertIn(
            "ai_investigations",
            result
        )

        self.assertIsNot(
            result["investigations"],
            result["ai_investigations"]
        )

        self.assertGreater(
            len(result["investigations"]),
            0
        )

        self.assertGreater(
            len(result["ai_investigations"]),
            0
        )

    @patch("src.pipeline.InvestigationAgent")
    def test_ai_failure_does_not_remove_soc_results(
        self,
        mock_agent_class,
    ):
        mock_agent = mock_agent_class.return_value

        mock_agent.investigate_with_llm.return_value = {
            "alert_id": "SOC-0001",
            "status": "LLM_ERROR",
            "response": (
                "LLM is not configured. "
                "No investigation response was generated."
            ),
            "model": "gpt-test",
            "error": "OPENAI_API_KEY_NOT_CONFIGURED",
            "llm_called": True,
            "prompt": "prompt",
            "context": {},
        }

        result = process_alerts(
            ALERT_FILE,
            run_ai_investigation=True,
        )

        # Core SOC pipeline must still succeed.
        self.assertGreater(
            len(result["alerts"]),
            0
        )

        self.assertIn(
            "detections",
            result
        )

        self.assertIn(
            "anomalies",
            result
        )

        self.assertIn(
            "risks",
            result
        )

        self.assertIn(
            "iocs",
            result
        )

        self.assertIn(
            "mitre",
            result
        )

        self.assertIn(
            "investigations",
            result
        )

        self.assertIn(
            "ai_investigations",
            result
        )

        for ai_result in result["ai_investigations"].values():
            self.assertEqual(
                ai_result["status"],
                "LLM_ERROR"
            )

    @patch("src.pipeline.InvestigationAgent")
    def test_each_alert_gets_its_own_ai_result(
        self,
        mock_agent_class,
    ):
        mock_agent = mock_agent_class.return_value

        def fake_investigation(**kwargs):
            alert_id = kwargs["alert"]["alert_id"]

            return {
                "alert_id": alert_id,
                "status": "COMPLETED",
                "response": (
                    f"AI investigation for {alert_id}"
                ),
                "model": "gpt-test",
                "error": None,
                "llm_called": True,
                "prompt": "prompt",
                "context": {},
            }

        mock_agent.investigate_with_llm.side_effect = (
            fake_investigation
        )

        result = process_alerts(
            ALERT_FILE,
            run_ai_investigation=True,
        )

        alert_ids = {
            alert["alert_id"]
            for alert in result["alerts"]
        }

        ai_alert_ids = set(
            result["ai_investigations"].keys()
        )

        self.assertEqual(
            alert_ids,
            ai_alert_ids
        )

        for alert_id in alert_ids:
            self.assertIn(
                alert_id,
                result["ai_investigations"]
            )

            self.assertIn(
                alert_id,
                result["investigations"]
            )


if __name__ == "__main__":
    unittest.main()