import os
import unittest
from src.ai.llm import LLMClient
from unittest.mock import Mock, patch

class TestLLMClient(unittest.TestCase):

    def test_client_is_not_configured_without_api_key(self):
        with patch.dict(
            os.environ,
            {},
            clear=True,
        ):
            client = LLMClient()

            self.assertFalse(
                client.is_configured()
            )

    def test_empty_prompt_fails_safely(self):
        with patch.dict(
            os.environ,
            {},
            clear=True,
        ):
            client = LLMClient()

            result = client.generate("")

            self.assertFalse(
                result["success"]
            )

            self.assertEqual(
                result["error"],
                "EMPTY_PROMPT",
            )

    def test_unconfigured_client_fails_safely(self):
        with patch.dict(
            os.environ,
            {},
            clear=True,
        ):
            client = LLMClient()

            result = client.generate(
                "Investigate this SOC alert."
            )

            self.assertFalse(
                result["success"]
            )

            self.assertEqual(
                result["error"],
                "OPENAI_API_KEY_NOT_CONFIGURED",
            )

    def test_model_can_be_configured(self):
        with patch.dict(
            os.environ,
            {},
            clear=True,
        ):
            client = LLMClient(
                model="test-model"
            )

            self.assertEqual(
                client.model,
                "test-model",
            )

    @patch("src.ai.llm.OpenAI")
    def test_successful_response(
        self,
        mock_openai,
    ):
        mock_response = type(
            "Response",
            (),
            {
                "output_text": (
                    "The alert shows evidence of "
                    "brute-force activity."
                )
            },
        )()

        mock_client = mock_openai.return_value

        mock_client.responses.create.return_value = (
            mock_response
        )

        with patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "test-key"
            },
            clear=True,
        ):
            client = LLMClient()

            result = client.generate(
                "Investigate brute-force activity."
            )

        self.assertTrue(
            result["success"]
        )

        self.assertEqual(
            result["response"],
            "The alert shows evidence of "
            "brute-force activity.",
        )

        self.assertIsNone(
            result["error"]
        )

        mock_client.responses.create.assert_called_once()

    @patch("src.ai.llm.OpenAI")
    def test_api_failure_is_handled(
        self,
        mock_openai,
    ):
        mock_client = mock_openai.return_value

        mock_client.responses.create.side_effect = (
            RuntimeError("API unavailable")
        )

        with patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "test-key"
            },
            clear=True,
        ):
            client = LLMClient()

            result = client.generate(
                "Investigate this alert."
            )

        self.assertFalse(
            result["success"]
        )

        self.assertEqual(
            result["error"],
            "API_REQUEST_ERROR",
        )

        self.assertEqual(
            result["debug_error"],
            "API unavailable",
        )

        self.assertIn(
            "AI investigation request failed",
            result["response"],
        )

    def test_rate_limit_error_is_classified_safely(self):
        mock_client = Mock()

        mock_error = Exception("429 quota exceeded")
        mock_error.status_code = 429

        mock_client.responses.create.side_effect = (
            mock_error
        )

        with patch(
            "src.ai.llm.OpenAI",
            return_value=mock_client,
        ):
            with patch.dict(
                os.environ,
                {"OPENAI_API_KEY": "test-key"},
            ):
                client = LLMClient()

                result = client.generate(
                    "Investigate this alert."
                )

        self.assertFalse(
            result["success"]
        )

        self.assertEqual(
            result["error"],
            "API_QUOTA_OR_RATE_LIMIT",
        )

        self.assertIn(
            "429 quota exceeded",
            result["debug_error"],
        )

        self.assertNotIn(
            "429 quota exceeded",
            result["response"],
        )


    def test_authentication_error_is_classified_safely(self):
        mock_client = Mock()

        mock_error = Exception(
            "401 invalid authentication"
        )
        mock_error.status_code = 401

        mock_client.responses.create.side_effect = (
            mock_error
        )

        with patch(
            "src.ai.llm.OpenAI",
            return_value=mock_client,
        ):
            with patch.dict(
                os.environ,
                {"OPENAI_API_KEY": "test-key"},
            ):
                client = LLMClient()

                result = client.generate(
                    "Investigate this alert."
                )

        self.assertFalse(
            result["success"]
        )

        self.assertEqual(
            result["error"],
            "API_AUTHENTICATION_ERROR",
        )

        self.assertIn(
            "401 invalid authentication",
            result["debug_error"],
        )


    def test_server_error_is_classified_safely(self):
        mock_client = Mock()

        mock_error = Exception(
            "500 provider failure"
        )
        mock_error.status_code = 500

        mock_client.responses.create.side_effect = (
            mock_error
        )

        with patch(
            "src.ai.llm.OpenAI",
            return_value=mock_client,
        ):
            with patch.dict(
                os.environ,
                {"OPENAI_API_KEY": "test-key"},
            ):
                client = LLMClient()

                result = client.generate(
                    "Investigate this alert."
                )

        self.assertFalse(
            result["success"]
        )

        self.assertEqual(
            result["error"],
            "API_PROVIDER_ERROR",
        )

        self.assertIn(
            "500 provider failure",
            result["debug_error"],
        )


if __name__ == "__main__":
    unittest.main()