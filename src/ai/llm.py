import os

from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()


class LLMClient:
    """OpenAI LLM adapter for the AI SOC investigation agent."""

    def __init__(
        self,
        model: str | None = None,
    ):
        self.model = model or os.getenv(
            "OPENAI_MODEL",
            "gpt-5-mini",
        )

        self.api_key = os.getenv(
            "OPENAI_API_KEY"
        )

        self.client = None

        if self.api_key:
            self.client = OpenAI(
                api_key=self.api_key
            )

    def is_configured(self) -> bool:
        """Return True when an OpenAI API key is configured."""

        return bool(
            self.api_key
            and self.client
        )

    @staticmethod
    def _classify_error(exc: Exception) -> str:
        """
        Convert provider/API exceptions into safe,
        application-level error categories.
        """

        status_code = getattr(
            exc,
            "status_code",
            None,
        )

        if status_code == 429:
            return "API_QUOTA_OR_RATE_LIMIT"

        if status_code in (401, 403):
            return "API_AUTHENTICATION_ERROR"

        if status_code == 400:
            return "API_BAD_REQUEST"

        if status_code is not None and status_code >= 500:
            return "API_PROVIDER_ERROR"

        return "API_REQUEST_ERROR"

    def generate(
        self,
        prompt: str,
    ) -> dict:
        """
        Generate an investigation response.

        The method fails safely when the API is not configured
        or when an API request fails.
        """

        if not prompt or not prompt.strip():
            return {
                "success": False,
                "response": (
                    "Insufficient evidence to generate "
                    "an investigation response."
                ),
                "model": self.model,
                "error": "EMPTY_PROMPT",
                "debug_error": None,
            }

        if not self.is_configured():
            return {
                "success": False,
                "response": (
                    "LLM is not configured. "
                    "No investigation response was generated."
                ),
                "model": self.model,
                "error": "OPENAI_API_KEY_NOT_CONFIGURED",
                "debug_error": None,
            }

        try:
            response = self.client.responses.create(
                model=self.model,
                input=prompt,
            )

            return {
                "success": True,
                "response": response.output_text,
                "model": self.model,
                "error": None,
                "debug_error": None,
            }

        except Exception as exc:
            return {
                "success": False,
                "response": (
                    "The AI investigation request failed. "
                    "Review the underlying SOC evidence manually."
                ),
                "model": self.model,
                "error": self._classify_error(exc),
                "debug_error": str(exc),
            }