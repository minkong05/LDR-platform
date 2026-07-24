# 📄 apps/backend/app/services/summarization/service.py

from __future__ import annotations

from typing import Any

from app.services.summarization.client import LLMClient
from app.services.summarization.prompt_builder import build_prompt
from app.settings import settings


class SummarizationService:
    """
    Orchestrates building the prompt and calling the LLM for one alert.

    Mirrors EmailService's resilience contract: short-circuits to None
    when disabled (no network call attempted at all), and otherwise
    delegates to LLMClient, which never raises.
    """

    def __init__(self, client: LLMClient | None = None) -> None:
        self._client = client or LLMClient()

    def summarize_alert(
        self,
        alert: dict[str, Any],
        events: list[dict[str, Any]],
        risk: dict[str, Any],
    ) -> str | None:
        if not settings.llm_enabled:
            return None

        prompt = build_prompt(
            ip=alert.get("source_ip", "unknown"),
            alerts=[alert],
            events=events,
            risk=risk,
        )
        return self._client.summarize(prompt)
