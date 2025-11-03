"""Anthropic Claude client wrapper."""

from __future__ import annotations

import os
from typing import Iterable

from pydantic import BaseModel

from ..config import AppConfig
from .openai_client import ChatMessage

try:  # pragma: no cover - optional dependency
    from anthropic import Anthropic
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    Anthropic = None  # type: ignore[misc,assignment]


class ClaudeChatResponse(BaseModel):
    content: str


class ClaudeClient:
    """Thin wrapper over Anthropics Messages API for chat parity with OpenAI client."""

    def __init__(self, config: AppConfig) -> None:
        if Anthropic is None:
            raise RuntimeError("anthropic package is not installed")

        api_env = config.llm.fallback_api_key_env or "ANTHROPIC_API_KEY"
        api_key = os.getenv(api_env)
        if not api_key:
            raise RuntimeError(
                f"Environment variable {api_env} not set; cannot use Anthropic API"
            )

        self._client = Anthropic(api_key=api_key)
        self._config = config
        self._model = config.llm.fallback_model or "claude-3-sonnet-20240229"

    def chat(self, messages: Iterable[ChatMessage] | Iterable[dict[str, str]]) -> str:
        """Send a chat conversation to Claude and return the assistant reply."""

        system_prompt: str | None = None
        formatted: list[dict[str, str]] = []

        for message in messages:
            if isinstance(message, ChatMessage):
                role = message.role
                content = message.content
            else:
                role = message["role"]
                content = message["content"]

            if role == "system" and system_prompt is None:
                system_prompt = content
                continue

            formatted.append({"role": role, "content": content})

        response = self._client.messages.create(
            model=self._model,
            max_tokens=self._config.llm.max_tokens,
            temperature=self._config.llm.temperature,
            system=system_prompt,
            messages=formatted,
        )

        if not response.content:
            return ""

        segments = []
        for part in response.content:
            text = getattr(part, "text", None)
            if text:
                segments.append(text)
        return "\n".join(segments)

    def summarize_analysis(self, summary: dict[str, object]) -> str:
        messages = [
            ChatMessage(role="system", content="You are a binary analysis assistant."),
            ChatMessage(
                role="user",
                content="Summarize the following structured analysis for an engineer:\n" + str(summary),
            ),
        ]
        return self.chat(messages)


__all__ = ["ClaudeClient"]
