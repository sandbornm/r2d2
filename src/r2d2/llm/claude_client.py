"""Anthropic Claude client wrapper."""

from __future__ import annotations

import logging
import os
from typing import Any, Iterable

from pydantic import BaseModel

from ..config import AppConfig


class ChatMessage(BaseModel):
    role: str
    content: str

try:  # pragma: no cover - optional dependency
    from anthropic import Anthropic, APIError, AuthenticationError, RateLimitError
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    Anthropic = None  # type: ignore[misc,assignment]
    APIError = Exception  # type: ignore
    AuthenticationError = Exception  # type: ignore
    RateLimitError = Exception  # type: ignore

_LOGGER = logging.getLogger(__name__)


class ClaudeChatResponse(BaseModel):
    content: str


class ClaudeError(Exception):
    """Wrapper for Anthropic API errors with clean messages."""
    pass


class ClaudeClient:
    """Thin wrapper over Anthropic's Messages API for chat parity with OpenAI client."""

    def __init__(self, config: AppConfig) -> None:
        if Anthropic is None:
            raise ClaudeError("Anthropic package is not installed. Run: pip install anthropic")

        api_env = config.llm.api_key_env or "ANTHROPIC_API_KEY"
        api_key = os.getenv(api_env)
        if not api_key:
            raise ClaudeError(
                f"Anthropic API key not found. Set the {api_env} environment variable."
            )

        self._client = Anthropic(api_key=api_key)
        self._config = config
        # Support both primary and fallback model configuration
        # Default to Opus 4.5 if no model specified
        if config.llm.provider and config.llm.provider.lower() in {"anthropic", "claude"}:
            self._model = config.llm.model or "claude-opus-4-5"
        else:
            self._model = config.llm.fallback_model or "claude-opus-4-5"

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

            # Claude handles system prompt separately
            if role == "system":
                if system_prompt is None:
                    system_prompt = content
                else:
                    system_prompt += "\n\n" + content
                continue

            # Map assistant to assistant, user to user
            formatted.append({"role": role, "content": content})

        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=self._config.llm.max_tokens,
                temperature=self._config.llm.temperature,
                system=system_prompt or "",
                messages=formatted,  # type: ignore[arg-type]
            )

            if not response.content:
                return ""

            segments = []
            for part in response.content:
                text = getattr(part, "text", None)
                if text:
                    segments.append(text)
            return "\n".join(segments)

        except AuthenticationError:
            raise ClaudeError("Invalid Anthropic API key. Check your ANTHROPIC_API_KEY.")
        except RateLimitError:
            raise ClaudeError("Anthropic rate limit exceeded. Please wait and try again.")
        except APIError as e:
            msg = str(e)
            if hasattr(e, 'message'):
                msg = e.message
            _LOGGER.debug("Anthropic API error: %s", e)
            raise ClaudeError(f"Anthropic API error: {msg}")

    def summarize_analysis(self, summary: dict[str, Any]) -> str:
        messages = [
            ChatMessage(role="system", content="You are a binary analysis assistant."),
            ChatMessage(
                role="user",
                content="Summarize the following structured analysis for an engineer:\n" + str(summary),
            ),
        ]
        return self.chat(messages)


__all__ = ["ChatMessage", "ClaudeClient", "ClaudeError"]
