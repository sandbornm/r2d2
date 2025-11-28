"""Thin wrapper around OpenAI's chat completion API."""

from __future__ import annotations

import logging
import os
from typing import Any, Iterable

from pydantic import BaseModel

from ..config import AppConfig

try:  # pragma: no cover - import guard
    from openai import OpenAI, APIError, AuthenticationError, RateLimitError
except ModuleNotFoundError:  # pragma: no cover
    OpenAI = None  # type: ignore
    APIError = Exception  # type: ignore
    AuthenticationError = Exception  # type: ignore
    RateLimitError = Exception  # type: ignore

_LOGGER = logging.getLogger(__name__)


class ChatMessage(BaseModel):
    role: str
    content: str


class OpenAIError(Exception):
    """Wrapper for OpenAI API errors with clean messages."""
    pass


class OpenAIClient:
    """OpenAI chat completions client with automatic parameter handling."""

    # Models that use the new max_completion_tokens parameter
    NEW_API_MODELS = frozenset({
        "o1", "o1-mini", "o1-preview",
        "gpt-4o", "gpt-4o-mini", "gpt-4o-2024-05-13", "gpt-4o-2024-08-06",
        "gpt-4-turbo", "gpt-4-turbo-2024-04-09", "gpt-4-turbo-preview",
    })

    def __init__(self, config: AppConfig) -> None:
        if OpenAI is None:
            raise OpenAIError("OpenAI package is not installed. Run: pip install openai")

        api_key = os.getenv(config.llm.api_key_env)
        if not api_key:
            raise OpenAIError(
                f"OpenAI API key not found. Set the {config.llm.api_key_env} environment variable."
            )

        self._client = OpenAI(api_key=api_key)
        self._config = config
        self._model = config.llm.model

    def _uses_new_api(self) -> bool:
        """Check if current model uses new API parameters (max_completion_tokens)."""
        model_lower = self._model.lower()
        # Check exact matches and prefixes
        for new_model in self.NEW_API_MODELS:
            if model_lower == new_model or model_lower.startswith(f"{new_model}-"):
                return True
        # Models that use new API: o1*, gpt-4o*, gpt-4-turbo*, gpt-5*
        new_prefixes = ["o1", "gpt-4o", "gpt-4-turbo", "gpt-5"]
        if any(model_lower.startswith(prefix) for prefix in new_prefixes):
            return True
        return False

    def chat(self, messages: Iterable[ChatMessage] | Iterable[dict[str, str]]) -> str:
        """Send messages to OpenAI and return the assistant response."""
        payload: list[dict[str, str]] = []
        for message in messages:
            if isinstance(message, ChatMessage):
                payload.append(message.model_dump())
            else:
                payload.append(dict(message))

        # Build request parameters based on model
        params: dict[str, Any] = {
            "model": self._model,
            "messages": payload,
            "temperature": self._config.llm.temperature,
        }

        # Use appropriate token parameter
        if self._uses_new_api():
            params["max_completion_tokens"] = self._config.llm.max_tokens
        else:
            params["max_tokens"] = self._config.llm.max_tokens

        try:
            completion = self._client.chat.completions.create(**params)
            return completion.choices[0].message.content or ""
        except AuthenticationError:
            raise OpenAIError("Invalid OpenAI API key. Check your OPENAI_API_KEY.")
        except RateLimitError:
            raise OpenAIError("OpenAI rate limit exceeded. Please wait and try again.")
        except APIError as e:
            # Extract clean message from API error
            msg = str(e)
            if hasattr(e, 'message'):
                msg = e.message
            _LOGGER.debug("OpenAI API error: %s", e)
            raise OpenAIError(f"OpenAI API error: {msg}")

    def summarize_analysis(self, summary: dict[str, Any]) -> str:
        messages = [
            ChatMessage(role="system", content="You are a binary analysis assistant."),
            ChatMessage(
                role="user",
                content="Summarize the following structured analysis for an engineer:\n" + str(summary),
            ),
        ]
        return self.chat(messages)


__all__ = ["ChatMessage", "OpenAIClient", "OpenAIError"]
