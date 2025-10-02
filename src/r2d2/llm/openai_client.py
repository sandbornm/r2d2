"""Thin wrapper around OpenAI's chat completion API."""

from __future__ import annotations

import os
from typing import Any, Iterable

from pydantic import BaseModel

from ..config import AppConfig

try:  # pragma: no cover - import guard
    from openai import OpenAI
except ModuleNotFoundError:  # pragma: no cover
    OpenAI = None  # type: ignore


class ChatMessage(BaseModel):
    role: str
    content: str


class OpenAIClient:
    def __init__(self, config: AppConfig) -> None:
        if OpenAI is None:
            raise RuntimeError("openai package is not installed")
        api_key = os.getenv(config.llm.api_key_env)
        if not api_key:
            raise RuntimeError(
                f"Environment variable {config.llm.api_key_env} not set; cannot use OpenAI API"
            )
        self._client = OpenAI(api_key=api_key)
        self._config = config

    def chat(self, messages: Iterable[ChatMessage] | Iterable[dict[str, str]]) -> str:
        payload: list[dict[str, str]] = []
        for message in messages:
            if isinstance(message, ChatMessage):
                payload.append(message.model_dump())
            else:
                payload.append(dict(message))

        completion = self._client.chat.completions.create(
            model=self._config.llm.model,
            messages=payload,
            max_tokens=self._config.llm.max_tokens,
            temperature=self._config.llm.temperature,
        )
        return completion.choices[0].message.content or ""

    def summarize_analysis(self, summary: dict[str, Any]) -> str:
        messages = [
            ChatMessage(role="system", content="You are a binary analysis assistant."),
            ChatMessage(
                role="user",
                content="Summarize the following structured analysis for an engineer:\n" + str(summary),
            ),
        ]
        return self.chat(messages)
