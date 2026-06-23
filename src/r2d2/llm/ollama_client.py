"""Ollama chat client for local models such as Gemma."""

from __future__ import annotations

from typing import Any, Iterable

import httpx
from pydantic import BaseModel

from ..config import AppConfig


class ChatMessage(BaseModel):
    role: str
    content: str


class OllamaError(Exception):
    """Wrapper for local Ollama API errors."""


class OllamaClient:
    """Small HTTP client for Ollama's local chat API."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._base_url = config.llm.base_url.rstrip("/")
        self._model = select_ollama_model(self._base_url, config.llm.model)
        self._config.llm.model = self._model
        self._timeout = httpx.Timeout(connect=2.0, read=180.0, write=20.0, pool=5.0)

    def chat(self, messages: Iterable[ChatMessage] | Iterable[dict[str, str]]) -> str:
        payload_messages: list[dict[str, str]] = []
        for message in messages:
            if isinstance(message, ChatMessage):
                payload_messages.append(message.model_dump())
            else:
                payload_messages.append(dict(message))

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": payload_messages,
            "stream": False,
            "options": {
                "temperature": self._config.llm.temperature,
                "num_predict": self._config.llm.max_tokens,
            },
        }

        try:
            response = httpx.post(
                f"{self._base_url}/api/chat",
                json=payload,
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.ConnectError as exc:
            raise OllamaError(
                f"Ollama is not reachable at {self._base_url}. "
                f"Start Ollama and run: ollama pull {self._model}"
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise OllamaError(f"Ollama HTTP error: {exc.response.status_code} {exc.response.text[:500]}") from exc
        except httpx.HTTPError as exc:
            raise OllamaError(f"Ollama request failed: {exc}") from exc

        data = response.json()
        message = data.get("message")
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, str):
                return content
        raise OllamaError("Ollama returned an unexpected response shape.")

    def summarize_analysis(self, summary: dict[str, Any]) -> str:
        messages = [
            ChatMessage(role="system", content="You are a binary analysis assistant."),
            ChatMessage(
                role="user",
                content="Summarize the following structured analysis for an engineer:\n" + str(summary),
            ),
        ]
        return self.chat(messages)

def list_ollama_models(base_url: str, *, timeout: float = 1.5) -> list[str]:
    """Return installed Ollama model names, or an empty list if unavailable."""
    try:
        response = httpx.get(f"{base_url.rstrip('/')}/api/tags", timeout=timeout)
        response.raise_for_status()
    except httpx.HTTPError:
        return []

    payload = response.json()
    models = payload.get("models")
    if not isinstance(models, list):
        return []

    names: list[str] = []
    for model in models:
        if not isinstance(model, dict):
            continue
        name = model.get("name") or model.get("model")
        if isinstance(name, str) and name:
            names.append(name)
    return sorted(set(names))


def select_ollama_model(base_url: str, preferred: str) -> str:
    """Choose an installed Ollama model, preferring Gemma for local chat."""
    installed = list_ollama_models(base_url)
    if not installed or preferred in installed:
        return preferred

    gemma_models = [model for model in installed if model.lower().startswith("gemma")]
    if gemma_models:
        return sorted(gemma_models, key=_ollama_model_rank)[0]
    return installed[0]


def _ollama_model_rank(model: str) -> tuple[int, str]:
    lower = model.lower()
    if lower.startswith("gemma4"):
        return (0, lower)
    if lower.startswith("gemma3"):
        return (1, lower)
    if lower.startswith("gemma2"):
        return (2, lower)
    return (9, lower)


__all__ = ["ChatMessage", "OllamaClient", "OllamaError", "list_ollama_models", "select_ollama_model"]
