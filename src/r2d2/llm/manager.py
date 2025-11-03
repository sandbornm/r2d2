"""High-level LLM orchestration with provider fallback."""

from __future__ import annotations

from typing import Iterable

from ..config import AppConfig
from .claude_client import ClaudeClient
from .openai_client import ChatMessage, OpenAIClient


class LLMBridge:
    """Facade that attempts the configured provider then falls back if necessary."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._order: list[str] = []
        self._clients: dict[str, object] = {}
        self._errors: dict[str, Exception] = {}
        self._last_provider: str | None = None

        primary = config.llm.provider
        if primary:
            self._order.append(primary)

        fallback = config.llm.fallback_provider
        if (
            config.llm.enable_fallback
            and fallback
            and fallback not in self._order
        ):
            self._order.append(fallback)

    def chat(self, messages: Iterable[ChatMessage] | Iterable[dict[str, str]]) -> str:
        errors: list[str] = []
        for provider in self._order:
            client = self._get_client(provider)
            if client is None:
                error = self._errors.get(provider)
                if error:
                    errors.append(f"{provider}: {error}")
                continue
            try:
                response = client.chat(messages)  # type: ignore[no-any-return]
                self._last_provider = provider
                return response
            except Exception as exc:  # pragma: no cover - upstream failures
                self._errors[provider] = exc
                errors.append(f"{provider}: {exc}")
        raise RuntimeError(
            "All configured LLM providers failed: " + "; ".join(errors) if errors else "No LLM providers available"
        )

    def summarize_analysis(self, summary: dict[str, object]) -> str:
        errors: list[str] = []
        for provider in self._order:
            client = self._get_client(provider)
            if client is None:
                error = self._errors.get(provider)
                if error:
                    errors.append(f"{provider}: {error}")
                continue
            try:
                response = client.summarize_analysis(summary)  # type: ignore[no-any-return]
                self._last_provider = provider
                return response
            except Exception as exc:  # pragma: no cover - upstream failures
                self._errors[provider] = exc
                errors.append(f"{provider}: {exc}")
        raise RuntimeError(
            "All configured LLM providers failed: " + "; ".join(errors) if errors else "No LLM providers available"
        )

    def _get_client(self, provider: str) -> object | None:
        if provider in self._clients:
            return self._clients[provider]

        try:
            if provider.lower() in {"openai"}:
                client: object = OpenAIClient(self._config)
            elif provider.lower() in {"anthropic", "claude"}:
                client = ClaudeClient(self._config)
            else:
                raise ValueError(f"Unsupported LLM provider: {provider}")
        except Exception as exc:  # pragma: no cover - initialization guard
            self._errors[provider] = exc
            return None

        self._clients[provider] = client
        return client

    @property
    def errors(self) -> dict[str, Exception]:
        return self._errors.copy()

    @property
    def providers(self) -> list[str]:
        return list(self._order)

    @property
    def last_provider(self) -> str | None:
        return self._last_provider


__all__ = ["LLMBridge"]
