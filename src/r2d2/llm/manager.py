"""High-level LLM orchestration with provider fallback."""

from __future__ import annotations

import logging
from typing import Iterable

from ..config import AppConfig
from .claude_client import ClaudeClient, ClaudeError, ChatMessage
from .ollama_client import OllamaClient, OllamaError, list_ollama_models, select_ollama_model
from .openai_client import OpenAIClient, OpenAIError

_LOGGER = logging.getLogger(__name__)


class LLMError(Exception):
    """High-level error for LLM operations."""
    pass


class LLMBridge:
    """Facade that attempts the configured provider then falls back if necessary."""

    # Available models for selection (provider, model_id, display_name)
    DEFAULT_MODEL = "gemma3:4b"
    AVAILABLE_MODELS = [
        ("ollama", "gemma4:latest", "Gemma 4 8B (local)"),
        ("ollama", "gemma3:4b", "Gemma 3 4B (local)"),
        ("ollama", "gemma3:12b", "Gemma 3 12B (local)"),
        ("ollama", "gemma2:9b", "Gemma 2 9B (local)"),
        ("anthropic", "claude-opus-4-5", "Claude Opus 4.5"),
        ("anthropic", "claude-5-1", "Claude 5.1"),
        ("anthropic", "claude-sonnet-4-5", "Claude Sonnet 4.5"),
        ("openai", "gpt-4o", "GPT-4o"),
    ]

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._order: list[str] = []
        self._clients: dict[str, object] = {}
        self._errors: dict[str, str] = {}
        self._last_provider: str | None = None

        primary = config.llm.provider
        if primary:
            self._order.append(primary)

        fallback = getattr(config.llm, 'fallback_provider', None)
        enable_fallback = getattr(config.llm, 'enable_fallback', False)
        if enable_fallback and fallback and fallback not in self._order:
            self._order.append(fallback)

        if any(provider.lower() in {"ollama", "local"} for provider in self._order):
            self._config.llm.model = select_ollama_model(
                self._config.llm.base_url,
                self._config.llm.model,
            )

    def chat(self, messages: Iterable[ChatMessage] | Iterable[dict[str, str]]) -> str:
        """Send messages to configured LLM providers with automatic fallback."""
        errors: list[str] = []

        for provider in self._order:
            client = self._get_client(provider)
            if client is None:
                error = self._errors.get(provider)
                if error:
                    errors.append(f"{provider}: {error}")
                continue

            try:
                response = client.chat(messages)  # type: ignore[arg-type]
                self._last_provider = provider
                return response
            except (OpenAIError, ClaudeError, OllamaError) as exc:
                # Clean error message from client
                error_msg = str(exc)
                self._errors[provider] = error_msg
                errors.append(f"{provider}: {error_msg}")
                _LOGGER.warning("LLM provider %s failed: %s", provider, error_msg)
            except Exception as exc:
                # Unexpected error
                error_msg = f"Unexpected error: {type(exc).__name__}"
                self._errors[provider] = error_msg
                errors.append(f"{provider}: {error_msg}")
                _LOGGER.exception("Unexpected LLM error from %s", provider)

        # All providers failed
        if errors:
            raise LLMError(
                "LLM request failed. " + " | ".join(errors)
            )
        raise LLMError("No LLM providers configured. Start Ollama or configure Anthropic/OpenAI keys.")

    def summarize_analysis(self, summary: dict[str, object]) -> str:
        """Generate an analysis summary using the LLM."""
        errors: list[str] = []

        for provider in self._order:
            client = self._get_client(provider)
            if client is None:
                error = self._errors.get(provider)
                if error:
                    errors.append(f"{provider}: {error}")
                continue

            try:
                response = client.summarize_analysis(summary)
                self._last_provider = provider
                return response
            except (OpenAIError, ClaudeError, OllamaError) as exc:
                error_msg = str(exc)
                self._errors[provider] = error_msg
                errors.append(f"{provider}: {error_msg}")
                _LOGGER.warning("LLM provider %s failed: %s", provider, error_msg)
            except Exception as exc:
                error_msg = f"Unexpected error: {type(exc).__name__}"
                self._errors[provider] = error_msg
                errors.append(f"{provider}: {error_msg}")
                _LOGGER.exception("Unexpected LLM error from %s", provider)

        if errors:
            raise LLMError(
                "LLM request failed. " + " | ".join(errors)
            )
        raise LLMError("No LLM providers configured. Start Ollama or configure Anthropic/OpenAI keys.")

    def _get_client(self, provider: str) -> OpenAIClient | ClaudeClient | OllamaClient | None:
        """Get or create a client for the specified provider."""
        if provider in self._clients:
            return self._clients[provider]  # type: ignore[return-value]

        try:
            client: OpenAIClient | ClaudeClient | OllamaClient
            if provider.lower() == "openai":
                client = OpenAIClient(self._config)
            elif provider.lower() in {"anthropic", "claude"}:
                client = ClaudeClient(self._config)
            elif provider.lower() in {"ollama", "local"}:
                client = OllamaClient(self._config)
            else:
                self._errors[provider] = f"Unknown provider: {provider}"
                return None
        except (OpenAIError, ClaudeError, OllamaError) as exc:
            self._errors[provider] = str(exc)
            _LOGGER.debug("Failed to initialize %s client: %s", provider, exc)
            return None
        except Exception as exc:
            self._errors[provider] = f"Initialization failed: {type(exc).__name__}"
            _LOGGER.exception("Failed to initialize %s client", provider)
            return None

        self._clients[provider] = client
        return client

    def set_model(self, model: str) -> None:
        """Change the active model (Claude or OpenAI)."""
        model_info = self._model_info(model)
        if not model_info:
            available = self.available_models
            raise LLMError(f"Unknown model: {model}. Available: {', '.join(available)}")
        
        provider, model_id, _ = model_info
        
        # Update config
        self._config.llm.model = model_id
        self._config.llm.provider = provider
        
        # Reorder providers based on selection
        if provider == "anthropic":
            self._order = ["anthropic"]
            if self._config.llm.enable_fallback:
                self._order.append("openai")
        elif provider == "ollama":
            self._order = ["ollama"]
            if self._config.llm.enable_fallback and self._config.llm.fallback_provider:
                self._order.append(self._config.llm.fallback_provider)
        else:
            self._order = ["openai"]
            if self._config.llm.enable_fallback:
                self._order.append("anthropic")
        
        # Reset clients to pick up new model
        self._clients.clear()

    @property
    def model(self) -> str:
        """Return the currently configured model."""
        return self._config.llm.model

    @property
    def available_models(self) -> list[str]:
        """Return list of available model IDs."""
        models: list[str] = []
        installed_ollama = list_ollama_models(self._config.llm.base_url)
        static_ollama = [model for provider, model, _ in self.AVAILABLE_MODELS if provider == "ollama"]
        remote_models = [model for provider, model, _ in self.AVAILABLE_MODELS if provider != "ollama"]
        models.extend(installed_ollama or static_ollama)
        models.extend(remote_models)
        if self._config.llm.model not in models:
            models.insert(0, self._config.llm.model)
        return list(dict.fromkeys(models))
    
    @property
    def model_display_names(self) -> dict[str, str]:
        """Return mapping of model ID to display name."""
        names = {m[1]: m[2] for m in self.AVAILABLE_MODELS}
        for model in list_ollama_models(self._config.llm.base_url):
            names.setdefault(model, f"{model} (local)")
        return names

    @property
    def errors(self) -> dict[str, str]:
        """Return copy of accumulated errors by provider."""
        return self._errors.copy()

    @property
    def providers(self) -> list[str]:
        """Return list of configured providers in priority order."""
        return list(self._order)

    @property
    def last_provider(self) -> str | None:
        """Return the provider used for the last successful request."""
        return self._last_provider

    def is_available(self) -> bool:
        """Check if at least one provider is available."""
        for provider in self._order:
            if self._get_client(provider) is not None:
                return True
        return False

    def _model_info(self, model: str) -> tuple[str, str, str] | None:
        static = next((entry for entry in self.AVAILABLE_MODELS if entry[1] == model), None)
        if static:
            return static
        if model in list_ollama_models(self._config.llm.base_url):
            return ("ollama", model, f"{model} (local)")
        return None


__all__ = ["LLMBridge", "LLMError", "ChatMessage"]
