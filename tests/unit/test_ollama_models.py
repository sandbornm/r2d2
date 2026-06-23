from __future__ import annotations

from typing import Any

from r2d2.config import AppConfig
from r2d2.llm.manager import LLMBridge
from r2d2.llm.ollama_client import list_ollama_models, select_ollama_model


class _FakeOllamaTagsResponse:
    def __init__(self, models: list[str]) -> None:
        self._models = models

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return {"models": [{"name": model, "model": model} for model in self._models]}


def test_ollama_model_selection_prefers_installed_gemma(monkeypatch):
    def fake_get(url: str, timeout: float) -> _FakeOllamaTagsResponse:
        assert url.endswith("/api/tags")
        assert timeout > 0
        return _FakeOllamaTagsResponse(["gemma4:latest"])

    monkeypatch.setattr("r2d2.llm.ollama_client.httpx.get", fake_get)

    assert list_ollama_models("http://127.0.0.1:11434") == ["gemma4:latest"]
    assert select_ollama_model("http://127.0.0.1:11434", "gemma3:4b") == "gemma4:latest"


def test_llm_bridge_health_models_include_installed_ollama_model(monkeypatch):
    def fake_get(url: str, timeout: float) -> _FakeOllamaTagsResponse:
        return _FakeOllamaTagsResponse(["gemma4:latest"])

    monkeypatch.setattr("r2d2.llm.ollama_client.httpx.get", fake_get)
    config = AppConfig()
    config.llm.provider = "ollama"
    config.llm.model = "gemma3:4b"

    bridge = LLMBridge(config)

    assert bridge.model == "gemma4:latest"
    assert "gemma4:latest" in bridge.available_models
    assert "gemma3:4b" not in bridge.available_models
