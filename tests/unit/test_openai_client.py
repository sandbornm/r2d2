from r2d2.config import AppConfig, LLMSettings
from r2d2.llm.openai_client import OpenAIClient, _openai_base_url


def test_openai_base_url_none_for_ollama_default():
    config = AppConfig(llm=LLMSettings())
    assert _openai_base_url(config) is None


def test_openai_base_url_uses_explicit_field():
    config = AppConfig(
        llm=LLMSettings(openai_base_url="http://minimus-mac-mini:52415/v1/")
    )
    assert _openai_base_url(config) == "http://minimus-mac-mini:52415/v1"


def test_openai_base_url_from_provider_base_url():
    config = AppConfig(
        llm=LLMSettings(provider="openai", base_url="http://127.0.0.1:8000/v1")
    )
    assert _openai_base_url(config) == "http://127.0.0.1:8000/v1"


def test_openai_client_accepts_local_gateway_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    config = AppConfig(
        llm=LLMSettings(
            provider="openai",
            model="qwen",
            openai_base_url="http://127.0.0.1:52415/v1",
            fallback_api_key_env="OPENAI_API_KEY",
        )
    )
    client = OpenAIClient(config)
    assert client._base_url == "http://127.0.0.1:52415/v1"
    assert client._model == "qwen"
    assert client._uses_new_api() is False
