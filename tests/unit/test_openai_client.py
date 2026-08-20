import pytest

from r2d2.config import AppConfig, LLMSettings
from r2d2.llm.openai_client import (
    OpenAIClient,
    OpenAIError,
    _openai_base_url,
    _rate_limit_message,
    _requires_api_key,
    _resolve_openai_api_key,
)


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


def test_resolve_prefers_named_api_key_env(monkeypatch):
    monkeypatch.setenv("ZAI_API_KEY", "zai-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-secret")
    config = AppConfig(
        llm=LLMSettings(provider="openai", api_key_env="ZAI_API_KEY", fallback_api_key_env="OPENAI_API_KEY")
    )
    key, name = _resolve_openai_api_key(config)
    assert key == "zai-secret"
    assert name == "ZAI_API_KEY"


def test_z_ai_host_requires_a_key(monkeypatch):
    for name in ("ZAI_API_KEY", "XAI_API_KEY", "OPENAI_API_KEY", "GLM_API_KEY", "ZHIPUAI_API_KEY", "ZHIPU_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    config = AppConfig(
        llm=LLMSettings(
            provider="openai",
            api_key_env="ZAI_API_KEY",
            openai_base_url="https://api.z.ai/api/paas/v4/",
        )
    )
    assert _requires_api_key(config.llm.openai_base_url) is True
    with pytest.raises(OpenAIError, match="ZAI_API_KEY"):
        OpenAIClient(config)


def test_glm_key_alias_wins_over_openai(monkeypatch):
    monkeypatch.setenv("GLM_API_KEY", "glm-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-secret")
    config = AppConfig(
        llm=LLMSettings(provider="glm", api_key_env="GLM_API_KEY", fallback_api_key_env="OPENAI_API_KEY")
    )
    key, name = _resolve_openai_api_key(config)
    assert key == "glm-secret"
    assert name == "GLM_API_KEY"


def test_glm_provider_defaults_to_bigmodel_host(monkeypatch):
    monkeypatch.setenv("GLM_API_KEY", "glm-secret")
    monkeypatch.delenv("ZAI_API_KEY", raising=False)
    config = AppConfig(llm=LLMSettings(provider="glm", api_key_env="GLM_API_KEY", model="glm-5.2"))
    assert _openai_base_url(config) == "https://open.bigmodel.cn/api/paas/v4"
    client = OpenAIClient(config)
    assert client._model == "glm-5.2"
    assert client._base_url == "https://open.bigmodel.cn/api/paas/v4"


def test_glm_provider_uses_z_ai_when_zai_key(monkeypatch):
    monkeypatch.delenv("GLM_API_KEY", raising=False)
    monkeypatch.setenv("ZAI_API_KEY", "zai-secret")
    config = AppConfig(llm=LLMSettings(provider="glm", api_key_env="ZAI_API_KEY", model="glm-5.2"))
    assert _openai_base_url(config) == "https://api.z.ai/api/paas/v4"


def test_rate_limit_message_distinguishes_z_ai_empty_credit():
    credit = (
        "Error code: 429 - {'error': {'code': '1113', "
        "'message': 'Insufficient balance or no resource package. Please recharge.'}}"
    )
    mapped = _rate_limit_message(Exception(credit))
    assert "1113" in mapped
    assert "coding/paas" in mapped
    assert "wait" in _rate_limit_message(Exception("Error code: 429 - rate limit exceeded")).lower()


class _StubCompletions:
    """Capture create() params; return one canned completion."""

    def __init__(self, content: str) -> None:
        self.calls: list[dict] = []
        self._content = content

    def create(self, **params):
        self.calls.append(params)
        message = type("M", (), {"content": self._content})()
        choice = type("C", (), {"message": message})()
        return type("R", (), {"choices": [choice]})()


def _local_client(monkeypatch) -> OpenAIClient:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    config = AppConfig(
        llm=LLMSettings(
            provider="openai",
            model="qwen",
            openai_base_url="http://127.0.0.1:52415/v1",
        )
    )
    return OpenAIClient(config)


def test_chat_overrides_per_call(monkeypatch):
    client = _local_client(monkeypatch)
    stub = _StubCompletions("planner reply")
    client._client = type("Client", (), {"chat": type("Chat", (), {"completions": stub})()})()
    out = client.chat(
        [{"role": "user", "content": "hi"}],
        max_tokens=17, temperature=0.4,
        extra_body={"enable_thinking": False}, timeout=12.0,
    )
    assert out == "planner reply"
    params = stub.calls[0]
    assert params["max_tokens"] == 17
    assert params["temperature"] == 0.4
    assert params["extra_body"] == {"enable_thinking": False}
    assert params["timeout"] == 12.0


def test_chat_defaults_to_config_values(monkeypatch):
    client = _local_client(monkeypatch)
    stub = _StubCompletions("ok")
    client._client = type("Client", (), {"chat": type("Chat", (), {"completions": stub})()})()
    client.chat([{"role": "user", "content": "hi"}])
    params = stub.calls[0]
    assert params["max_tokens"] == client._config.llm.max_tokens
    assert params["temperature"] == client._config.llm.temperature
    assert "extra_body" not in params
    assert "timeout" not in params


def test_chat_truncates_chat_template_token_leak(monkeypatch):
    client = _local_client(monkeypatch)
    leak = "real answer<|endoftext|>garbage continuation<|im_end|>more"
    stub = _StubCompletions(leak)
    client._client = type("Client", (), {"chat": type("Chat", (), {"completions": stub})()})()
    assert client.chat([{"role": "user", "content": "hi"}]) == "real answer"


def test_coding_plan_host_disables_thinking_by_default(monkeypatch):
    monkeypatch.setenv("ZAI_API_KEY", "id.secret")
    config = AppConfig(
        llm=LLMSettings(
            provider="openai",
            model="glm-5.3",
            api_key_env="ZAI_API_KEY",
            openai_base_url="https://api.z.ai/api/coding/paas/v4/",
        )
    )
    client = OpenAIClient(config)
    stub = _StubCompletions("pong")
    client._client = type("Client", (), {"chat": type("Chat", (), {"completions": stub})()})()
    client.chat([{"role": "user", "content": "hi"}])
    assert stub.calls[0]["extra_body"] == {"thinking": {"type": "disabled"}}
