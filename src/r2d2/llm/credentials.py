"""Resolve cloud LLM keys from named env vars. Never read secrets from toml."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..config import AppConfig

OPENAI_COMPAT_PROVIDERS = frozenset({"openai", "glm", "zai", "z.ai", "zhipu", "bigmodel"})
ZAI_BASE_URL = "https://api.z.ai/api/paas/v4"
BIGMODEL_BASE_URL = "https://open.bigmodel.cn/api/paas/v4"
DEFAULT_GLM_MODEL = "glm-5.2"
_DEFAULT_OLLAMA_HOST = "11434"
REMOTE_KEY_HOSTS = ("api.openai.com", "api.z.ai", "open.bigmodel.cn")

# First match wins after the overlay's api_key_env / fallback_api_key_env.
CLOUD_KEY_ENVS = (
    "GLM_API_KEY",
    "ZHIPUAI_API_KEY",
    "ZHIPU_API_KEY",
    "ZAI_API_KEY",
    "XAI_API_KEY",
    "OPENAI_API_KEY",
)
ZAI_KEY_ENVS = frozenset({"ZAI_API_KEY"})
BIGMODEL_KEY_ENVS = frozenset({"GLM_API_KEY", "ZHIPUAI_API_KEY", "ZHIPU_API_KEY"})
_LOCAL_DEFAULT_MODELS = frozenset({"", "gemma3:4b", "gemma4:latest", "gemma3:12b", "gemma2:9b"})


def is_openai_compat(provider: str | None) -> bool:
    return (provider or "").lower() in OPENAI_COMPAT_PROVIDERS


def is_glm_family(provider: str | None) -> bool:
    return (provider or "").lower() in {"glm", "zai", "z.ai", "zhipu", "bigmodel"}


def resolve_llm_api_key(config: AppConfig) -> tuple[str | None, str | None]:
    """Return (key, env_name). Prefer the named overlay env, then GLM/Z.ai aliases."""
    names: list[str] = []
    if is_openai_compat(config.llm.provider) and config.llm.api_key_env:
        names.append(config.llm.api_key_env)
    if config.llm.fallback_api_key_env:
        names.append(config.llm.fallback_api_key_env)
    names.extend(CLOUD_KEY_ENVS)
    seen: set[str] = set()
    for name in names:
        if not name or name in seen:
            continue
        seen.add(name)
        value = os.getenv(name)
        if value:
            return value, name
    return None, names[0] if names else "GLM_API_KEY"


def requires_api_key(base_url: str | None) -> bool:
    if not base_url:
        return True
    lowered = base_url.lower()
    return any(host in lowered for host in REMOTE_KEY_HOSTS)


def resolve_openai_base_url(config: AppConfig, key_env: str | None = None) -> str | None:
    """Return an OpenAI-compatible base URL, or None for the official OpenAI host."""
    explicit = getattr(config.llm, "openai_base_url", None)
    if explicit:
        return explicit.rstrip("/")

    provider = (config.llm.provider or "").lower()
    if is_glm_family(provider):
        env_name = key_env
        if env_name is None:
            _, env_name = resolve_llm_api_key(config)
        if env_name in ZAI_KEY_ENVS or (not env_name and os.getenv("ZAI_API_KEY")):
            return ZAI_BASE_URL
        if env_name in BIGMODEL_KEY_ENVS:
            return BIGMODEL_BASE_URL
        if os.getenv("ZAI_API_KEY"):
            return ZAI_BASE_URL
        return BIGMODEL_BASE_URL

    base = (config.llm.base_url or "").rstrip("/")
    if provider == "openai" and base and _DEFAULT_OLLAMA_HOST not in base:
        return base
    return None


def apply_glm_defaults(config: AppConfig) -> None:
    """Fill model/base URL when the provider is a GLM family name."""
    if not is_glm_family(config.llm.provider):
        return
    if (config.llm.model or "") in _LOCAL_DEFAULT_MODELS:
        config.llm.model = DEFAULT_GLM_MODEL
    if config.llm.api_key_env in {"", "ANTHROPIC_API_KEY"}:
        if os.getenv("ZAI_API_KEY") and not any(os.getenv(name) for name in BIGMODEL_KEY_ENVS):
            config.llm.api_key_env = "ZAI_API_KEY"
        else:
            config.llm.api_key_env = "GLM_API_KEY"
    if not config.llm.openai_base_url:
        config.llm.openai_base_url = resolve_openai_base_url(config)


def unused_glm_key_hint(config: AppConfig) -> str | None:
    """Headless hint when a GLM key is set but the provider still points at Ollama."""
    if is_openai_compat(config.llm.provider):
        return None
    if not any(os.getenv(name) for name in (*BIGMODEL_KEY_ENVS, *ZAI_KEY_ENVS)):
        return None
    present = next(name for name in (*BIGMODEL_KEY_ENVS, *ZAI_KEY_ENVS) if os.getenv(name))
    return (
        f"{present} is set but llm.provider={config.llm.provider!r}. "
        "export R2D2_LLM_PROVIDER=glm  (or copy config/glm.example.toml → config/local.toml)."
    )


__all__ = [
    "BIGMODEL_BASE_URL",
    "CLOUD_KEY_ENVS",
    "DEFAULT_GLM_MODEL",
    "ZAI_BASE_URL",
    "apply_glm_defaults",
    "is_glm_family",
    "is_openai_compat",
    "requires_api_key",
    "resolve_llm_api_key",
    "resolve_openai_base_url",
    "unused_glm_key_hint",
]
