"""Configuration loading and modelling."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "default_config.toml"
USER_CONFIG_PATH = Path("~/.config/r2d2/config.toml").expanduser()


class LLMSettings(BaseModel):
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-20250514"
    api_key_env: str = "ANTHROPIC_API_KEY"
    fallback_provider: str | None = "openai"
    fallback_model: str | None = "gpt-4o"
    fallback_api_key_env: str | None = "OPENAI_API_KEY"
    enable_fallback: bool = True
    max_tokens: int = 8192
    temperature: float = 0.1


class AnalysisSettings(BaseModel):
    auto_analyze: bool = True
    max_binary_size: str = "5MB"
    timeout_quick: int = 5
    timeout_deep: int = 60
    enable_angr: bool = True
    enable_ghidra: bool = False
    require_elf: bool = True
    default_radare_profile: str = "analysis.quick"
    enable_trajectory_recording: bool = True


class OutputSettings(BaseModel):
    format: str = "terminal"
    verbosity: str = "normal"
    save_artifacts: bool = True
    artifacts_dir: Path = Field(default=Path("~/.cache/r2d2").expanduser())


class PerformanceSettings(BaseModel):
    parallel_functions: int = 4
    cache_results: bool = True


class StorageSettings(BaseModel):
    database_path: Path = Field(default=Path("~/.local/share/r2d2/r2d2.db").expanduser())
    auto_migrate: bool = True


class GhidraSettings(BaseModel):
    use_bridge: bool = False
    bridge_host: str = "127.0.0.1"
    bridge_port: int = 13100
    install_dir: Path | None = None
    project_dir: Path = Field(default=Path("~/.local/share/r2d2/ghidra-projects").expanduser())


class AppConfig(BaseModel):
    llm: LLMSettings = Field(default_factory=LLMSettings)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    performance: PerformanceSettings = Field(default_factory=PerformanceSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    ghidra: GhidraSettings = Field(default_factory=GhidraSettings)
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def verbosity(self) -> str:
        return self.output.verbosity


def _load_toml(path: Path) -> dict[str, Any]:
    import tomllib

    with path.open("rb") as fh:
        return tomllib.load(fh)


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(config_path: Path | None = None) -> AppConfig:
    """Load configuration from defaults and optional user overrides."""

    load_dotenv()

    data: dict[str, Any] = {}
    if DEFAULT_CONFIG_PATH.exists():
        data = _merge(data, _load_toml(DEFAULT_CONFIG_PATH))

    resolved_path = config_path
    if resolved_path is None and USER_CONFIG_PATH.exists():
        resolved_path = USER_CONFIG_PATH

    if resolved_path and resolved_path.exists():
        data = _merge(data, _load_toml(resolved_path))

    config = AppConfig(raw=data)

    # Re-bind nested models from merged dict to capture overrides.
    if "llm" in data:
        config.llm = LLMSettings.model_validate(data["llm"])
    if "analysis" in data:
        config.analysis = AnalysisSettings.model_validate(data["analysis"])
    if "output" in data:
        config.output = OutputSettings.model_validate(data["output"])
    if "performance" in data:
        config.performance = PerformanceSettings.model_validate(data["performance"])
    if "storage" in data:
        config.storage = StorageSettings.model_validate(data["storage"])
    if "ghidra" in data:
        config.ghidra = GhidraSettings.model_validate(data["ghidra"])

    # Honor environment overrides for secrets and tool paths without
    # requiring users to edit their config manually.
    env_install_dir = os.getenv("GHIDRA_INSTALL_DIR")
    if not config.ghidra.install_dir and env_install_dir:
        config.ghidra.install_dir = Path(env_install_dir).expanduser()

    env_api_key = os.getenv(config.llm.api_key_env)
    if env_api_key:
        config.raw.setdefault("llm", {})
        config.raw["llm"]["api_key_present"] = True

    return config
