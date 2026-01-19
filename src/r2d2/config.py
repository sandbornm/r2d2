"""Configuration loading and modelling.

Configuration is loaded from:
1. config/default_config.toml (shipped defaults)
2. R2D2_CONFIG env var (optional custom config path)
3. Environment variables override specific settings:
   - GHIDRA_INSTALL_DIR: Path to Ghidra installation
   - ANTHROPIC_API_KEY / OPENAI_API_KEY: API keys
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "default_config.toml"


class LLMSettings(BaseModel):
    provider: str = "anthropic"
    model: str = "claude-opus-4-5"  # Default to Opus 4.5; user can override via UI
    api_key_env: str = "ANTHROPIC_API_KEY"
    fallback_provider: str | None = "openai"
    fallback_model: str | None = "gpt-4o"
    fallback_api_key_env: str | None = "OPENAI_API_KEY"
    enable_fallback: bool = False  # Disabled by default - user enables if needed
    max_tokens: int = 8192
    temperature: float = 0.1


class AnalysisSettings(BaseModel):
    auto_analyze: bool = True
    max_binary_size: str = "5MB"
    timeout_quick: int = 5
    timeout_deep: int = 60
    enable_angr: bool = True  # Symbolic execution - skipped if not available
    enable_ghidra: bool = True  # Decompilation - skipped if not available
    enable_frida: bool = True  # Dynamic instrumentation - skipped if not available
    enable_gef: bool = True  # GDB+GEF in Docker - skipped if not available
    gef_timeout: int = 60
    gef_max_instructions: int = 10000
    require_elf: bool = True
    # Radare2 profile: placeholder for future use. Intended: "analysis.quick" (aa),
    # "analysis.deep" (aaa), "analysis.full" (aaaa). Currently always uses aaa.
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
    use_bridge: bool = True  # Try bridge first - falls back to headless if unavailable
    bridge_host: str = "127.0.0.1"
    bridge_port: int = 13100
    bridge_timeout: int = 30
    install_dir: Path | None = None
    project_dir: Path = Field(default=Path("~/.local/share/r2d2/ghidra-projects").expanduser())
    max_decompile_functions: int = 20
    max_types: int = 100
    max_strings: int = 200


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
    """Load configuration from defaults and optional overrides.
    
    Config sources (in order of precedence, later overrides earlier):
    1. config/default_config.toml (project defaults)
    2. R2D2_CONFIG env var or config_path argument (optional custom config)
    3. Environment variables (GHIDRA_INSTALL_DIR, API keys)
    """
    load_dotenv()

    data: dict[str, Any] = {}
    
    # Load project defaults
    if DEFAULT_CONFIG_PATH.exists():
        data = _merge(data, _load_toml(DEFAULT_CONFIG_PATH))

    # Load custom config if specified via argument or R2D2_CONFIG env var
    custom_config = config_path
    if custom_config is None:
        env_config = os.getenv("R2D2_CONFIG")
        if env_config:
            custom_config = Path(env_config).expanduser()
    
    if custom_config and custom_config.exists():
        data = _merge(data, _load_toml(custom_config))

    config = AppConfig(raw=data)

    # Re-bind nested models from merged dict to capture overrides
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
        ghidra_data = dict(data["ghidra"])
        # Handle empty string install_dir - treat as None so env var can apply
        if ghidra_data.get("install_dir") == "":
            ghidra_data["install_dir"] = None
        config.ghidra = GhidraSettings.model_validate(ghidra_data)

    # Environment variable overrides (highest precedence)
    env_install_dir = os.getenv("GHIDRA_INSTALL_DIR")
    if env_install_dir:
        config.ghidra.install_dir = Path(env_install_dir).expanduser()

    env_api_key = os.getenv(config.llm.api_key_env)
    if env_api_key:
        config.raw.setdefault("llm", {})
        config.raw["llm"]["api_key_present"] = True

    return config
