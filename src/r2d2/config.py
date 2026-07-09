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
TRUE_ENV_VALUES = {"1", "true", "yes", "on"}
FALSE_ENV_VALUES = {"0", "false", "no", "off"}


def _get_env(*names: str) -> str | None:
    """Return the first configured environment variable from a small alias set."""
    for name in names:
        value = os.getenv(name)
        if value is not None:
            return value
    return None


def _parse_env_bool(value: str) -> bool | None:
    normalized = value.strip().lower()
    if normalized in TRUE_ENV_VALUES:
        return True
    if normalized in FALSE_ENV_VALUES:
        return False
    return None


class LLMSettings(BaseModel):
    provider: str = "ollama"
    model: str = "gemma3:4b"
    api_key_env: str = "ANTHROPIC_API_KEY"
    fallback_provider: str | None = "openai"
    fallback_model: str | None = "gpt-4o"
    fallback_api_key_env: str | None = "OPENAI_API_KEY"
    enable_fallback: bool = False  # Disabled by default - user enables if needed
    max_tokens: int = 8192
    temperature: float = 0.1
    base_url: str = "http://127.0.0.1:11434"
    compact_context: bool = True
    context_budget_chars: int = 24000


class AnalysisSettings(BaseModel):
    auto_analyze: bool = True
    max_binary_size: str = "200MB"
    timeout_quick: int = 5
    timeout_deep: int = 60
    enable_angr: bool = True  # Symbolic execution - skipped if not available
    enable_ghidra: bool = True  # Decompilation - skipped if not available
    enable_frida: bool = True  # Dynamic instrumentation - skipped if not available
    enable_gef: bool = True  # GDB+GEF in Docker - skipped if not available
    gef_timeout: int = 60
    gef_max_instructions: int = 10000
    require_elf: bool = False
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


class UISettings(BaseModel):
    show_compiler: bool = False


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


class MCPServerSettings(BaseModel):
    enabled: bool = True
    description: str = ""
    transport: str = "http"
    url: str | None = None
    fallback_urls: list[str] = Field(default_factory=list)
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    start_command: list[str] = Field(default_factory=list)
    working_dir: str | None = None
    health_path: str | None = None
    capabilities_path: str | None = None
    timeout: float = 1.5
    install_hint: str | None = None


class MCPSettings(BaseModel):
    ghidra_mcp: MCPServerSettings = Field(
        default_factory=lambda: MCPServerSettings(
            description="GhidraMCP static analysis HTTP API",
            transport="http",
            url="http://127.0.0.1:8080",
            fallback_urls=["http://127.0.0.1:18080"],
            health_path="/methods",
            capabilities_path="/methods",
            install_hint="Start Ghidra with the GhidraMCP plugin enabled, then load the target program.",
        )
    )
    ghidra_gdb: MCPServerSettings = Field(
        default_factory=lambda: MCPServerSettings(
            description="GhidraMCP GDB/Docker dynamic analysis API",
            transport="http",
            url="http://127.0.0.1:5051",
            command="docker",
            start_command=["docker", "compose", "up", "-d", "--build"],
            working_dir="../GhidraMCP/docker",
            health_path="/health",
            install_hint="Run the GhidraMCP docker service from the sibling GhidraMCP/docker directory.",
        )
    )
    angr_mcp: MCPServerSettings = Field(
        default_factory=lambda: MCPServerSettings(
            description="angr_mcp streamable HTTP server",
            transport="streamable-http",
            url="http://127.0.0.1:8770/mcp",
            command="angr-mcp-dev-server",
            args=["--transport", "streamable-http", "--host", "127.0.0.1", "--port", "8770"],
            start_command=[
                "uv",
                "run",
                "angr-mcp-dev-server",
                "--transport",
                "streamable-http",
                "--host",
                "127.0.0.1",
                "--port",
                "8770",
            ],
            working_dir="../angr_mcp",
            install_hint="Run the streamable HTTP dev server from the sibling angr_mcp checkout.",
        )
    )

    def configured_servers(self) -> dict[str, MCPServerSettings]:
        return {
            "ghidra_mcp": self.ghidra_mcp,
            "ghidra_gdb": self.ghidra_gdb,
            "angr_mcp": self.angr_mcp,
        }


class AppConfig(BaseModel):
    llm: LLMSettings = Field(default_factory=LLMSettings)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)
    performance: PerformanceSettings = Field(default_factory=PerformanceSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    ui: UISettings = Field(default_factory=UISettings)
    ghidra: GhidraSettings = Field(default_factory=GhidraSettings)
    mcp: MCPSettings = Field(default_factory=MCPSettings)
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
    if "ui" in data:
        config.ui = UISettings.model_validate(data["ui"])
    if "ghidra" in data:
        ghidra_data = dict(data["ghidra"])
        # Handle empty string install_dir - treat as None so env var can apply
        if ghidra_data.get("install_dir") == "":
            ghidra_data["install_dir"] = None
        config.ghidra = GhidraSettings.model_validate(ghidra_data)
    if "mcp" in data:
        config.mcp = MCPSettings.model_validate(data["mcp"])

    # Environment variable overrides (highest precedence)
    env_install_dir = os.getenv("GHIDRA_INSTALL_DIR")
    if env_install_dir:
        config.ghidra.install_dir = Path(env_install_dir).expanduser()

    env_api_key = os.getenv(config.llm.api_key_env)
    if env_api_key:
        config.raw.setdefault("llm", {})
        config.raw["llm"]["api_key_present"] = True

    env_show_compiler = _get_env("R2D2_SHOW_COMPILER", "r2d2_show_compiler")
    if env_show_compiler is not None:
        parsed_show_compiler = _parse_env_bool(env_show_compiler)
        if parsed_show_compiler is not None:
            config.ui.show_compiler = parsed_show_compiler

    return config
