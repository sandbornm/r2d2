"""Unit tests for configuration module."""

from pathlib import Path
from unittest.mock import patch
import os

from r2d2.config import (
    AppConfig,
    AnalysisSettings,
    LLMSettings,
    MCPServerSettings,
    MCPSettings,
    StorageSettings,
    UISettings,
    GhidraSettings,
    OutputSettings,
    PerformanceSettings,
    load_config,
    _merge,
)


class TestAppConfig:
    """Tests for AppConfig."""

    def test_default_config_has_expected_structure(self):
        """Test default AppConfig has all expected sections."""
        config = AppConfig()

        assert isinstance(config.llm, LLMSettings)
        assert isinstance(config.analysis, AnalysisSettings)
        assert isinstance(config.storage, StorageSettings)
        assert isinstance(config.ui, UISettings)
        assert isinstance(config.ghidra, GhidraSettings)
        assert isinstance(config.mcp, MCPSettings)
        assert isinstance(config.output, OutputSettings)
        assert isinstance(config.performance, PerformanceSettings)

    def test_verbosity_property_returns_output_verbosity(self):
        """Test verbosity property delegates to output.verbosity."""
        config = AppConfig()
        config.output.verbosity = "debug"

        assert config.verbosity == "debug"


class TestLLMSettings:
    """Tests for LLMSettings."""

    def test_default_values(self):
        """Test LLMSettings has sensible defaults."""
        settings = LLMSettings()

        assert settings.provider == "ollama"
        assert settings.model == "gemma3:4b"
        assert settings.base_url == "http://127.0.0.1:11434"
        assert settings.compact_context is True
        assert settings.enable_fallback is False  # Disabled by default
        assert settings.max_tokens > 0
        assert 0 <= settings.temperature <= 1

    def test_custom_values(self):
        """Test LLMSettings accepts custom values."""
        settings = LLMSettings(
            provider="openai",
            model="gpt-4o",
            enable_fallback=False,
            max_tokens=4096,
            temperature=0.5,
        )

        assert settings.provider == "openai"
        assert settings.model == "gpt-4o"
        assert settings.enable_fallback is False
        assert settings.max_tokens == 4096


class TestAnalysisSettings:
    """Tests for AnalysisSettings."""

    def test_default_values(self):
        """Test AnalysisSettings has sensible defaults."""
        settings = AnalysisSettings()

        assert settings.auto_analyze is True
        assert settings.require_elf is False
        assert settings.max_binary_size == "200MB"
        assert settings.enable_angr is True
        assert settings.enable_ghidra is True  # Defaults to True (falls back gracefully if unavailable)
        assert settings.timeout_quick > 0
        assert settings.timeout_deep > 0

    def test_disable_adapters(self):
        """Test adapters can be disabled."""
        settings = AnalysisSettings(
            enable_angr=False,
            enable_ghidra=False,
        )

        assert settings.enable_angr is False
        assert settings.enable_ghidra is False


class TestStorageSettings:
    """Tests for StorageSettings."""

    def test_default_database_path(self):
        """Test default database path is in user's data directory."""
        settings = StorageSettings()

        assert isinstance(settings.database_path, Path)
        assert "r2d2" in str(settings.database_path)

    def test_custom_database_path(self, tmp_path):
        """Test custom database path can be set."""
        custom_path = tmp_path / "custom.db"
        settings = StorageSettings(database_path=custom_path)

        assert settings.database_path == custom_path


class TestUISettings:
    """Tests for UI feature flags."""

    def test_compiler_hidden_by_default(self):
        settings = UISettings()

        assert settings.show_compiler is False


class TestGhidraSettings:
    """Tests for GhidraSettings."""

    def test_default_values(self):
        """Test GhidraSettings has sensible defaults."""
        settings = GhidraSettings()

        assert settings.use_bridge is True  # Defaults to True (falls back to headless if unavailable)
        assert settings.bridge_host == "127.0.0.1"
        assert settings.bridge_port == 13100
        assert settings.install_dir is None

    def test_bridge_configuration(self):
        """Test bridge settings can be configured."""
        settings = GhidraSettings(
            use_bridge=True,
            bridge_host="192.168.1.1",
            bridge_port=9999,
        )

        assert settings.use_bridge is True
        assert settings.bridge_host == "192.168.1.1"
        assert settings.bridge_port == 9999


class TestMCPSettings:
    """Tests for MCP connection settings."""

    def test_default_servers(self):
        """Test MCP defaults cover the expected analysis backends."""
        settings = MCPSettings()

        assert isinstance(settings.ghidra_mcp, MCPServerSettings)
        assert settings.ghidra_mcp.url == "http://127.0.0.1:8080"
        assert "http://127.0.0.1:18080" in settings.ghidra_mcp.fallback_urls
        assert settings.ghidra_mcp.health_path == "/methods"
        assert settings.ghidra_gdb.url == "http://127.0.0.1:5051"
        assert settings.ghidra_gdb.fallback_urls == []
        assert settings.ghidra_gdb.command == "docker"
        assert settings.ghidra_gdb.start_command == ["docker", "compose", "up", "-d", "--build"]
        assert settings.ghidra_gdb.working_dir == "../GhidraMCP/docker"
        assert settings.angr_mcp.transport == "streamable-http"
        assert settings.angr_mcp.url == "http://127.0.0.1:8770/mcp"
        assert settings.angr_mcp.command == "angr-mcp-dev-server"
        assert settings.angr_mcp.args == ["--transport", "streamable-http", "--host", "127.0.0.1", "--port", "8770"]
        assert settings.angr_mcp.start_command[0:3] == ["uv", "run", "angr-mcp-dev-server"]
        assert settings.angr_mcp.working_dir == "../angr_mcp"

    def test_configured_servers(self):
        """Test MCP server registry is stable for probes and health output."""
        settings = MCPSettings()

        assert set(settings.configured_servers()) == {"ghidra_mcp", "ghidra_gdb", "angr_mcp"}


class TestMerge:
    """Tests for _merge function."""

    def test_merge_flat_dicts(self):
        """Test merging flat dictionaries."""
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = _merge(base, override)

        assert result == {"a": 1, "b": 3, "c": 4}

    def test_merge_nested_dicts(self):
        """Test merging nested dictionaries."""
        base = {"outer": {"a": 1, "b": 2}}
        override = {"outer": {"b": 3, "c": 4}}
        result = _merge(base, override)

        assert result == {"outer": {"a": 1, "b": 3, "c": 4}}

    def test_merge_preserves_base(self):
        """Test merge doesn't modify base dictionary."""
        base = {"a": 1}
        override = {"a": 2}
        _merge(base, override)

        assert base == {"a": 1}

    def test_merge_deeply_nested(self):
        """Test merging deeply nested structures."""
        base = {"l1": {"l2": {"l3": {"a": 1}}}}
        override = {"l1": {"l2": {"l3": {"b": 2}}}}
        result = _merge(base, override)

        assert result == {"l1": {"l2": {"l3": {"a": 1, "b": 2}}}}


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_config_returns_app_config(self):
        """Test load_config returns an AppConfig instance."""
        config = load_config()

        assert isinstance(config, AppConfig)

    def test_load_config_from_custom_path(self, tmp_path):
        """Test load_config loads from custom path."""
        config_path = tmp_path / "custom_config.toml"
        config_path.write_text("""
[llm]
model = "test-model"

[analysis]
timeout_quick = 10

[mcp.angr_mcp]
url = "http://127.0.0.1:9999/mcp"
command = "custom-angr-mcp"
""")

        config = load_config(config_path)

        assert config.llm.model == "test-model"
        assert config.analysis.timeout_quick == 10
        assert config.mcp.angr_mcp.url == "http://127.0.0.1:9999/mcp"
        assert config.mcp.angr_mcp.command == "custom-angr-mcp"

    def test_load_config_honors_env_ghidra_dir(self, tmp_path):
        """Test GHIDRA_INSTALL_DIR env var is honored."""
        ghidra_dir = str(tmp_path / "ghidra")

        with patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": ghidra_dir}):
            config = load_config()

            assert config.ghidra.install_dir == Path(ghidra_dir)

    def test_load_config_honors_show_compiler_env_bool(self):
        """Test show_compiler accepts compact boolean environment values."""
        with patch.dict(os.environ, {"R2D2_SHOW_COMPILER": "1"}, clear=True):
            config = load_config()

            assert config.ui.show_compiler is True

    def test_load_config_honors_lowercase_show_compiler_env(self):
        """Test shell-friendly lowercase show_compiler env aliases are honored."""
        with patch.dict(os.environ, {"r2d2_show_compiler": "1"}, clear=True):
            config = load_config()

            assert config.ui.show_compiler is True

    def test_load_config_env_can_disable_show_compiler(self, tmp_path):
        """Test false-like environment values override config files."""
        config_path = tmp_path / "show_compiler.toml"
        config_path.write_text("""
[ui]
show_compiler = true
""")

        with patch.dict(os.environ, {"R2D2_SHOW_COMPILER": "0"}, clear=True):
            config = load_config(config_path)

            assert config.ui.show_compiler is False

    def test_load_config_without_custom_config(self):
        """Test load_config works without custom config file."""
        # When R2D2_CONFIG env var is not set and no config_path provided,
        # load_config should still return a valid AppConfig from defaults
        with patch.dict(os.environ, {"R2D2_CONFIG": ""}, clear=False):
            config = load_config()

            assert isinstance(config, AppConfig)
