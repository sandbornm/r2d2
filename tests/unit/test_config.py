"""Unit tests for configuration module."""

from pathlib import Path
from unittest.mock import patch
import os

import pytest

from r2d2.config import (
    AppConfig,
    AnalysisSettings,
    LLMSettings,
    StorageSettings,
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
        assert isinstance(config.ghidra, GhidraSettings)
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

        assert settings.provider == "anthropic"
        assert settings.model == "claude-opus-4-5"  # Default to Opus 4.5
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
        assert settings.require_elf is True
        assert settings.enable_angr is True
        assert settings.enable_ghidra is False
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


class TestGhidraSettings:
    """Tests for GhidraSettings."""

    def test_default_values(self):
        """Test GhidraSettings has sensible defaults."""
        settings = GhidraSettings()

        assert settings.use_bridge is False
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
""")

        config = load_config(config_path)

        assert config.llm.model == "test-model"
        assert config.analysis.timeout_quick == 10

    def test_load_config_honors_env_ghidra_dir(self, tmp_path):
        """Test GHIDRA_INSTALL_DIR env var is honored."""
        ghidra_dir = str(tmp_path / "ghidra")

        with patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": ghidra_dir}):
            config = load_config()

            assert config.ghidra.install_dir == Path(ghidra_dir)

    def test_load_config_without_user_config(self, tmp_path):
        """Test load_config works without user config file."""
        # Patch USER_CONFIG_PATH to a non-existent path
        with patch("r2d2.config.USER_CONFIG_PATH", tmp_path / "nonexistent.toml"):
            config = load_config()

            assert isinstance(config, AppConfig)
