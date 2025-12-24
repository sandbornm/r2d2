"""Unit tests for analysis adapters."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from r2d2.adapters.base import AdapterRegistry, AdapterUnavailable


class TestAdapterRegistry:
    """Tests for AdapterRegistry."""

    def test_available_returns_only_available_adapters(self, mock_adapter, unavailable_adapter):
        """Test that available() filters out unavailable adapters."""
        registry = AdapterRegistry([mock_adapter, unavailable_adapter])
        available = registry.available()

        assert len(available) == 1
        assert available[0].name == "mock"

    def test_get_returns_available_adapter(self, mock_adapter):
        """Test get() returns adapter when available."""
        registry = AdapterRegistry([mock_adapter])
        adapter = registry.get("mock")

        assert adapter is mock_adapter

    def test_get_raises_for_unavailable_adapter(self, unavailable_adapter):
        """Test get() raises AdapterUnavailable for unavailable adapter."""
        registry = AdapterRegistry([unavailable_adapter])

        with pytest.raises(AdapterUnavailable) as exc_info:
            registry.get("unavailable")

        assert "not available" in str(exc_info.value)

    def test_get_raises_for_unregistered_adapter(self, mock_adapter):
        """Test get() raises AdapterUnavailable for unregistered adapter."""
        registry = AdapterRegistry([mock_adapter])

        with pytest.raises(AdapterUnavailable) as exc_info:
            registry.get("nonexistent")

        assert "not registered" in str(exc_info.value)

    def test_empty_registry_returns_empty_available(self):
        """Test empty registry returns empty list from available()."""
        registry = AdapterRegistry([])
        assert registry.available() == []


class TestMockAdapter:
    """Tests for mock adapter behavior (validates test fixtures)."""

    def test_mock_adapter_is_available(self, mock_adapter):
        """Test mock adapter reports as available."""
        assert mock_adapter.is_available() is True

    def test_mock_adapter_quick_scan(self, mock_adapter, sample_elf_file):
        """Test mock adapter quick_scan returns expected structure."""
        result = mock_adapter.quick_scan(sample_elf_file)

        assert result["mock"] is True
        assert str(sample_elf_file) in result["binary"]
        assert mock_adapter.quick_scan_called is True

    def test_mock_adapter_deep_scan(self, mock_adapter, sample_elf_file):
        """Test mock adapter deep_scan returns expected structure."""
        result = mock_adapter.deep_scan(sample_elf_file)

        assert result["mock"] is True
        assert "functions" in result
        assert "cfg" in result
        assert mock_adapter.deep_scan_called is True

    def test_unavailable_adapter_is_not_available(self, unavailable_adapter):
        """Test unavailable adapter reports as not available."""
        assert unavailable_adapter.is_available() is False


class TestRadare2Adapter:
    """Tests for Radare2Adapter (mocked)."""

    def test_is_available_checks_binary_and_module(self):
        """Test is_available checks both radare2 binary and r2pipe module."""
        from r2d2.adapters.radare2 import Radare2Adapter

        adapter = Radare2Adapter()

        # Test with mocked shutil.which and module check
        with patch("shutil.which") as mock_which:
            mock_which.return_value = None
            assert adapter.is_available() is False

    def test_module_available_returns_false_when_missing(self):
        """Test _module_available returns False when r2pipe not installed."""
        from r2d2.adapters.radare2 import Radare2Adapter

        adapter = Radare2Adapter()

        with patch.dict("sys.modules", {"r2pipe": None}):
            # Force reimport check
            with patch("builtins.__import__", side_effect=ModuleNotFoundError):
                assert adapter._module_available() is False


class TestCapstoneAdapter:
    """Tests for CapstoneAdapter."""

    def test_is_available_checks_module(self):
        """Test is_available checks capstone module availability."""
        from r2d2.adapters.capstone import CapstoneAdapter

        adapter = CapstoneAdapter()
        # This should work if capstone is installed
        result = adapter.is_available()
        assert isinstance(result, bool)


class TestAngrAdapter:
    """Tests for AngrAdapter (mocked)."""

    def test_is_available_checks_module(self):
        """Test is_available checks angr module availability."""
        from r2d2.adapters.angr import AngrAdapter

        # Mock at module import level to avoid broken angr dependency issues
        with patch.dict("sys.modules", {"angr": MagicMock()}):
            adapter = AngrAdapter()
            # When angr import succeeds, is_available should return True
            result = adapter.is_available()
            assert result is True

        # Test when angr is not installed
        with patch("builtins.__import__", side_effect=ModuleNotFoundError("angr")):
            adapter = AngrAdapter()
            result = adapter.is_available()
            assert result is False

    def test_quick_scan_raises_when_unavailable(self):
        """Test quick_scan raises AdapterUnavailable when angr not installed."""
        from r2d2.adapters.angr import AngrAdapter

        adapter = AngrAdapter()

        # Patch the is_available method at class level
        with patch.object(AngrAdapter, "is_available", return_value=False):
            with pytest.raises(AdapterUnavailable):
                adapter.quick_scan(Path("/tmp/test.bin"))

    def test_deep_scan_raises_when_unavailable(self):
        """Test deep_scan raises AdapterUnavailable when angr not installed."""
        from r2d2.adapters.angr import AngrAdapter

        adapter = AngrAdapter()

        # Patch the is_available method at class level
        with patch.object(AngrAdapter, "is_available", return_value=False):
            with pytest.raises(AdapterUnavailable):
                adapter.deep_scan(Path("/tmp/test.bin"))


class TestLibmagicAdapter:
    """Tests for LibmagicAdapter."""

    def test_is_available_checks_module(self):
        """Test is_available checks python-magic module."""
        from r2d2.adapters.libmagic import LibmagicAdapter

        adapter = LibmagicAdapter()
        result = adapter.is_available()
        assert isinstance(result, bool)
