"""Shared pytest fixtures for r2d2 tests."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Generator

import pytest

from r2d2.config import AppConfig, AnalysisSettings, LLMSettings, StorageSettings
from r2d2.environment.detectors import EnvironmentReport, ToolCheck
from r2d2.storage import ChatDAO, Database
from r2d2.analysis.resource_tree import BinaryResource, FunctionResource, Resource


# ============================================================================
# Path Fixtures
# ============================================================================

@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    """Return a temporary database path."""
    return tmp_path / "test_r2d2.db"


@pytest.fixture
def sample_elf_bytes() -> bytes:
    """Return minimal ELF header bytes."""
    # Minimal ELF header (64-bit little-endian)
    return (
        b'\x7fELF'                      # Magic
        b'\x02'                          # 64-bit
        b'\x01'                          # Little endian
        b'\x01'                          # ELF version
        b'\x00'                          # OS/ABI
        + b'\x00' * 8                    # Padding
        + b'\x02\x00'                    # Type: executable
        + b'\xb7\x00'                    # Machine: ARM64
        + b'\x01\x00\x00\x00'           # Version
        + b'\x00' * 48                   # Rest of header padding
    )


@pytest.fixture
def sample_elf_file(tmp_path: Path, sample_elf_bytes: bytes) -> Path:
    """Create a minimal ELF file for testing."""
    elf_path = tmp_path / "sample.elf"
    elf_path.write_bytes(sample_elf_bytes)
    return elf_path


@pytest.fixture
def sample_non_elf_file(tmp_path: Path) -> Path:
    """Create a non-ELF file for testing validation."""
    bin_path = tmp_path / "not_elf.bin"
    bin_path.write_bytes(b'\x00\x00\x00\x00NOTELF\x00\x00\x00\x00')
    return bin_path


# ============================================================================
# Configuration Fixtures
# ============================================================================

@pytest.fixture
def test_config(tmp_path: Path) -> AppConfig:
    """Return a test configuration with adapters disabled."""
    config = AppConfig()
    config.analysis = AnalysisSettings(
        enable_angr=False,
        enable_ghidra=False,
        require_elf=True,
        timeout_quick=5,
        timeout_deep=30,
    )
    config.storage = StorageSettings(
        database_path=tmp_path / "test.db",
        auto_migrate=True,
    )
    config.llm = LLMSettings(
        provider="anthropic",
        model="claude-sonnet-4-5",
        enable_fallback=False,
    )
    return config


@pytest.fixture
def minimal_config() -> AppConfig:
    """Return minimal configuration for unit tests."""
    return AppConfig()


# ============================================================================
# Environment Fixtures
# ============================================================================

@pytest.fixture
def mock_env_report() -> EnvironmentReport:
    """Return a mock environment report with tools unavailable."""
    return EnvironmentReport(
        python_version="3.11.0",
        uv_available=True,
        openai_key_present=False,
        tools=[
            ToolCheck(name="radare2", command="radare2", available=False),
            ToolCheck(name="libmagic", command="file", available=True),
            ToolCheck(name="angr", command="python -c 'import angr'", available=False),
        ],
        ghidra=None,
    )


@pytest.fixture
def full_env_report() -> EnvironmentReport:
    """Return an environment report with all tools available."""
    return EnvironmentReport(
        python_version="3.11.0",
        uv_available=True,
        openai_key_present=True,
        tools=[
            ToolCheck(name="radare2", command="radare2", available=True, version="5.8.0"),
            ToolCheck(name="libmagic", command="file", available=True, version="5.45"),
            ToolCheck(name="angr", command="python -c 'import angr'", available=True, version="9.2.0"),
            ToolCheck(name="capstone", command="python -c 'import capstone'", available=True, version="5.0.1"),
        ],
        ghidra=None,
    )


# ============================================================================
# Database Fixtures
# ============================================================================

@pytest.fixture
def test_database(tmp_db_path: Path) -> Generator[Database, None, None]:
    """Create and return a test database."""
    db = Database(tmp_db_path)
    yield db
    # Cleanup happens when tmp_path is removed


@pytest.fixture
def chat_dao(test_database: Database) -> ChatDAO:
    """Return a ChatDAO instance with test database."""
    return ChatDAO(test_database)


# ============================================================================
# Resource Tree Fixtures
# ============================================================================

@pytest.fixture
def sample_resource_tree() -> BinaryResource:
    """Create a sample resource tree for testing."""
    binary = BinaryResource(
        kind="binary",
        name="test.elf",
        path="/tmp/test.elf",
        architecture="ARM64",
    )

    # Add some function resources
    main_func = FunctionResource(
        kind="function",
        name="main",
        address=0x1000,
        size=256,
        metadata={"nargs": 2, "nlocals": 4},
    )

    helper_func = FunctionResource(
        kind="function",
        name="helper",
        address=0x1100,
        size=128,
        metadata={"nargs": 1, "nlocals": 2},
    )

    binary.add_child(main_func)
    binary.add_child(helper_func)

    return binary


@pytest.fixture
def empty_resource_tree() -> BinaryResource:
    """Create an empty resource tree."""
    return BinaryResource(
        kind="binary",
        name="empty.elf",
        path="/tmp/empty.elf",
        architecture=None,
    )


# ============================================================================
# Mock Adapter Fixtures
# ============================================================================

class MockAdapter:
    """Mock adapter for testing."""

    def __init__(self, name: str = "mock", available: bool = True):
        self.name = name
        self._available = available
        self.quick_scan_called = False
        self.deep_scan_called = False

    def is_available(self) -> bool:
        return self._available

    def quick_scan(self, binary: Path) -> dict:
        self.quick_scan_called = True
        return {
            "mock": True,
            "binary": str(binary),
            "info": {"type": "mock_binary"},
        }

    def deep_scan(self, binary: Path, **kwargs) -> dict:
        self.deep_scan_called = True
        return {
            "mock": True,
            "binary": str(binary),
            "functions": [],
            "cfg": {"nodes": [], "edges": []},
        }


@pytest.fixture
def mock_adapter() -> MockAdapter:
    """Return a mock adapter for testing."""
    return MockAdapter()


@pytest.fixture
def unavailable_adapter() -> MockAdapter:
    """Return an unavailable mock adapter."""
    return MockAdapter(name="unavailable", available=False)


# ============================================================================
# Analysis Result Fixtures
# ============================================================================

@pytest.fixture
def mock_radare2_quick_result() -> dict:
    """Return mock radare2 quick scan result."""
    return {
        "info": {
            "arch": "arm",
            "bits": 64,
            "os": "linux",
            "type": "elf",
            "machine": "ARM64",
            "endian": "little",
        },
        "headers": [],
        "imports": [
            {"name": "printf", "type": "func"},
            {"name": "exit", "type": "func"},
        ],
        "strings": [
            {"string": "Hello, World!", "offset": "0x1000"},
        ],
        "sections": [
            {"name": ".text", "size": 1024, "perm": "r-x"},
            {"name": ".data", "size": 256, "perm": "rw-"},
        ],
        "symbols": [],
        "entry_points": [{"offset": "0x400", "type": "program"}],
    }


@pytest.fixture
def mock_radare2_deep_result() -> dict:
    """Return mock radare2 deep scan result."""
    return {
        "functions": [
            {"name": "main", "offset": 0x1000, "size": 256, "nargs": 2, "nlocals": 4},
            {"name": "helper", "offset": 0x1100, "size": 128, "nargs": 1, "nlocals": 2},
        ],
        "function_count": 2,
        "xrefs": [],
        "xref_map": {},
        "cfg": [],
        "function_cfgs": [
            {
                "name": "main",
                "offset": "0x1000",
                "size": 256,
                "blocks": [
                    {
                        "offset": "0x1000",
                        "size": 64,
                        "disassembly": [
                            {"addr": "0x1000", "opcode": "push {fp, lr}", "bytes": "04e02de5"},
                            {"addr": "0x1004", "opcode": "add fp, sp, #4", "bytes": "04b08de2"},
                        ],
                    }
                ],
            }
        ],
        "disassembly": "",
        "entry_disassembly": None,
        "entry_function": None,
        "snippets": [],
    }


@pytest.fixture
def mock_angr_deep_result() -> dict:
    """Return mock angr deep scan result."""
    return {
        "active": 1,
        "found": 0,
        "arch": "AARCH64",
        "entry": "0x400",
        "cfg": {
            "nodes": [
                {
                    "addr": "0x1000",
                    "size": 64,
                    "function": "0x1000",
                    "function_name": "main",
                    "instruction_count": 8,
                    "disassembly": [
                        {"addr": "0x1000", "mnemonic": "stp", "op_str": "x29, x30, [sp, #-16]!"},
                        {"addr": "0x1004", "mnemonic": "mov", "op_str": "x29, sp"},
                    ],
                }
            ],
            "edges": [
                {"source": "0x1000", "target": "0x1040", "type": "fallthrough"},
            ],
            "node_count": 1,
            "edge_count": 1,
        },
        "functions": [
            {
                "addr": "0x1000",
                "name": "main",
                "size": 256,
                "is_plt": False,
                "is_syscall": False,
                "has_return": True,
                "block_count": 4,
            }
        ],
        "function_count": 1,
        "snippets": [],
    }
