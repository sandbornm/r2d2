"""Analysis adapter implementations."""

from .angr import AngrAdapter
from .angr_mcp import AngrMCPAdapter
from .autoprofile import AutoProfileAdapter
from .capstone import CapstoneAdapter
from .dwarf import DWARFAdapter
from .frida import FridaAdapter
from .firmware import FirmwareAdapter
from .gef import GEFAdapter
from .ghidra import GhidraAdapter
from .ghidra_bridge_client import (
    CrossReference,
    DecompiledFunction,
    GhidraBridgeClient,
    GhidraTypeInfo,
)
from .ghidra_mcp import GhidraGDBMCPAdapter
from .libmagic import LibmagicAdapter
from .radare2 import Radare2Adapter

__all__ = [
    "AngrAdapter",
    "AngrMCPAdapter",
    "AutoProfileAdapter",
    "CapstoneAdapter",
    "CrossReference",
    "DecompiledFunction",
    "DWARFAdapter",
    "FirmwareAdapter",
    "FridaAdapter",
    "GEFAdapter",
    "GhidraAdapter",
    "GhidraGDBMCPAdapter",
    "GhidraBridgeClient",
    "GhidraTypeInfo",
    "LibmagicAdapter",
    "Radare2Adapter",
]
