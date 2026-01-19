"""Analysis adapter implementations."""

from .angr import AngrAdapter
from .autoprofile import AutoProfileAdapter
from .capstone import CapstoneAdapter
from .dwarf import DWARFAdapter
from .frida import FridaAdapter
from .gef import GEFAdapter
from .ghidra import GhidraAdapter
from .ghidra_bridge_client import (
    CrossReference,
    DecompiledFunction,
    GhidraBridgeClient,
    GhidraTypeInfo,
)
from .libmagic import LibmagicAdapter
from .radare2 import Radare2Adapter

__all__ = [
    "AngrAdapter",
    "AutoProfileAdapter",
    "CapstoneAdapter",
    "CrossReference",
    "DecompiledFunction",
    "DWARFAdapter",
    "FridaAdapter",
    "GEFAdapter",
    "GhidraAdapter",
    "GhidraBridgeClient",
    "GhidraTypeInfo",
    "LibmagicAdapter",
    "Radare2Adapter",
]
