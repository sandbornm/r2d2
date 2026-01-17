"""Ghidra Bridge RPC client for interactive Ghidra analysis.

This module provides a client wrapper for ghidra_bridge, enabling persistent
RPC connections to a running Ghidra instance for richer reverse engineering
data (decompilation, types, cross-references).

The bridge server must be started externally in Ghidra's Script Manager by
running ghidra_bridge_server_background.py.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import ghidra_bridge

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True, frozen=True)
class DecompiledFunction:
    """Decompiled function data from Ghidra."""

    name: str
    address: int
    signature: str
    decompiled_c: str
    parameters: list[dict[str, Any]]
    return_type: str
    calling_convention: str | None = None


@dataclass(slots=True, frozen=True)
class GhidraTypeInfo:
    """Type information from Ghidra's data type manager."""

    name: str
    category: str
    size: int
    kind: str  # "struct", "enum", "typedef", "pointer", "array", "primitive"
    members: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True, frozen=True)
class CrossReference:
    """Cross-reference information."""

    from_address: int
    to_address: int
    ref_type: str  # "CALL", "DATA", "JUMP", etc.
    from_function: str | None = None
    to_function: str | None = None


@dataclass
class GhidraBridgeClient:
    """RPC client wrapper for ghidra_bridge.

    This client manages connections to a Ghidra bridge server and provides
    methods for extracting analysis data via RPC.
    """

    host: str = "127.0.0.1"
    port: int = 13100
    timeout: int = 30

    _bridge: "ghidra_bridge.GhidraBridge | None" = field(default=None, repr=False)
    _connected: bool = field(default=False, repr=False)

    def connect(self) -> bool:
        """Establish connection to the Ghidra bridge server.

        Returns:
            True if connection succeeded, False otherwise.
        """
        if self._connected and self._bridge is not None:
            return True

        try:
            import ghidra_bridge

            self._bridge = ghidra_bridge.GhidraBridge(
                connect_to_host=self.host,
                connect_to_port=self.port,
                response_timeout=self.timeout,
            )
            self._connected = True
            _LOGGER.info("Connected to Ghidra bridge at %s:%d", self.host, self.port)
            return True
        except ImportError:
            _LOGGER.warning("ghidra_bridge module not available")
            return False
        except Exception as exc:
            _LOGGER.warning("Failed to connect to Ghidra bridge: %s", exc)
            self._connected = False
            self._bridge = None
            return False

    def is_connected(self) -> bool:
        """Check if the client is connected to the bridge server."""
        if not self._connected or self._bridge is None:
            return False

        # Verify connection is still alive with a simple ping
        try:
            # Use remote_import to verify connection
            self._bridge.remote_import("__main__")
            return True
        except Exception:
            self._connected = False
            return False

    def disconnect(self) -> None:
        """Disconnect from the Ghidra bridge server."""
        self._bridge = None
        self._connected = False
        _LOGGER.debug("Disconnected from Ghidra bridge")

    def get_current_program_name(self) -> str | None:
        """Get the name of the currently loaded program in Ghidra.

        Returns:
            Program name if a program is loaded, None otherwise.
        """
        if not self.is_connected() or self._bridge is None:
            return None

        try:
            currentProgram = self._bridge.remote_import("__main__").currentProgram
            if currentProgram:
                return str(currentProgram.getName())
            return None
        except Exception as exc:
            _LOGGER.debug("Failed to get current program name: %s", exc)
            return None

    def get_current_program_path(self) -> str | None:
        """Get the executable path of the currently loaded program.

        Returns:
            Executable path if available, None otherwise.
        """
        if not self.is_connected() or self._bridge is None:
            return None

        try:
            currentProgram = self._bridge.remote_import("__main__").currentProgram
            if currentProgram:
                return str(currentProgram.getExecutablePath())
            return None
        except Exception as exc:
            _LOGGER.debug("Failed to get current program path: %s", exc)
            return None

    def is_binary_loaded(self, binary: Path) -> bool:
        """Check if the specified binary is currently loaded in Ghidra.

        Args:
            binary: Path to the binary file.

        Returns:
            True if the binary is loaded, False otherwise.
        """
        current_path = self.get_current_program_path()
        if not current_path:
            return False

        # Compare resolved paths
        try:
            return Path(current_path).resolve() == binary.resolve()
        except Exception:
            return current_path == str(binary)

    def get_functions(self, limit: int = 200) -> list[dict[str, Any]]:
        """Get list of functions from the current program.

        Args:
            limit: Maximum number of functions to return.

        Returns:
            List of function dictionaries with name, address, size, etc.
        """
        if not self.is_connected() or self._bridge is None:
            return []

        try:
            main_module = self._bridge.remote_import("__main__")
            currentProgram = main_module.currentProgram

            if not currentProgram:
                return []

            fm = currentProgram.getFunctionManager()
            funcs = fm.getFunctions(True)

            results = []
            count = 0
            for func in funcs:
                if count >= limit:
                    break
                try:
                    results.append({
                        "name": func.getName(),
                        "address": func.getEntryPoint().getOffset(),
                        "size": func.getBody().getNumAddresses(),
                        "signature": func.getSignature().getPrototypeString(),
                        "calling_convention": func.getCallingConventionName(),
                        "is_thunk": func.isThunk(),
                        "comment": func.getComment(),
                    })
                    count += 1
                except Exception:
                    continue

            return results
        except Exception as exc:
            _LOGGER.warning("Failed to get functions: %s", exc)
            return []

    def decompile_function(self, address: int) -> DecompiledFunction | None:
        """Decompile a single function at the given address.

        Args:
            address: Entry point address of the function.

        Returns:
            DecompiledFunction with decompiled C code, or None on failure.
        """
        if not self.is_connected() or self._bridge is None:
            return None

        try:
            main_module = self._bridge.remote_import("__main__")
            currentProgram = main_module.currentProgram

            if not currentProgram:
                return None

            # Import Ghidra classes
            DecompInterface = self._bridge.remote_import(
                "ghidra.app.decompiler"
            ).DecompInterface
            ConsoleTaskMonitor = self._bridge.remote_import(
                "ghidra.util.task"
            ).ConsoleTaskMonitor

            # Get function at address
            addr_factory = currentProgram.getAddressFactory()
            addr_obj = addr_factory.getAddress(hex(address))
            fm = currentProgram.getFunctionManager()
            func = fm.getFunctionContaining(addr_obj)

            if not func:
                return None

            # Decompile
            decomp = DecompInterface()
            decomp.openProgram(currentProgram)

            try:
                results = decomp.decompileFunction(func, 30, ConsoleTaskMonitor())
                if not results or not results.decompileCompleted():
                    return None

                decompiled_func = results.getDecompiledFunction()
                high_func = results.getHighFunction()

                params = []
                if high_func:
                    local_map = high_func.getLocalSymbolMap()
                    if local_map:
                        for i, param in enumerate(local_map.getSymbols()):
                            if param.isParameter():
                                params.append({
                                    "name": param.getName(),
                                    "type": str(param.getDataType()),
                                    "index": i,
                                })

                return DecompiledFunction(
                    name=func.getName(),
                    address=func.getEntryPoint().getOffset(),
                    signature=func.getSignature().getPrototypeString(),
                    decompiled_c=decompiled_func.getC() if decompiled_func else "",
                    parameters=params,
                    return_type=str(func.getReturnType()),
                    calling_convention=func.getCallingConventionName(),
                )
            finally:
                decomp.dispose()

        except Exception as exc:
            _LOGGER.warning("Failed to decompile function at 0x%x: %s", address, exc)
            return None

    def batch_decompile(
        self, addresses: list[int], limit: int = 20
    ) -> list[DecompiledFunction]:
        """Decompile multiple functions in batch.

        Args:
            addresses: List of function entry point addresses.
            limit: Maximum number of functions to decompile.

        Returns:
            List of successfully decompiled functions.
        """
        if not self.is_connected():
            return []

        results = []
        for addr in addresses[:limit]:
            func = self.decompile_function(addr)
            if func:
                results.append(func)

        return results

    def get_types(self, limit: int = 100) -> list[GhidraTypeInfo]:
        """Get data types from Ghidra's data type manager.

        Args:
            limit: Maximum number of types to return.

        Returns:
            List of GhidraTypeInfo objects.
        """
        if not self.is_connected() or self._bridge is None:
            return []

        try:
            main_module = self._bridge.remote_import("__main__")
            currentProgram = main_module.currentProgram

            if not currentProgram:
                return []

            # Import type classes
            data_module = self._bridge.remote_import("ghidra.program.model.data")
            Structure = data_module.Structure
            Enum = data_module.Enum
            TypeDef = data_module.TypeDef
            Pointer = data_module.Pointer
            Array = data_module.Array

            dtm = currentProgram.getDataTypeManager()
            results = []
            count = 0

            for dt in dtm.getAllDataTypes():
                if count >= limit:
                    break

                try:
                    kind = "primitive"
                    members = []

                    if isinstance(dt, Structure):
                        kind = "struct"
                        for comp in dt.getComponents():
                            members.append({
                                "name": comp.getFieldName() or f"field_{comp.getOffset()}",
                                "type": str(comp.getDataType()),
                                "offset": comp.getOffset(),
                                "size": comp.getLength(),
                            })
                    elif isinstance(dt, Enum):
                        kind = "enum"
                        for name in dt.getNames():
                            members.append({
                                "name": name,
                                "value": dt.getValue(name),
                            })
                    elif isinstance(dt, TypeDef):
                        kind = "typedef"
                    elif isinstance(dt, Pointer):
                        kind = "pointer"
                    elif isinstance(dt, Array):
                        kind = "array"

                    results.append(GhidraTypeInfo(
                        name=dt.getName(),
                        category=str(dt.getCategoryPath()),
                        size=dt.getLength(),
                        kind=kind,
                        members=members,
                    ))
                    count += 1
                except Exception:
                    continue

            return results
        except Exception as exc:
            _LOGGER.warning("Failed to get types: %s", exc)
            return []

    def get_xrefs_to(self, address: int) -> list[CrossReference]:
        """Get cross-references TO the given address.

        Args:
            address: Target address to find references to.

        Returns:
            List of CrossReference objects pointing to this address.
        """
        if not self.is_connected() or self._bridge is None:
            return []

        try:
            main_module = self._bridge.remote_import("__main__")
            currentProgram = main_module.currentProgram

            if not currentProgram:
                return []

            addr_factory = currentProgram.getAddressFactory()
            addr_obj = addr_factory.getAddress(hex(address))
            ref_mgr = currentProgram.getReferenceManager()
            fm = currentProgram.getFunctionManager()

            results = []
            for ref in ref_mgr.getReferencesTo(addr_obj):
                try:
                    from_addr = ref.getFromAddress().getOffset()
                    from_func = fm.getFunctionContaining(ref.getFromAddress())
                    to_func = fm.getFunctionContaining(addr_obj)

                    results.append(CrossReference(
                        from_address=from_addr,
                        to_address=address,
                        ref_type=str(ref.getReferenceType()),
                        from_function=from_func.getName() if from_func else None,
                        to_function=to_func.getName() if to_func else None,
                    ))
                except Exception:
                    continue

            return results
        except Exception as exc:
            _LOGGER.warning("Failed to get xrefs to 0x%x: %s", address, exc)
            return []

    def get_xrefs_from(self, address: int) -> list[CrossReference]:
        """Get cross-references FROM the given address.

        Args:
            address: Source address to find references from.

        Returns:
            List of CrossReference objects originating from this address.
        """
        if not self.is_connected() or self._bridge is None:
            return []

        try:
            main_module = self._bridge.remote_import("__main__")
            currentProgram = main_module.currentProgram

            if not currentProgram:
                return []

            addr_factory = currentProgram.getAddressFactory()
            addr_obj = addr_factory.getAddress(hex(address))
            ref_mgr = currentProgram.getReferenceManager()
            fm = currentProgram.getFunctionManager()

            results = []
            for ref in ref_mgr.getReferencesFrom(addr_obj):
                try:
                    to_addr = ref.getToAddress().getOffset()
                    from_func = fm.getFunctionContaining(addr_obj)
                    to_func = fm.getFunctionContaining(ref.getToAddress())

                    results.append(CrossReference(
                        from_address=address,
                        to_address=to_addr,
                        ref_type=str(ref.getReferenceType()),
                        from_function=from_func.getName() if from_func else None,
                        to_function=to_func.getName() if to_func else None,
                    ))
                except Exception:
                    continue

            return results
        except Exception as exc:
            _LOGGER.warning("Failed to get xrefs from 0x%x: %s", address, exc)
            return []

    def get_xrefs_for_functions(
        self, addresses: list[int], limit: int = 10
    ) -> dict[str, dict[str, list[dict[str, Any]]]]:
        """Get cross-references for multiple function addresses.

        Args:
            addresses: List of function addresses.
            limit: Maximum number of addresses to process.

        Returns:
            Dict mapping hex addresses to {"to": [...], "from": [...]} xref lists.
        """
        if not self.is_connected():
            return {}

        xref_map: dict[str, dict[str, list[dict[str, Any]]]] = {}

        for addr in addresses[:limit]:
            addr_key = f"0x{addr:x}"
            to_refs = self.get_xrefs_to(addr)
            from_refs = self.get_xrefs_from(addr)

            xref_map[addr_key] = {
                "to": [
                    {
                        "from_address": f"0x{r.from_address:x}",
                        "ref_type": r.ref_type,
                        "from_function": r.from_function,
                    }
                    for r in to_refs
                ],
                "from": [
                    {
                        "to_address": f"0x{r.to_address:x}",
                        "ref_type": r.ref_type,
                        "to_function": r.to_function,
                    }
                    for r in from_refs
                ],
            }

        return xref_map

    def get_strings(self, limit: int = 200) -> list[dict[str, Any]]:
        """Get defined strings from the current program.

        Args:
            limit: Maximum number of strings to return.

        Returns:
            List of string dictionaries with address, value, and length.
        """
        if not self.is_connected() or self._bridge is None:
            return []

        try:
            main_module = self._bridge.remote_import("__main__")
            currentProgram = main_module.currentProgram

            if not currentProgram:
                return []

            DefinedDataIterator = self._bridge.remote_import(
                "ghidra.program.util"
            ).DefinedDataIterator

            results = []
            count = 0

            for data in DefinedDataIterator.definedStrings(currentProgram):
                if count >= limit:
                    break

                try:
                    value = data.getValue()
                    if value:
                        results.append({
                            "address": data.getAddress().getOffset(),
                            "value": str(value),
                            "length": data.getLength(),
                            "type": str(data.getDataType()),
                        })
                        count += 1
                except Exception:
                    continue

            return results
        except Exception as exc:
            _LOGGER.warning("Failed to get strings: %s", exc)
            return []


__all__ = [
    "GhidraBridgeClient",
    "DecompiledFunction",
    "GhidraTypeInfo",
    "CrossReference",
]
