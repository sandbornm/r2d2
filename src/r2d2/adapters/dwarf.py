"""DWARF debug information parser using pyelftools."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .base import AdapterUnavailable

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class DWARFAdapter:
    """Extract DWARF debug information from ELF binaries."""

    name: str = "dwarf"
    _available: bool | None = field(default=None, repr=False)

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            from elftools.elf.elffile import ELFFile  # noqa: F401
            self._available = True
        except ImportError:
            self._available = False
        return self._available

    def quick_scan(self, binary: Path, **kwargs: Any) -> dict[str, Any]:
        """Quick scan: check if DWARF info is present."""
        if not self.is_available():
            raise AdapterUnavailable("pyelftools is not installed")

        from elftools.elf.elffile import ELFFile

        result: dict[str, Any] = {
            "has_dwarf": False,
            "dwarf_version": None,
            "compilation_units": 0,
            "debug_sections": [],
        }

        try:
            with open(binary, "rb") as f:
                elf = ELFFile(f)

                # Check for DWARF sections
                debug_sections = [
                    s.name for s in elf.iter_sections()
                    if s.name.startswith(".debug_") or s.name.startswith(".zdebug_")
                ]
                result["debug_sections"] = debug_sections
                result["has_dwarf"] = len(debug_sections) > 0

                if elf.has_dwarf_info():
                    dwarf = elf.get_dwarf_info()
                    result["has_dwarf"] = True

                    # Count compilation units
                    cu_count = 0
                    for cu in dwarf.iter_CUs():
                        cu_count += 1
                        if result["dwarf_version"] is None:
                            result["dwarf_version"] = cu.header.get("version")
                    result["compilation_units"] = cu_count

        except Exception as exc:
            _LOGGER.debug("DWARF quick scan failed: %s", exc)
            result["error"] = str(exc)

        return result

    def deep_scan(
        self, binary: Path, *, resource_tree: Any | None = None, **kwargs: Any
    ) -> dict[str, Any]:
        """Deep scan: extract full DWARF debug information."""
        if not self.is_available():
            raise AdapterUnavailable("pyelftools is not installed")

        from elftools.elf.elffile import ELFFile
        from elftools.dwarf.descriptions import describe_form_class

        result: dict[str, Any] = {
            "has_dwarf": False,
            "dwarf_version": None,
            "compilation_units": [],
            "functions": [],
            "variables": [],
            "types": [],
            "source_files": [],
            "line_programs": [],
        }

        try:
            with open(binary, "rb") as f:
                elf = ELFFile(f)

                if not elf.has_dwarf_info():
                    result["error"] = "No DWARF information found"
                    return result

                dwarf = elf.get_dwarf_info()
                result["has_dwarf"] = True

                # Process each compilation unit
                for cu in dwarf.iter_CUs():
                    cu_info = self._process_compilation_unit(cu, dwarf)
                    result["compilation_units"].append(cu_info)

                    if result["dwarf_version"] is None:
                        result["dwarf_version"] = cu.header.get("version")

                    # Collect functions, variables, types from this CU
                    result["functions"].extend(cu_info.get("functions", []))
                    result["variables"].extend(cu_info.get("variables", []))
                    result["types"].extend(cu_info.get("types", []))

                    # Collect source files
                    for src in cu_info.get("source_files", []):
                        if src not in result["source_files"]:
                            result["source_files"].append(src)

                # Extract line number information
                result["line_programs"] = self._extract_line_programs(dwarf)

        except Exception as exc:
            _LOGGER.exception("DWARF deep scan failed: %s", exc)
            result["error"] = str(exc)

        return result

    def _process_compilation_unit(self, cu: Any, dwarf: Any) -> dict[str, Any]:
        """Process a single compilation unit."""
        from elftools.dwarf.die import DIE

        cu_info: dict[str, Any] = {
            "offset": cu.cu_offset,
            "version": cu.header.get("version"),
            "unit_length": cu.header.get("unit_length"),
            "functions": [],
            "variables": [],
            "types": [],
            "source_files": [],
        }

        # Get the top DIE (compilation unit DIE)
        top_die = cu.get_top_DIE()
        if top_die is None:
            return cu_info

        # Extract compilation unit name
        cu_info["name"] = self._get_die_name(top_die)
        cu_info["producer"] = self._get_attr_string(top_die, "DW_AT_producer")
        cu_info["language"] = self._get_attr_value(top_die, "DW_AT_language")
        cu_info["comp_dir"] = self._get_attr_string(top_die, "DW_AT_comp_dir")

        # Extract line program for source files
        try:
            line_program = dwarf.line_program_for_CU(cu)
            if line_program:
                header = line_program.header
                if hasattr(header, "file_entry"):
                    for file_entry in header.file_entry:
                        if hasattr(file_entry, "name"):
                            name = file_entry.name
                            if isinstance(name, bytes):
                                name = name.decode("utf-8", errors="replace")
                            cu_info["source_files"].append(name)
        except Exception as exc:
            _LOGGER.debug("Line program extraction failed: %s", exc)

        # Iterate through all DIEs in this CU
        for die in cu.iter_DIEs():
            if die.tag is None:
                continue

            if die.tag == "DW_TAG_subprogram":
                func = self._extract_function(die, cu)
                if func:
                    cu_info["functions"].append(func)
            elif die.tag == "DW_TAG_variable":
                var = self._extract_variable(die, cu)
                if var:
                    cu_info["variables"].append(var)
            elif die.tag in (
                "DW_TAG_base_type",
                "DW_TAG_typedef",
                "DW_TAG_structure_type",
                "DW_TAG_union_type",
                "DW_TAG_enumeration_type",
                "DW_TAG_pointer_type",
                "DW_TAG_array_type",
            ):
                type_info = self._extract_type(die, cu)
                if type_info:
                    cu_info["types"].append(type_info)

        return cu_info

    def _extract_function(self, die: Any, cu: Any) -> dict[str, Any] | None:
        """Extract function information from a DW_TAG_subprogram DIE."""
        name = self._get_die_name(die)
        if not name:
            return None

        func: dict[str, Any] = {
            "name": name,
            "offset": die.offset,
            "low_pc": self._get_attr_value(die, "DW_AT_low_pc"),
            "high_pc": self._get_attr_value(die, "DW_AT_high_pc"),
            "is_external": self._get_attr_value(die, "DW_AT_external", False),
            "is_inline": die.tag == "DW_TAG_inlined_subroutine",
            "decl_file": self._get_attr_value(die, "DW_AT_decl_file"),
            "decl_line": self._get_attr_value(die, "DW_AT_decl_line"),
            "parameters": [],
            "local_variables": [],
        }

        # Calculate size if high_pc is an offset
        if func["low_pc"] is not None and func["high_pc"] is not None:
            if isinstance(func["high_pc"], int) and func["high_pc"] < func["low_pc"]:
                func["size"] = func["high_pc"]
                func["high_pc"] = func["low_pc"] + func["high_pc"]
            else:
                func["size"] = func["high_pc"] - func["low_pc"]

        # Extract parameters and local variables from children
        if die.has_children:
            for child in die.iter_children():
                if child.tag == "DW_TAG_formal_parameter":
                    param = self._extract_parameter(child)
                    if param:
                        func["parameters"].append(param)
                elif child.tag == "DW_TAG_variable":
                    var = self._extract_variable(child, cu, is_local=True)
                    if var:
                        func["local_variables"].append(var)

        return func

    def _extract_parameter(self, die: Any) -> dict[str, Any] | None:
        """Extract parameter information from a DW_TAG_formal_parameter DIE."""
        name = self._get_die_name(die)
        return {
            "name": name or "(unnamed)",
            "offset": die.offset,
            "type_offset": self._get_attr_value(die, "DW_AT_type"),
            "location": self._get_location_description(die),
        }

    def _extract_variable(
        self, die: Any, cu: Any, is_local: bool = False
    ) -> dict[str, Any] | None:
        """Extract variable information from a DW_TAG_variable DIE."""
        name = self._get_die_name(die)
        if not name:
            return None

        return {
            "name": name,
            "offset": die.offset,
            "is_local": is_local,
            "type_offset": self._get_attr_value(die, "DW_AT_type"),
            "decl_file": self._get_attr_value(die, "DW_AT_decl_file"),
            "decl_line": self._get_attr_value(die, "DW_AT_decl_line"),
            "location": self._get_location_description(die),
            "is_external": self._get_attr_value(die, "DW_AT_external", False),
        }

    def _extract_type(self, die: Any, cu: Any) -> dict[str, Any] | None:
        """Extract type information from various type DIEs."""
        name = self._get_die_name(die)

        type_info: dict[str, Any] = {
            "name": name,
            "offset": die.offset,
            "tag": die.tag,
            "byte_size": self._get_attr_value(die, "DW_AT_byte_size"),
            "encoding": self._get_attr_value(die, "DW_AT_encoding"),
        }

        # For pointer/array types, get the base type
        if die.tag in ("DW_TAG_pointer_type", "DW_TAG_array_type", "DW_TAG_typedef"):
            type_info["base_type_offset"] = self._get_attr_value(die, "DW_AT_type")

        # For structures/unions, extract members
        if die.tag in ("DW_TAG_structure_type", "DW_TAG_union_type"):
            type_info["members"] = []
            if die.has_children:
                for child in die.iter_children():
                    if child.tag == "DW_TAG_member":
                        member = {
                            "name": self._get_die_name(child),
                            "offset": self._get_attr_value(
                                child, "DW_AT_data_member_location"
                            ),
                            "type_offset": self._get_attr_value(child, "DW_AT_type"),
                        }
                        type_info["members"].append(member)

        # For enumerations, extract enumerators
        if die.tag == "DW_TAG_enumeration_type":
            type_info["enumerators"] = []
            if die.has_children:
                for child in die.iter_children():
                    if child.tag == "DW_TAG_enumerator":
                        enumerator = {
                            "name": self._get_die_name(child),
                            "value": self._get_attr_value(child, "DW_AT_const_value"),
                        }
                        type_info["enumerators"].append(enumerator)

        return type_info

    def _extract_line_programs(self, dwarf: Any) -> list[dict[str, Any]]:
        """Extract line number program information."""
        line_programs: list[dict[str, Any]] = []

        for cu in dwarf.iter_CUs():
            try:
                line_program = dwarf.line_program_for_CU(cu)
                if line_program is None:
                    continue

                entries: list[dict[str, Any]] = []
                for entry in line_program.get_entries():
                    if entry.state is None:
                        continue
                    entries.append({
                        "address": entry.state.address,
                        "file": entry.state.file,
                        "line": entry.state.line,
                        "column": entry.state.column,
                        "is_stmt": entry.state.is_stmt,
                        "end_sequence": entry.state.end_sequence,
                    })

                if entries:
                    # Limit entries to avoid huge payloads
                    line_programs.append({
                        "cu_offset": cu.cu_offset,
                        "entries": entries[:500],
                        "total_entries": len(entries),
                    })
            except Exception as exc:
                _LOGGER.debug("Line program extraction failed for CU: %s", exc)

        return line_programs

    def _get_die_name(self, die: Any) -> str | None:
        """Get the name attribute from a DIE."""
        return self._get_attr_string(die, "DW_AT_name")

    def _get_attr_string(self, die: Any, attr_name: str) -> str | None:
        """Get a string attribute from a DIE."""
        try:
            attr = die.attributes.get(attr_name)
            if attr is None:
                return None
            value = attr.value
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            return str(value) if value else None
        except Exception:
            return None

    def _get_attr_value(self, die: Any, attr_name: str, default: Any = None) -> Any:
        """Get an attribute value from a DIE."""
        try:
            attr = die.attributes.get(attr_name)
            if attr is None:
                return default
            return attr.value
        except Exception:
            return default

    def _get_location_description(self, die: Any) -> str | None:
        """Get a human-readable location description."""
        try:
            attr = die.attributes.get("DW_AT_location")
            if attr is None:
                return None
            # For simplicity, just return a string representation
            return f"location_form={attr.form}"
        except Exception:
            return None


def get_address_to_source_map(
    dwarf_data: dict[str, Any],
) -> dict[int, dict[str, Any]]:
    """Build a mapping from addresses to source locations.

    This is useful for showing source file/line info in the disassembly view.
    """
    addr_map: dict[int, dict[str, Any]] = {}

    for lp in dwarf_data.get("line_programs", []):
        for entry in lp.get("entries", []):
            addr = entry.get("address")
            if addr is not None:
                addr_map[addr] = {
                    "file": entry.get("file"),
                    "line": entry.get("line"),
                    "column": entry.get("column"),
                    "is_stmt": entry.get("is_stmt"),
                }

    return addr_map


def get_function_symbols(dwarf_data: dict[str, Any]) -> dict[int, str]:
    """Build a mapping from addresses to function names.

    This supplements radare2's function detection with debug symbols.
    """
    func_map: dict[int, str] = {}

    for func in dwarf_data.get("functions", []):
        low_pc = func.get("low_pc")
        name = func.get("name")
        if low_pc is not None and name:
            func_map[low_pc] = name

    return func_map
