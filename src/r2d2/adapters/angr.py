"""Optional angr symbolic execution adapter with enhanced CFG extraction."""

from __future__ import annotations

import logging
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .base import AdapterUnavailable

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class AngrAdapter:
    name: str = "angr"

    def is_available(self) -> bool:
        try:
            import angr  # noqa: F401
        except ModuleNotFoundError:
            return False
        return True

    def _angr(self) -> types.ModuleType:
        try:
            import angr
        except ModuleNotFoundError as exc:  # pragma: no cover - import guard
            raise AdapterUnavailable("angr is not installed") from exc
        return angr

    def quick_scan(self, binary: Path) -> dict[str, Any]:
        if not self.is_available():
            raise AdapterUnavailable("angr is not installed")
        angr = self._angr()
        proj = angr.Project(str(binary), auto_load_libs=False)
        entry_state = proj.factory.entry_state()
        return {
            "entry": hex(entry_state.addr),
            "arch": str(proj.arch),
            "arch_name": proj.arch.name,
            "arch_bits": proj.arch.bits,
            "arch_endness": proj.arch.memory_endness,
        }

    def deep_scan(self, binary: Path, *, target: int | None = None) -> dict[str, Any]:
        if not self.is_available():
            raise AdapterUnavailable("angr is not installed")
        angr = self._angr()
        proj = angr.Project(str(binary), auto_load_libs=False)
        state = proj.factory.entry_state()
        simgr = proj.factory.simgr(state)
        if target is not None:
            simgr.explore(find=target)

        # Build comprehensive CFG with block details
        cfg_nodes: list[dict[str, Any]] = []
        cfg_edges: list[dict[str, str]] = []
        function_map: dict[int, dict[str, Any]] = {}
        block_snippets: list[dict[str, Any]] = []
        cfg_error: str | None = None
        total_nodes_available = 0
        node_limit = 300
        
        try:
            cfg_analysis = proj.analyses.CFGFast(
                normalize=True, 
                data_references=True,
                force_complete_scan=False,
            )
            
            # Extract functions first
            for func_addr, func in cfg_analysis.kb.functions.items():
                function_map[func_addr] = {
                    "addr": hex(func_addr),
                    "name": func.name or f"sub_{func_addr:x}",
                    "size": func.size,
                    "is_plt": func.is_plt,
                    "is_syscall": func.is_syscall,
                    "has_return": func.has_return,
                    "block_count": len(list(func.blocks)),
                }
            
            # Extract CFG nodes with block-level details
            node_map: dict[int, dict[str, Any]] = {}
            total_nodes_available = cfg_analysis.graph.number_of_nodes()
            
            for node in cfg_analysis.graph.nodes():
                if len(cfg_nodes) >= node_limit:
                    _LOGGER.debug(
                        "CFG node limit reached (%d), truncating from %d total nodes",
                        node_limit, total_nodes_available
                    )
                    break
                    
                addr = getattr(node, "addr", None)
                if addr is None:
                    continue
                
                block = getattr(node, "block", None)
                func_addr = getattr(node, "function_address", addr)
                
                # Extract block disassembly if available
                disasm_lines: list[dict[str, str]] = []
                block_bytes: str | None = None
                
                if block is not None:
                    try:
                        # Get block bytes for snippet storage
                        block_bytes = block.bytes.hex() if hasattr(block, "bytes") else None
                        
                        # Extract instruction details
                        if hasattr(block, "capstone") and block.capstone:
                            for insn in block.capstone.insns:
                                disasm_lines.append({
                                    "addr": hex(insn.address),
                                    "mnemonic": insn.mnemonic,
                                    "op_str": insn.op_str,
                                    "bytes": insn.bytes.hex(),
                                })
                    except Exception as exc:
                        _LOGGER.debug("Failed to extract disassembly for block at %s: %s", hex(addr), exc)
                
                entry = {
                    "addr": hex(addr),
                    "size": getattr(node, "size", None),
                    "function": hex(func_addr) if func_addr else None,
                    "function_name": function_map.get(func_addr, {}).get("name"),
                    "name": getattr(node, "name", None),
                    "type": block.__class__.__name__ if block else None,
                    "instruction_count": len(disasm_lines),
                    "disassembly": disasm_lines[:20],  # Limit per block
                }
                cfg_nodes.append(entry)
                node_map[addr] = entry
                
                # Store block snippet for session persistence
                if disasm_lines:
                    block_snippets.append({
                        "addr": hex(addr),
                        "function": hex(func_addr) if func_addr else None,
                        "function_name": function_map.get(func_addr, {}).get("name"),
                        "bytes": block_bytes,
                        "instructions": disasm_lines,
                    })

            # Extract edges between nodes
            selected_addrs = {int(entry["addr"], 16) for entry in cfg_nodes}
            for node in cfg_analysis.graph.nodes():
                addr = getattr(node, "addr", None)
                if addr not in selected_addrs:
                    continue
                for succ in cfg_analysis.graph.successors(node):
                    succ_addr = getattr(succ, "addr", None)
                    if succ_addr in selected_addrs:
                        cfg_edges.append({
                            "source": hex(addr),
                            "target": hex(succ_addr),
                            "type": "fallthrough",  # Could be enhanced with edge types
                        })
                        
        except Exception as exc:
            _LOGGER.exception("angr CFG extraction failed: %s", exc)
            cfg_error = str(exc)
            cfg_nodes = []
            cfg_edges = []
            function_map = {}
            block_snippets = []

        # Build functions list for output
        functions_list = sorted(
            function_map.values(), 
            key=lambda f: int(f["addr"], 16)
        )[:100]

        found_states = simgr.stashes.get("found", [])
        return {
            "active": len(simgr.active),
            "found": len(found_states),
            "arch": str(proj.arch),
            "entry": hex(proj.entry),
            "command": "angr CFGFast(normalize=True, data_references=True)",
            "cfg": {
                "nodes": cfg_nodes,
                "edges": cfg_edges,
                "node_count": len(cfg_nodes),
                "edge_count": len(cfg_edges),
                "truncated": len(cfg_nodes) >= node_limit,
                "total_nodes_available": total_nodes_available,
                "error": cfg_error,
            },
            "functions": functions_list,
            "function_count": len(function_map),
            "snippets": block_snippets[:200],  # Store snippets for session persistence
        }
