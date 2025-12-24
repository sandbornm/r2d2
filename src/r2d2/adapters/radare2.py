"""radare2 integration via r2pipe with enhanced CFG and snippet extraction."""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .base import AdapterUnavailable

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class Radare2Adapter:
    name: str = "radare2"
    profile: str = "analysis.quick"

    @staticmethod
    def _r2pipe() -> "module":
        try:
            import r2pipe
        except ModuleNotFoundError as exc:  # pragma: no cover - import guard
            raise AdapterUnavailable("r2pipe module is not installed") from exc
        return r2pipe

    def is_available(self) -> bool:
        return shutil.which("radare2") is not None and self._module_available()

    @staticmethod
    def _module_available() -> bool:
        try:
            import r2pipe  # noqa: F401
        except ModuleNotFoundError:
            return False
        return True

    def quick_scan(self, binary: Path) -> dict[str, object]:
        if not self.is_available():
            raise AdapterUnavailable("radare2 is not available on this system")

        r2pipe = self._r2pipe()
        session = r2pipe.open(str(binary))
        try:
            info = session.cmdj("ij")  # Binary information
            headers = session.cmdj("iHj")
            imports = session.cmdj("iij")
            strings = session.cmdj("izj")
            sections = session.cmdj("iSj")  # Section info
            symbols = session.cmdj("isj")  # Symbols
            entry_points = session.cmdj("iej")  # Entry points
        except Exception as exc:  # pragma: no cover - runtime guard
            _LOGGER.exception("radare2 quick scan failed: %s", exc)
            raise AdapterUnavailable(f"radare2 quick scan failed: {exc}") from exc
        finally:
            session.quit()

        return {
            "info": info,
            "headers": headers,
            "imports": imports,
            "strings": strings[:200],  # limit for summaries
            "sections": sections,
            "symbols": symbols[:100] if symbols else [],
            "entry_points": entry_points,
        }

    def deep_scan(self, binary: Path, *, resource_tree: object | None = None) -> dict[str, object]:
        if not self.is_available():
            raise AdapterUnavailable("radare2 is not available on this system")

        r2pipe = self._r2pipe()
        session = r2pipe.open(str(binary))
        
        try:
            session.cmd("e scr.color=false")
            session.cmd("aaa")  # Full analysis
            
            # Basic analysis data
            functions = session.cmdj("aflj") or []
            xrefs = session.cmdj("axj") or []
            cfg = session.cmdj("agj") or []
            disassembly = session.cmd("pd 256")

            # Enhanced function-level data with CFG blocks
            function_cfgs: list[dict[str, Any]] = []
            function_snippets: list[dict[str, Any]] = []
            
            # Get detailed info for top functions by size
            sorted_functions = sorted(
                [f for f in functions if isinstance(f, dict)],
                key=lambda f: f.get("size", 0),
                reverse=True
            )[:30]  # Top 30 functions by size

            for func in sorted_functions:
                func_offset = func.get("offset")
                func_name = func.get("name", f"fcn_{func_offset:x}" if func_offset else "unknown")
                
                if func_offset is not None:
                    try:
                        # Get function CFG blocks
                        func_cfg = session.cmdj(f"agfj @ {func_offset}")
                        if func_cfg:
                            blocks = []
                            for graph in func_cfg if isinstance(func_cfg, list) else [func_cfg]:
                                if isinstance(graph, dict) and "blocks" in graph:
                                    for block in graph.get("blocks", []):
                                        block_offset = block.get("offset")
                                        block_size = block.get("size", 0)
                                        
                                        # Get block disassembly
                                        block_disasm = []
                                        if block_offset:
                                            try:
                                                block_ops = session.cmdj(f"pDj {block_size} @ {block_offset}")
                                                if block_ops:
                                                    for op in block_ops[:50]:
                                                        if isinstance(op, dict):
                                                            block_disasm.append({
                                                                "addr": hex(op.get("offset", 0)),
                                                                "bytes": op.get("bytes", ""),
                                                                "opcode": op.get("opcode", ""),
                                                                "type": op.get("type", ""),
                                                            })
                                            except Exception:
                                                pass
                                        
                                        blocks.append({
                                            "offset": hex(block_offset) if block_offset else None,
                                            "size": block_size,
                                            "ops": block.get("ops", [])[:50],
                                            "jump": hex(block.get("jump")) if block.get("jump") else None,
                                            "fail": hex(block.get("fail")) if block.get("fail") else None,
                                            "disassembly": block_disasm,
                                        })
                            
                            function_cfgs.append({
                                "name": func_name,
                                "offset": hex(func_offset),
                                "size": func.get("size", 0),
                                "nargs": func.get("nargs", 0),
                                "nlocals": func.get("nlocals", 0),
                                "blocks": blocks,
                                "block_count": len(blocks),
                            })
                            
                            # Store snippets for this function
                            if blocks:
                                function_snippets.append({
                                    "function": func_name,
                                    "offset": hex(func_offset),
                                    "blocks": [{
                                        "offset": b["offset"],
                                        "disassembly": b["disassembly"][:10],
                                    } for b in blocks[:10]],
                                })
                                
                    except Exception as exc:
                        _LOGGER.debug("Failed to get CFG for %s: %s", func_name, exc)

            # Entry function disassembly
            entry_disassembly = None
            entry_function = None
            if functions:
                preferred_names = {"main", "entry0", "sym.main", "_main", "entry"}
                entry_function = next(
                    (fn for fn in functions if fn.get("name") in preferred_names),
                    functions[0] if functions else None,
                )
                if entry_function:
                    entry_offset = entry_function.get("offset")
                    if entry_offset is not None:
                        try:
                            entry_disassembly = session.cmd(f"pdf @ {entry_offset}")
                        except Exception:  # pragma: no cover - best effort
                            entry_disassembly = None
                            
            # Get cross-references for main functions
            xref_map: dict[str, list[dict[str, Any]]] = {}
            for func in sorted_functions[:10]:
                func_offset = func.get("offset")
                if func_offset:
                    try:
                        func_xrefs = session.cmdj(f"axtj @ {func_offset}")
                        if func_xrefs:
                            xref_map[hex(func_offset)] = [
                                {
                                    "from": hex(x.get("from", 0)),
                                    "type": x.get("type", ""),
                                    "opcode": x.get("opcode", ""),
                                }
                                for x in func_xrefs[:20]
                            ]
                    except Exception:
                        pass
                        
        except Exception as exc:  # pragma: no cover - runtime guard
            _LOGGER.exception("radare2 deep scan failed: %s", exc)
            raise AdapterUnavailable(f"radare2 deep scan failed: {exc}") from exc
        finally:
            session.quit()

        return {
            "functions": functions,
            "function_count": len(functions),
            "xrefs": xrefs,
            "xref_map": xref_map,
            "cfg": cfg,
            "function_cfgs": function_cfgs,
            "disassembly": disassembly,
            "entry_disassembly": entry_disassembly,
            "entry_function": entry_function,
            "snippets": function_snippets,
        }
