"""radare2 integration via r2pipe with enhanced CFG and snippet extraction."""

from __future__ import annotations

import json
import logging
import re
import shutil
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .base import AdapterUnavailable

_LOGGER = logging.getLogger(__name__)
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_SYMBOL_HINTS = (
    "subghz",
    "nfc_",
    "lfrfid",
    "ibutton",
    "infrared",
    "protocol",
    "httpd",
    "tdpserver",
    "keeloq",
    "princeton",
    "decoder",
    "poller",
)


@dataclass(slots=True)
class Radare2Adapter:
    name: str = "radare2"
    profile: str = "analysis.quick"

    @staticmethod
    def _r2pipe() -> types.ModuleType:
        try:
            import r2pipe
        except ModuleNotFoundError as exc:  # pragma: no cover - import guard
            raise AdapterUnavailable("r2pipe module is not installed") from exc
        return r2pipe  # type: ignore[no-any-return]

    def is_available(self) -> bool:
        return shutil.which("radare2") is not None and self._module_available()

    @staticmethod
    def _module_available() -> bool:
        try:
            import r2pipe  # noqa: F401
        except ModuleNotFoundError:
            return False
        return True

    def _open(self, binary: Path) -> Any:
        r2pipe = self._r2pipe()
        session = r2pipe.open(
            str(binary),
            flags=["-2", "-e", "bin.relocs.apply=true", "-e", "scr.interactive=false"],
        )
        session.cmd("e scr.color=false")
        session.cmd("e scr.interactive=false")
        session.cmd("e bin.relocs.apply=true")
        return session

    @staticmethod
    def _cmdj(session: Any, command: str) -> Any:
        """JSON command that survives r2 mouse/ANSI junk on headless hosts."""
        try:
            payload = session.cmdj(command)
            if payload is not None:
                return payload
        except Exception as exc:
            _LOGGER.debug("radare2 cmdj %s failed: %s", command, exc)
        raw = session.cmd(command) or ""
        cleaned = _ANSI_RE.sub("", raw).strip()
        if not cleaned:
            return None
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            start, end = cleaned.find("{"), cleaned.rfind("}")
            if start >= 0 and end > start:
                try:
                    return json.loads(cleaned[start : end + 1])
                except json.JSONDecodeError:
                    return None
            start, end = cleaned.find("["), cleaned.rfind("]")
            if start >= 0 and end > start:
                try:
                    return json.loads(cleaned[start : end + 1])
                except json.JSONDecodeError:
                    return None
            return None

    @staticmethod
    def _interesting_symbols(symbols: list[Any]) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in symbols:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or item.get("flagname") or item.get("realname") or "")
            lowered = name.lower()
            if not name or name in seen:
                continue
            if not any(hint in lowered for hint in _SYMBOL_HINTS):
                continue
            seen.add(name)
            hits.append(item)
            if len(hits) >= 48:
                break
        return hits

    def quick_scan(self, binary: Path) -> dict[str, object]:
        if not self.is_available():
            raise AdapterUnavailable("radare2 is not available on this system")

        session = self._open(binary)
        try:
            info = self._cmdj(session, "ij") or {}
            headers = self._cmdj(session, "iHj") or []
            imports = self._cmdj(session, "iij") or []
            strings = self._cmdj(session, "izj") or []
            sections = self._cmdj(session, "iSj") or []
            symbols = self._cmdj(session, "isj") or []
            entry_points = self._cmdj(session, "iej") or []
        except Exception as exc:  # pragma: no cover - runtime guard
            _LOGGER.exception("radare2 quick scan failed: %s", exc)
            raise AdapterUnavailable(f"radare2 quick scan failed: {exc}") from exc
        finally:
            session.quit()

        symbol_list = symbols if isinstance(symbols, list) else []
        string_list = strings if isinstance(strings, list) else []
        return {
            "info": info,
            "headers": headers,
            "imports": imports if isinstance(imports, list) else [],
            "strings": string_list[:200],
            "sections": sections if isinstance(sections, list) else [],
            "symbols": symbol_list[:400],
            "interesting_symbols": self._interesting_symbols(symbol_list),
            "entry_points": entry_points if isinstance(entry_points, list) else [],
            "commands": ["ij", "iHj", "iij", "izj", "iSj", "isj", "iej"],
        }

    def deep_scan(self, binary: Path, *, resource_tree: object | None = None) -> dict[str, object]:
        if not self.is_available():
            raise AdapterUnavailable("radare2 is not available on this system")

        session = self._open(binary)
        
        try:
            session.cmd("aaa")  # Full analysis
            
            # Basic analysis data
            functions = self._cmdj(session, "aflj") or []
            if not isinstance(functions, list):
                functions = []
            xrefs = self._cmdj(session, "axj") or []
            if not isinstance(xrefs, list):
                xrefs = []
            cfg = self._cmdj(session, "agj") or []
            if not isinstance(cfg, list):
                cfg = []
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

                if func_offset is None:
                    continue
                    
                try:
                    # Get function CFG blocks using agfj (graph JSON format)
                    func_cfg = self._cmdj(session, f"agfj @ {func_offset}")
                    if not func_cfg:
                        _LOGGER.debug("No CFG data from agfj for %s at %s", func_name, hex(func_offset))
                        continue
                        
                    blocks = []
                    graphs = func_cfg if isinstance(func_cfg, list) else [func_cfg]
                    
                    for graph in graphs:
                        if not isinstance(graph, dict) or "blocks" not in graph:
                            continue
                            
                        for block in graph.get("blocks", []):
                            block_offset = block.get("offset")
                            block_size = block.get("size", 0)
                            
                            if not block_offset:
                                continue

                            # Get block disassembly - use ops from agfj directly (no fallback chain)
                            raw_ops = block.get("ops", [])
                            block_disasm = []
                            for op in raw_ops[:50]:
                                if isinstance(op, dict):
                                    op_offset = op.get("offset")
                                    block_disasm.append({
                                        "addr": hex(op_offset) if op_offset else "?",
                                        "bytes": op.get("bytes", ""),
                                        "opcode": op.get("opcode", ""),
                                        "type": op.get("type", ""),
                                    })

                            blocks.append({
                                "offset": hex(block_offset),
                                "size": block_size,
                                "ops": raw_ops[:50],
                                "jump": hex(block.get("jump")) if block.get("jump") else None,
                                "fail": hex(block.get("fail")) if block.get("fail") else None,
                                "disassembly": block_disasm,
                            })

                    # Only add function if we extracted blocks
                    if blocks:
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
                        func_xrefs = self._cmdj(session, f"axtj @ {func_offset}")
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
            "commands": ["aaa", "aflj", "axj", "agj", "pd 256", "agfj", "pDj", "axtj", "afbj"],
        }
