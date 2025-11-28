"""Optional angr symbolic execution adapter."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .base import AdapterUnavailable


@dataclass(slots=True)
class AngrAdapter:
    name: str = "angr"

    def is_available(self) -> bool:
        try:
            import angr  # noqa: F401
        except ModuleNotFoundError:
            return False
        return True

    def _angr(self) -> "module":
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

        cfg_nodes: list[dict[str, Any]] = []
        cfg_edges: list[dict[str, str]] = []
        try:
            cfg_analysis = proj.analyses.CFGFast(normalize=True, data_references=True)
            limit = 150
            node_map: dict[int, dict[str, Any]] = {}
            for node in cfg_analysis.graph.nodes():
                if len(cfg_nodes) >= limit:
                    break
                addr = getattr(node, "addr", None)
                if addr is None:
                    continue
                entry = {
                    "addr": hex(addr),
                    "size": getattr(node, "size", None),
                    "function": hex(getattr(node, "function_address", addr)),
                    "name": getattr(node, "name", None),
                    "type": getattr(node, "block", None).__class__.__name__ if getattr(node, "block", None) else None,
                }
                cfg_nodes.append(entry)
                node_map[addr] = entry

            selected_addrs = {int(entry["addr"], 16) for entry in cfg_nodes}
            for node in cfg_analysis.graph.nodes():
                addr = getattr(node, "addr", None)
                if addr not in selected_addrs:
                    continue
                for succ in cfg_analysis.graph.successors(node):
                    succ_addr = getattr(succ, "addr", None)
                    if succ_addr in selected_addrs:
                        cfg_edges.append(
                            {
                                "source": hex(addr),
                                "target": hex(succ_addr),
                            }
                        )
        except Exception:  # pragma: no cover - best effort
            cfg_nodes = []
            cfg_edges = []

        return {
            "active": len(simgr.active),
            "found": len(simgr.found),
            "cfg": {
                "nodes": cfg_nodes,
                "edges": cfg_edges,
            },
        }
