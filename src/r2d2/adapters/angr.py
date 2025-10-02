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
        return {
            "active": len(simgr.active),
            "found": len(simgr.found),
        }
