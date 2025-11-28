"""radare2 integration via r2pipe."""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass
from pathlib import Path

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
        }

    def deep_scan(self, binary: Path, *, resource_tree: object | None = None) -> dict[str, object]:
        if not self.is_available():
            raise AdapterUnavailable("radare2 is not available on this system")

        r2pipe = self._r2pipe()
        session = r2pipe.open(str(binary))
        try:
            session.cmd("e scr.color=false")
            session.cmd("aaa")
            functions = session.cmdj("aflj")
            xrefs = session.cmdj("axj")
            cfg = session.cmdj("agj")
            disassembly = session.cmd("pd 256")

            entry_disassembly = None
            entry_function = None
            if functions:
                preferred_names = {"main", "entry0", "sym.main"}
                entry_function = next(
                    (fn for fn in functions if fn.get("name") in preferred_names),
                    functions[0],
                )
                entry_offset = entry_function.get("offset")
                if entry_offset is not None:
                    try:
                        entry_disassembly = session.cmd(f"pdf @ {entry_offset}")
                    except Exception:  # pragma: no cover - best effort
                        entry_disassembly = None
        except Exception as exc:  # pragma: no cover - runtime guard
            _LOGGER.exception("radare2 deep scan failed: %s", exc)
            raise AdapterUnavailable(f"radare2 deep scan failed: {exc}") from exc
        finally:
            session.quit()

        return {
            "functions": functions,
            "xrefs": xrefs,
            "cfg": cfg,
            "disassembly": disassembly,
            "entry_disassembly": entry_disassembly,
            "entry_function": entry_function,
        }
