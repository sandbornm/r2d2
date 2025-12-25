"""Capstone disassembly adapter."""

from __future__ import annotations

import logging
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .base import AdapterUnavailable

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class CapstoneAdapter:
    name: str = "capstone"

    def is_available(self) -> bool:
        try:
            import capstone  # noqa: F401
        except ModuleNotFoundError:
            return False
        return True

    def _capstone(self) -> types.ModuleType:
        try:
            import capstone
        except ModuleNotFoundError as exc:  # pragma: no cover - import guard
            raise AdapterUnavailable("capstone module is not installed") from exc
        return capstone

    def quick_scan(self, binary: Path, *, arch: str | None = None, entry: int | None = None) -> dict[str, Any]:
        if not self.is_available():
            raise AdapterUnavailable("capstone is not available on this system")

        if arch is None:
            raise AdapterUnavailable("Architecture hint required for capstone quick scan")

        capstone = self._capstone()
        mode = _resolve_mode(capstone, arch)
        disassembler = capstone.Cs(*mode)
        data = binary.read_bytes()[:64]
        instructions = []
        for insn in disassembler.disasm(data, entry or 0):
            instructions.append({
                "address": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
            })

        return {"instructions": instructions}

    def deep_scan(self, binary: Path, *, blocks: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        if blocks is None:
            _LOGGER.debug("capstone deep scan skipped; no basic blocks provided")
            return {"status": "skipped", "reason": "no basic blocks"}
        return {"status": "pending", "blocks": len(blocks)}


def _resolve_mode(capstone: types.ModuleType, arch: str) -> tuple[int, int]:
    arch_map = {
        "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        "x86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
        "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    }
    if arch not in arch_map:
        raise AdapterUnavailable(f"Unsupported architecture for capstone: {arch}")
    return arch_map[arch]
