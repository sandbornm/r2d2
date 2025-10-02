"""Adapter interfaces for analysis backends."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol


class AnalyzerAdapter(Protocol):
    name: str

    def is_available(self) -> bool:
        ...

    def quick_scan(self, binary: Path) -> dict[str, Any]:
        ...

    def deep_scan(self, binary: Path, *, resource_tree: Any | None = None) -> dict[str, Any]:
        ...


class AdapterUnavailable(RuntimeError):
    """Raised when an adapter is invoked but unavailable."""


class AdapterRegistry:
    """Maintain the list of available adapters."""

    def __init__(self, adapters: list[AnalyzerAdapter]):
        self._adapters = adapters

    def available(self) -> list[AnalyzerAdapter]:
        return [adapter for adapter in self._adapters if adapter.is_available()]

    def get(self, name: str) -> AnalyzerAdapter:
        for adapter in self._adapters:
            if adapter.name == name:
                if not adapter.is_available():
                    raise AdapterUnavailable(f"Adapter {name} is not available")
                return adapter
        raise AdapterUnavailable(f"Adapter {name} not registered")
