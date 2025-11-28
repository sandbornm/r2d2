"""libmagic file identification adapter."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from .base import AdapterUnavailable

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class LibmagicAdapter:
    name: str = "libmagic"

    def is_available(self) -> bool:
        try:
            import magic  # noqa: F401
        except (ModuleNotFoundError, ImportError):
            return False
        return True

    def _magic(self) -> "module":
        try:
            import magic
        except (ModuleNotFoundError, ImportError) as exc:  # pragma: no cover - import guard
            raise AdapterUnavailable(
                "python-magic is not installed or libmagic native library is missing. "
                "On macOS: brew install libmagic"
            ) from exc
        return magic

    def quick_scan(self, binary: Path) -> dict[str, str]:
        if not self.is_available():
            raise AdapterUnavailable("python-magic is not installed")
        magic = self._magic()
        ms = magic.Magic(mime=True)
        mime_type = ms.from_file(str(binary))
        human = magic.from_file(str(binary))
        return {"mime": mime_type, "description": human}

    def deep_scan(self, binary: Path, *, resource_tree: object | None = None) -> dict[str, str]:
        _LOGGER.debug("libmagic deep scan not required; returning quick scan info")
        return self.quick_scan(binary)
