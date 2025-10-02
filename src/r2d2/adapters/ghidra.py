"""Ghidra headless integration."""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..environment.ghidra import GhidraDetection
from .base import AdapterUnavailable

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class GhidraAdapter:
    detection: GhidraDetection
    project_dir: Path
    default_project: str = "r2d2"
    name: str = "ghidra"

    def is_available(self) -> bool:
        return self.detection.is_ready

    def quick_scan(self, binary: Path) -> dict[str, Any]:
        return {
            "status": "queued",
            "message": "Ghidra runs in deep analysis stage only",
            "binary": str(binary),
        }

    def deep_scan(
        self,
        binary: Path,
        *,
        resource_tree: Any | None = None,
        script: Path | None = None,
        project_name: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        if not self.is_available():
            raise AdapterUnavailable("Ghidra headless not configured")

        project_name = project_name or self.default_project
        script = script or (self.detection.extension_root / "scripts" / "R2D2Headless.java")

        if not script.exists():
            raise AdapterUnavailable(f"Ghidra headless script missing: {script}")

        command = [
            str(self.detection.headless_path),
            str(self.project_dir),
            project_name,
            "-import",
            str(binary),
            "-postScript",
            str(script),
        ]

        if dry_run:
            return {"command": command, "dry_run": True}

        _LOGGER.info("Running Ghidra headless: %s", " ".join(command))
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        payload = {
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "command": command,
        }

        if result.returncode != 0:
            raise AdapterUnavailable(f"Ghidra headless run failed: {result.stderr.strip()}")

        return payload
