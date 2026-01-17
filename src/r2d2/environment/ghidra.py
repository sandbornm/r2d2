"""Ghidra-specific setup helpers."""

from __future__ import annotations

import importlib
import os
import platform
from dataclasses import dataclass, field
from pathlib import Path

from ..config import AppConfig

GHIDRA_MIN_VERSION = "10.4"


@dataclass(slots=True)
class GhidraDetection:
    install_dir: Path | None
    headless_path: Path | None
    bridge_available: bool
    extension_root: Path
    issues: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    bridge_connected: bool = False
    bridge_program_loaded: str | None = None

    @property
    def is_ready(self) -> bool:
        return self.install_dir is not None and self.headless_path is not None

    @property
    def bridge_ready(self) -> bool:
        """Check if the bridge is available and connected."""
        return self.bridge_available and self.bridge_connected


def detect_ghidra(config: AppConfig, project_root: Path | None = None) -> GhidraDetection:
    """Inspect available Ghidra installation and extension layout."""

    project_root = project_root or Path(__file__).resolve().parents[2]
    extension_root = project_root / "ghidra" / "extensions" / "r2d2"

    configured_dir = config.ghidra.install_dir
    env_dir = os.environ.get("GHIDRA_INSTALL_DIR")

    install_dir: Path | None = None
    if configured_dir and Path(configured_dir).expanduser().exists():
        install_dir = Path(configured_dir).expanduser()
    elif env_dir and Path(env_dir).expanduser().exists():
        install_dir = Path(env_dir).expanduser()

    headless_path: Path | None = None
    issues: list[str] = []
    notes: list[str] = []

    if install_dir:
        candidate = install_dir / "support" / ("analyzeHeadless.bat" if platform.system() == "Windows" else "analyzeHeadless")
        if candidate.exists():
            headless_path = candidate
            notes.append(f"Found analyzeHeadless at {candidate}")
        else:
            issues.append("Could not locate analyzeHeadless script in Ghidra install.")
    else:
        issues.append("Ghidra installation directory not configured or not found.")

    bridge_available = False
    bridge_connected = False
    bridge_program_loaded: str | None = None

    if config.ghidra.use_bridge:
        try:
            importlib.import_module("ghidra_bridge")
        except ModuleNotFoundError:
            issues.append("ghidra_bridge requested but not importable; install optional dependency 'ghidra'.")
        else:
            bridge_available = True
            notes.append("ghidra_bridge module import successful.")

            # Probe bridge connectivity
            try:
                from ..adapters.ghidra_bridge_client import GhidraBridgeClient

                client = GhidraBridgeClient(
                    host=config.ghidra.bridge_host,
                    port=config.ghidra.bridge_port,
                    timeout=config.ghidra.bridge_timeout,
                )
                if client.connect():
                    bridge_connected = True
                    bridge_program_loaded = client.get_current_program_name()
                    if bridge_program_loaded:
                        notes.append(f"Bridge connected, program loaded: {bridge_program_loaded}")
                    else:
                        notes.append("Bridge connected, no program loaded.")
                    client.disconnect()
                else:
                    notes.append("Bridge module available but server not reachable.")
            except Exception as exc:
                notes.append(f"Bridge connectivity probe failed: {exc}")

    if not extension_root.exists():
        issues.append(f"Extension path {extension_root} is missing; run bootstrap script.")

    return GhidraDetection(
        install_dir=install_dir,
        headless_path=headless_path,
        bridge_available=bridge_available,
        extension_root=extension_root,
        issues=issues,
        notes=notes,
        bridge_connected=bridge_connected,
        bridge_program_loaded=bridge_program_loaded,
    )


def extension_build_command(detection: GhidraDetection) -> list[str]:
    """Return gradle command to build the Ghidra extension."""

    gradle_cmd = "gradle"
    if platform.system() == "Windows":  # pragma: no cover - windows specific
        gradle_cmd = "gradlew.bat"

    return [
        gradle_cmd,
        "-PGHIDRA_INSTALL_DIR=" + (str(detection.install_dir) if detection.install_dir else ""),
        "build",
    ]
