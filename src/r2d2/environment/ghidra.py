"""Ghidra-specific setup helpers."""

from __future__ import annotations

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
    bridge_connected: bool
    extension_root: Path
    issues: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    bridge_program_loaded: str | None = None

    @property
    def is_ready(self) -> bool:
        """Check if Ghidra headless mode is available."""
        return self.headless_path is not None

    @property
    def headless_ready(self) -> bool:
        """Check if headless mode is available."""
        return self.headless_path is not None

    @property
    def bridge_ready(self) -> bool:
        """Check if the bridge is available AND connected with a program loaded."""
        return self.bridge_available and self.bridge_connected and self.bridge_program_loaded is not None


def detect_ghidra(config: AppConfig, project_root: Path | None = None) -> GhidraDetection:
    """Inspect available Ghidra installation and extension layout.
    
    Detection priority:
    1. Headless mode (analyzeHeadless) - always works if Ghidra installed
    2. Bridge mode - only if user has Ghidra GUI running with bridge server
    """
    project_root = project_root or Path(__file__).resolve().parents[3]
    extension_root = project_root / "ghidra" / "extensions" / "r2d2"

    # Find Ghidra installation
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

    # Check for headless analyzer (primary method)
    if install_dir:
        script_name = "analyzeHeadless.bat" if platform.system() == "Windows" else "analyzeHeadless"
        candidate = install_dir / "support" / script_name
        if candidate.exists():
            headless_path = candidate
            notes.append(f"Ghidra headless ready: {candidate}")
        else:
            issues.append("analyzeHeadless not found in Ghidra install.")
    else:
        issues.append("Set GHIDRA_INSTALL_DIR to enable Ghidra decompilation.")

    # Check for bridge (optional enhancement - requires Ghidra GUI running)
    bridge_available = False
    bridge_connected = False
    bridge_program_loaded: str | None = None

    if config.ghidra.use_bridge:
        try:
            import ghidra_bridge  # noqa: F401
            bridge_available = True
            
            # Only probe if module is available
            try:
                from ..adapters.ghidra_bridge_client import GhidraBridgeClient
                client = GhidraBridgeClient(
                    host=config.ghidra.bridge_host,
                    port=config.ghidra.bridge_port,
                    timeout=5,  # Short timeout for probe
                )
                if client.connect():
                    bridge_program_loaded = client.get_current_program_name()
                    if bridge_program_loaded:
                        bridge_connected = True
                        notes.append(f"Bridge active: {bridge_program_loaded}")
                    client.disconnect()
            except Exception:
                pass  # Bridge not running, that's fine
                
        except ImportError:
            pass  # ghidra_bridge not installed

    return GhidraDetection(
        install_dir=install_dir,
        headless_path=headless_path,
        bridge_available=bridge_available,
        bridge_connected=bridge_connected,
        extension_root=extension_root,
        issues=issues,
        notes=notes,
        bridge_program_loaded=bridge_program_loaded,
    )


def extension_build_command(detection: GhidraDetection) -> list[str]:
    """Return gradle command to build the Ghidra extension."""
    gradle_cmd = "gradle"
    if platform.system() == "Windows":
        gradle_cmd = "gradlew.bat"

    return [
        gradle_cmd,
        "-PGHIDRA_INSTALL_DIR=" + (str(detection.install_dir) if detection.install_dir else ""),
        "build",
    ]
