"""Ghidra integration with headless and bridge modes.

Modes:
1. Bridge - Connects to running Ghidra GUI (fastest, richest data, but requires setup)
2. Headless - Runs analyzeHeadless subprocess (always works, slower)

Note: PyGhidra's `pyghidra.start()` has a recursion bug with Python 3.11.
Use `python -m pyghidra.ghidra_launch` instead for headless analysis.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..config import GhidraSettings
from ..environment.ghidra import GhidraDetection
from .base import AdapterUnavailable

if TYPE_CHECKING:
    from .ghidra_bridge_client import GhidraBridgeClient

_LOGGER = logging.getLogger(__name__)


@dataclass
class GhidraAdapter:
    """Ghidra adapter supporting headless and bridge modes.

    Mode priority:
    1. Bridge - If Ghidra GUI running with bridge server AND binary loaded
    2. Headless - Default fallback, always works
    """

    detection: GhidraDetection
    project_dir: Path
    settings: GhidraSettings | None = None
    default_project: str = "r2d2"
    name: str = "ghidra"

    _bridge_client: "GhidraBridgeClient | None" = field(default=None, repr=False)

    def is_available(self) -> bool:
        """Check if Ghidra analysis is available."""
        return self.detection.headless_ready or self.detection.bridge_ready

    def _use_bridge_mode(self) -> bool:
        """Check if bridge mode should be used (connected with program loaded)."""
        return self.detection.bridge_ready

    def _get_mode(self) -> str:
        """Get the mode that will be used."""
        if self._use_bridge_mode():
            return "bridge"
        if self.detection.headless_ready:
            return "headless"
        return "unavailable"

    def quick_scan(self, binary: Path) -> dict[str, Any]:
        """Quick scan - Ghidra only runs in deep analysis stage."""
        return {
            "status": "queued",
            "message": "Ghidra runs in deep analysis stage only",
            "binary": str(binary),
            "mode": self._get_mode(),
        }

    def deep_scan(
        self,
        binary: Path,
        *,
        resource_tree: Any | None = None,
        script: Path | None = None,
        project_name: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Perform deep analysis using bridge or headless mode."""
        
        # Try bridge mode if available (Ghidra GUI running with binary loaded)
        if self._use_bridge_mode():
            try:
                return self._bridge_deep_scan(binary, resource_tree=resource_tree)
            except Exception as exc:
                _LOGGER.warning("Bridge scan failed, falling back to headless: %s", exc)

        # Use headless mode (default)
        if self.detection.headless_ready:
            return self._headless_deep_scan(
                binary,
                resource_tree=resource_tree,
                script=script,
                project_name=project_name,
                dry_run=dry_run,
            )

        raise AdapterUnavailable("Ghidra not available. Set GHIDRA_INSTALL_DIR.")

    def _bridge_deep_scan(
        self,
        binary: Path,
        *,
        resource_tree: Any | None = None,
    ) -> dict[str, Any]:
        """Perform deep scan using Ghidra bridge RPC."""
        from .ghidra_bridge_client import GhidraBridgeClient

        settings = self.settings or GhidraSettings()
        
        client = GhidraBridgeClient(
            host=settings.bridge_host,
            port=settings.bridge_port,
            timeout=settings.bridge_timeout,
        )
        
        if not client.connect():
            raise AdapterUnavailable("Failed to connect to Ghidra bridge")

        _LOGGER.info("Running Ghidra analysis via bridge for: %s", binary)

        try:
            # Get functions
            functions = client.get_functions(limit=200)
            _LOGGER.debug("Retrieved %d functions", len(functions))

            # Get function addresses for decompilation
            func_addresses = [f["address"] for f in functions if isinstance(f.get("address"), int)]

            # Batch decompile top functions
            decompiled = client.batch_decompile(
                func_addresses, limit=settings.max_decompile_functions
            )
            _LOGGER.debug("Decompiled %d functions", len(decompiled))

            # Get types
            types = client.get_types(limit=settings.max_types)

            # Get strings
            strings = client.get_strings(limit=settings.max_strings)

            # Get xrefs for key functions
            xref_map = client.get_xrefs_for_functions(func_addresses[:10], limit=10)

            # Build serializable data
            decompiled_data = [
                {
                    "name": d.name,
                    "address": f"0x{d.address:x}",
                    "signature": d.signature,
                    "decompiled_c": d.decompiled_c,
                    "parameters": d.parameters,
                    "return_type": d.return_type,
                    "calling_convention": d.calling_convention,
                }
                for d in decompiled
            ]

            types_data = [
                {
                    "name": t.name,
                    "category": t.category,
                    "size": t.size,
                    "kind": t.kind,
                    "members": t.members,
                }
                for t in types
            ]

            return {
                "mode": "bridge",
                "functions": functions,
                "function_count": len(functions),
                "decompiled": decompiled_data,
                "decompiled_count": len(decompiled_data),
                "types": types_data,
                "type_count": len(types_data),
                "strings": strings,
                "string_count": len(strings),
                "xref_map": xref_map,
                "binary": str(binary),
            }
        finally:
            client.disconnect()

    def _headless_deep_scan(
        self,
        binary: Path,
        *,
        resource_tree: Any | None = None,
        script: Path | None = None,
        project_name: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Perform deep scan using Ghidra headless analyzer.
        
        The R2D2Headless.java script outputs JSON with functions, strings,
        and decompiled code to a temp file, which we parse and return.
        """
        if not self.detection.headless_ready:
            raise AdapterUnavailable("Ghidra headless not available")

        project_name = project_name or self.default_project
        script = script or (self.detection.extension_root / "scripts" / "R2D2Headless.java")
        
        # Ensure script is in user's ghidra_scripts directory
        user_scripts = Path.home() / "ghidra_scripts"
        user_script = user_scripts / "R2D2Headless.java"
        if script.exists() and (not user_script.exists() or 
                                 script.stat().st_mtime > user_script.stat().st_mtime):
            user_scripts.mkdir(parents=True, exist_ok=True)
            shutil.copy(script, user_script)
            _LOGGER.info("Copied R2D2Headless.java to %s", user_scripts)

        # Ensure project directory exists
        self.project_dir.mkdir(parents=True, exist_ok=True)

        # Create temp file for JSON output
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            output_path = tmp.name

        command = [
            str(self.detection.headless_path),
            str(self.project_dir),
            project_name,
            "-import", str(binary),
            "-overwrite",
            "-postScript", "R2D2Headless.java",
            "-deleteProject",  # Clean up after analysis
        ]

        if dry_run:
            return {"command": command, "dry_run": True, "mode": "headless"}

        _LOGGER.info("Running Ghidra headless: %s", " ".join(command))
        
        # Set output path environment variable for the script
        env = os.environ.copy()
        env["R2D2_OUTPUT"] = output_path
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=300,  # 5 minute timeout
                env=env,
            )

            # Parse JSON output if available
            ghidra_data: dict[str, Any] = {}
            if Path(output_path).exists():
                try:
                    with open(output_path) as f:
                        ghidra_data = json.load(f)
                    _LOGGER.info("Parsed Ghidra JSON output: %d functions, %d strings",
                                 len(ghidra_data.get("functions", [])),
                                 len(ghidra_data.get("strings", [])))
                except json.JSONDecodeError as e:
                    _LOGGER.warning("Failed to parse Ghidra JSON output: %s", e)

            return {
                "mode": "headless",
                "returncode": result.returncode,
                "success": result.returncode == 0,
                "functions": ghidra_data.get("functions", []),
                "function_count": len(ghidra_data.get("functions", [])),
                "strings": ghidra_data.get("strings", []),
                "string_count": len(ghidra_data.get("strings", [])),
                "decompiled": ghidra_data.get("decompiled", []),
                "decompiled_count": len(ghidra_data.get("decompiled", [])),
                "program": ghidra_data.get("program", {}),
                "stdout": result.stdout.strip()[-2000:] if result.stdout else "",
                "stderr": result.stderr.strip()[-1000:] if result.stderr else "",
            }
        finally:
            # Clean up temp file
            try:
                Path(output_path).unlink(missing_ok=True)
            except Exception:
                pass

    def close(self) -> None:
        """Clean up resources."""
        if self._bridge_client:
            self._bridge_client.disconnect()
            self._bridge_client = None
