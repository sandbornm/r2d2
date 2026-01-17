"""Ghidra integration with headless and bridge mode support."""

from __future__ import annotations

import logging
import subprocess
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
    """Ghidra adapter supporting both headless and bridge modes.

    When bridge mode is enabled (settings.use_bridge=True) and the bridge
    server is reachable, uses RPC for richer analysis data. Otherwise,
    falls back to headless subprocess execution.
    """

    detection: GhidraDetection
    project_dir: Path
    settings: GhidraSettings | None = None
    default_project: str = "r2d2"
    name: str = "ghidra"

    _bridge_client: "GhidraBridgeClient | None" = field(default=None, repr=False)

    def is_available(self) -> bool:
        """Check if either headless or bridge mode is available."""
        if self._use_bridge_mode():
            return True
        return self.detection.is_ready

    def _use_bridge_mode(self) -> bool:
        """Determine if bridge mode should be used."""
        if not self.settings or not self.settings.use_bridge:
            return False
        if not self.detection.bridge_available:
            return False
        # Try to connect if not already connected
        if self._bridge_client is None:
            self._init_bridge_client()
        return self._bridge_client is not None and self._bridge_client.is_connected()

    def _init_bridge_client(self) -> None:
        """Initialize the bridge client if not already done."""
        if self._bridge_client is not None:
            return
        if not self.settings:
            return

        try:
            from .ghidra_bridge_client import GhidraBridgeClient

            self._bridge_client = GhidraBridgeClient(
                host=self.settings.bridge_host,
                port=self.settings.bridge_port,
                timeout=self.settings.bridge_timeout,
            )
            if not self._bridge_client.connect():
                _LOGGER.warning("Failed to connect to Ghidra bridge server")
                self._bridge_client = None
        except ImportError:
            _LOGGER.warning("ghidra_bridge module not available")
            self._bridge_client = None
        except Exception as exc:
            _LOGGER.warning("Bridge client initialization failed: %s", exc)
            self._bridge_client = None

    def quick_scan(self, binary: Path) -> dict[str, Any]:
        """Quick scan - Ghidra only runs in deep analysis stage."""
        return {
            "status": "queued",
            "message": "Ghidra runs in deep analysis stage only",
            "binary": str(binary),
            "mode": "bridge" if self._use_bridge_mode() else "headless",
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
        """Perform deep analysis using bridge or headless mode.

        Args:
            binary: Path to the binary to analyze.
            resource_tree: Optional resource tree for context.
            script: Path to headless script (headless mode only).
            project_name: Ghidra project name (headless mode only).
            dry_run: If True, return command without executing (headless mode only).

        Returns:
            Analysis results dictionary.
        """
        # Try bridge mode first if available
        if self._use_bridge_mode():
            try:
                return self._bridge_deep_scan(binary, resource_tree=resource_tree)
            except Exception as exc:
                _LOGGER.warning("Bridge scan failed, falling back to headless: %s", exc)
                # Mark bridge as disconnected so we don't retry
                if self._bridge_client:
                    self._bridge_client.disconnect()
                    self._bridge_client = None

        # Fall back to headless mode
        return self._headless_deep_scan(
            binary,
            resource_tree=resource_tree,
            script=script,
            project_name=project_name,
            dry_run=dry_run,
        )

    def _bridge_deep_scan(
        self,
        binary: Path,
        *,
        resource_tree: Any | None = None,
    ) -> dict[str, Any]:
        """Perform deep scan using Ghidra bridge RPC.

        Returns rich analysis data including decompilation, types, and xrefs.
        """
        if not self._bridge_client or not self._bridge_client.is_connected():
            raise AdapterUnavailable("Ghidra bridge not connected")

        settings = self.settings or GhidraSettings()
        _LOGGER.info("Running Ghidra analysis via bridge for: %s", binary)

        # Check if the binary is already loaded
        if not self._bridge_client.is_binary_loaded(binary):
            _LOGGER.info("Binary not loaded in Ghidra, bridge analysis may be limited")

        # Get functions
        functions = self._bridge_client.get_functions(limit=200)
        _LOGGER.debug("Retrieved %d functions from Ghidra", len(functions))

        # Get function addresses for decompilation
        func_addresses = [f["address"] for f in functions if isinstance(f.get("address"), int)]

        # Batch decompile top functions
        decompiled = self._bridge_client.batch_decompile(
            func_addresses, limit=settings.max_decompile_functions
        )
        _LOGGER.debug("Decompiled %d functions", len(decompiled))

        # Get types (focus on structs for usefulness)
        types = self._bridge_client.get_types(limit=settings.max_types)
        _LOGGER.debug("Retrieved %d types from Ghidra", len(types))

        # Get strings
        strings = self._bridge_client.get_strings(limit=settings.max_strings)
        _LOGGER.debug("Retrieved %d strings from Ghidra", len(strings))

        # Get xrefs for key functions (top 10)
        xref_map = self._bridge_client.get_xrefs_for_functions(
            func_addresses[:10], limit=10
        )

        # Build decompiled data for serialization
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

        # Build types data for serialization
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

    def _headless_deep_scan(
        self,
        binary: Path,
        *,
        resource_tree: Any | None = None,
        script: Path | None = None,
        project_name: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Perform deep scan using Ghidra headless analyzer."""
        if not self.detection.is_ready:
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
            return {"command": command, "dry_run": True, "mode": "headless"}

        _LOGGER.info("Running Ghidra headless: %s", " ".join(command))
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        payload = {
            "mode": "headless",
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "command": command,
        }

        if result.returncode != 0:
            raise AdapterUnavailable(f"Ghidra headless run failed: {result.stderr.strip()}")

        return payload

    def close(self) -> None:
        """Clean up resources, including bridge connection."""
        if self._bridge_client:
            self._bridge_client.disconnect()
            self._bridge_client = None
