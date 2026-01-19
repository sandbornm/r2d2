"""GEF/GDB dynamic analysis adapter.

This adapter runs ARM binaries in an isolated Docker container with GDB/GEF
for dynamic analysis and execution tracing.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .base import AdapterUnavailable

_LOGGER = logging.getLogger(__name__)

DEFAULT_IMAGE = "r2d2-gef"
DEFAULT_TIMEOUT = 60
DEFAULT_MAX_INSTRUCTIONS = 10000


@dataclass
class RegisterSnapshot:
    """Snapshot of CPU registers at a point in execution."""

    pc: int
    sp: int
    registers: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pc": self.pc,
            "sp": self.sp,
            "registers": self.registers,
        }


@dataclass
class MemoryRegion:
    """Memory region information."""

    start: str
    end: str
    size: str
    offset: str
    permissions: str
    name: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "end": self.end,
            "size": self.size,
            "offset": self.offset,
            "permissions": self.permissions,
            "name": self.name,
        }


@dataclass
class ExecutionTrace:
    """Results of dynamic execution analysis."""

    entry_point: str | None = None
    register_snapshots: list[RegisterSnapshot] = field(default_factory=list)
    memory_maps: list[MemoryRegion] = field(default_factory=list)
    instruction_count: int = 0
    exit_code: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_point": self.entry_point,
            "register_snapshots": [s.to_dict() for s in self.register_snapshots],
            "memory_maps": [m.to_dict() for m in self.memory_maps],
            "instruction_count": self.instruction_count,
            "exit_code": self.exit_code,
            "error": self.error,
        }


@dataclass(slots=True)
class GEFAdapter:
    """Dynamic analysis adapter using GDB/GEF in Docker container.

    This adapter provides sandboxed execution of ARM binaries with:
    - Network isolation (--network=none)
    - Read-only root filesystem (--read-only)
    - Resource limits (memory, CPU)
    - No privilege escalation (--security-opt=no-new-privileges)
    """

    name: str = "gef"
    image: str = DEFAULT_IMAGE
    timeout: int = DEFAULT_TIMEOUT
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS
    memory_limit: str = "512m"
    cpu_limit: float = 1.0

    def is_available(self) -> bool:
        """Check if Docker is available and the GEF image exists."""
        # Check for Docker
        docker = shutil.which("docker")
        if not docker:
            _LOGGER.debug("Docker not found in PATH")
            return False

        # Check if image exists
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", self.image],
                capture_output=True,
                timeout=10,
            )
            if result.returncode != 0:
                _LOGGER.debug("GEF Docker image '%s' not found", self.image)
                return False
            return True
        except subprocess.TimeoutExpired:
            _LOGGER.debug("Docker image check timed out")
            return False
        except Exception as e:
            _LOGGER.debug("Docker check failed: %s", e)
            return False

    def quick_scan(self, binary: Path, **kwargs: Any) -> dict[str, Any]:
        """Quick scan - returns availability status and config info."""
        return {
            "mode": "gef",
            "available": self.is_available(),
            "image": self.image,
            "message": "GEF dynamic analysis runs in deep scan only",
        }

    def deep_scan(
        self,
        binary: Path,
        *,
        resource_tree: Any | None = None,
        max_instructions: int | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Perform dynamic analysis using GDB/GEF in Docker container.

        Args:
            binary: Path to the binary to analyze.
            resource_tree: Optional resource tree for context.
            max_instructions: Override max instruction count.

        Returns:
            Analysis results with execution trace data.
        """
        if not self.is_available():
            raise AdapterUnavailable(
                f"GEF adapter unavailable - ensure Docker is installed and "
                f"'{self.image}' image is built"
            )

        binary = binary.resolve()
        if not binary.exists():
            return {"error": f"Binary not found: {binary}", "mode": "gef"}

        max_instr = max_instructions or self.max_instructions

        # Create temporary output directory
        with tempfile.TemporaryDirectory() as output_dir:
            try:
                result = self._run_container(binary, output_dir, max_instr)
                return result
            except Exception as e:
                _LOGGER.exception("GEF analysis failed")
                return {
                    "error": str(e),
                    "mode": "gef",
                    "binary": str(binary),
                }

    def _run_container(
        self,
        binary: Path,
        output_dir: str,
        max_instructions: int,
    ) -> dict[str, Any]:
        """Run the GEF analysis container."""
        _LOGGER.info("Starting GEF dynamic analysis: %s", binary)

        # Build Docker command with security constraints
        cmd = [
            "docker", "run",
            "--rm",  # Remove container after execution
            "--network=none",  # No network access
            "--read-only",  # Read-only root filesystem
            f"--memory={self.memory_limit}",  # Memory limit
            f"--cpus={self.cpu_limit}",  # CPU limit
            "--security-opt=no-new-privileges",  # Prevent privilege escalation
            "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",  # Writable tmp
            "-v", f"{binary}:/binary:ro",  # Mount binary read-only
            "-v", f"{output_dir}:/output:rw",  # Mount output directory
            self.image,
            "/binary",
            "--output=/output",
            f"--max-instructions={max_instructions}",
        ]

        _LOGGER.debug("Docker command: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # Read output file
            output_file = Path(output_dir) / "output.json"
            if output_file.exists():
                with open(output_file) as f:
                    data = json.load(f)

                # Parse into structured data
                trace = self._parse_trace(data)

                return {
                    "mode": "gef",
                    "binary": str(binary),
                    "returncode": data.get("returncode", result.returncode),
                    "trace": trace.to_dict(),
                    "error": data.get("error"),
                }
            else:
                return {
                    "mode": "gef",
                    "binary": str(binary),
                    "returncode": result.returncode,
                    "error": "No output generated",
                    "stdout": result.stdout[-500:] if result.stdout else "",
                    "stderr": result.stderr[-500:] if result.stderr else "",
                }

        except subprocess.TimeoutExpired:
            return {
                "mode": "gef",
                "binary": str(binary),
                "error": f"Analysis timed out after {self.timeout}s",
            }

    def _parse_trace(self, data: dict[str, Any]) -> ExecutionTrace:
        """Parse raw output into ExecutionTrace."""
        trace = ExecutionTrace(
            entry_point=data.get("entry_point"),
            instruction_count=data.get("instruction_count", 0),
            exit_code=data.get("exit_code"),
            error=data.get("error"),
        )

        # Parse register snapshots
        for snap in data.get("register_snapshots", []):
            if isinstance(snap, dict):
                trace.register_snapshots.append(
                    RegisterSnapshot(
                        pc=snap.get("pc", 0),
                        sp=snap.get("sp", 0),
                        registers=snap.get("registers", {}),
                    )
                )

        # Parse memory maps
        for region in data.get("memory_maps", []):
            if isinstance(region, dict):
                trace.memory_maps.append(
                    MemoryRegion(
                        start=region.get("start", "0"),
                        end=region.get("end", "0"),
                        size=region.get("size", "0"),
                        offset=region.get("offset", "0"),
                        permissions=region.get("permissions", ""),
                        name=region.get("name", ""),
                    )
                )

        return trace

    def build_image(self, dockerfile_path: Path | None = None) -> bool:
        """Build the GEF Docker image.

        Args:
            dockerfile_path: Path to Dockerfile.gef. If not provided,
                            looks in the project root.

        Returns:
            True if build succeeded, False otherwise.
        """
        if dockerfile_path is None:
            # Try to find Dockerfile.gef in common locations
            candidates = [
                Path("Dockerfile.gef"),
                Path(__file__).parent.parent.parent.parent / "Dockerfile.gef",
            ]
            for candidate in candidates:
                if candidate.exists():
                    dockerfile_path = candidate
                    break

        if dockerfile_path is None or not dockerfile_path.exists():
            _LOGGER.error("Dockerfile.gef not found")
            return False

        _LOGGER.info("Building GEF Docker image from %s", dockerfile_path)

        try:
            result = subprocess.run(
                [
                    "docker", "build",
                    "-t", self.image,
                    "-f", str(dockerfile_path),
                    str(dockerfile_path.parent),
                ],
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout for build
            )

            if result.returncode == 0:
                _LOGGER.info("Successfully built GEF image: %s", self.image)
                return True
            else:
                _LOGGER.error("Failed to build GEF image: %s", result.stderr)
                return False

        except subprocess.TimeoutExpired:
            _LOGGER.error("Docker build timed out")
            return False
        except Exception as e:
            _LOGGER.error("Docker build failed: %s", e)
            return False
