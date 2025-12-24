"""Compiler wrapper for GCC/Clang cross-compilation to ARM targets."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

_LOGGER = logging.getLogger(__name__)

# Supported architectures
Architecture = Literal["arm32", "arm64", "x86", "x86_64"]

# Compiler toolchain mappings
ARM32_COMPILERS = [
    "arm-linux-gnueabihf-gcc",
    "arm-linux-gnueabi-gcc",
    "arm-none-eabi-gcc",
    "clang",
]

ARM64_COMPILERS = [
    "aarch64-linux-gnu-gcc",
    "aarch64-linux-android-clang",
    "clang",
]

X86_COMPILERS = ["gcc", "clang"]
X86_64_COMPILERS = ["gcc", "clang"]


@dataclass(slots=True)
class CompilerResult:
    """Result of a compilation operation."""

    success: bool
    output_path: Path | None = None
    stdout: str = ""
    stderr: str = ""
    command: str = ""
    return_code: int = 0
    architecture: str = ""
    compiler_used: str = ""


@dataclass(slots=True)
class Compiler:
    """Compiler instance for a specific architecture."""

    name: str
    path: Path
    architecture: Architecture
    version: str = ""
    is_clang: bool = False

    def compile_c(
        self,
        source: Path | str,
        output: Path | None = None,
        optimization: str = "-O0",
        extra_flags: list[str] | None = None,
    ) -> CompilerResult:
        """Compile C source code to binary.

        Args:
            source: Path to C source file or C source code string
            output: Output binary path (auto-generated if None)
            optimization: Optimization level (-O0, -O1, -O2, -O3, -Os)
            extra_flags: Additional compiler flags

        Returns:
            CompilerResult with compilation status and output
        """
        extra_flags = extra_flags or []

        # Handle source as string (inline source code)
        temp_source = None
        if isinstance(source, str) and not Path(source).exists():
            temp_source = Path(tempfile.mktemp(suffix=".c"))
            temp_source.write_text(source)
            source_path = temp_source
        else:
            source_path = Path(source)

        # Generate output path if not provided
        if output is None:
            output = source_path.with_suffix("")
            if output.suffix == "":
                output = Path(str(output) + ".out")

        try:
            # Build compiler command
            cmd = [str(self.path)]

            # Add architecture-specific flags
            if self.is_clang:
                if self.architecture == "arm32":
                    cmd.extend(["--target=arm-linux-gnueabihf", "-march=armv7-a"])
                elif self.architecture == "arm64":
                    cmd.extend(["--target=aarch64-linux-gnu"])

            # Add common flags
            cmd.extend([
                optimization,
                "-g",  # Debug symbols
                "-fno-stack-protector",  # Simpler binaries for learning
                "-o", str(output),
                str(source_path),
            ])

            # Add extra flags
            cmd.extend(extra_flags)

            _LOGGER.debug("Compiling with: %s", " ".join(cmd))

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )

            return CompilerResult(
                success=result.returncode == 0,
                output_path=output if result.returncode == 0 else None,
                stdout=result.stdout,
                stderr=result.stderr,
                command=" ".join(cmd),
                return_code=result.returncode,
                architecture=self.architecture,
                compiler_used=self.name,
            )

        except subprocess.TimeoutExpired:
            return CompilerResult(
                success=False,
                stderr="Compilation timed out after 60 seconds",
                command=" ".join(cmd) if 'cmd' in locals() else "",
                return_code=-1,
                architecture=self.architecture,
                compiler_used=self.name,
            )
        except Exception as exc:
            return CompilerResult(
                success=False,
                stderr=f"Compilation failed: {exc}",
                return_code=-1,
                architecture=self.architecture,
                compiler_used=self.name,
            )
        finally:
            if temp_source and temp_source.exists():
                temp_source.unlink()

    def assemble(
        self,
        source: Path | str,
        output: Path | None = None,
        extra_flags: list[str] | None = None,
    ) -> CompilerResult:
        """Assemble assembly source code to binary.

        Args:
            source: Path to assembly file or assembly source string
            output: Output binary path (auto-generated if None)
            extra_flags: Additional assembler flags

        Returns:
            CompilerResult with assembly status and output
        """
        extra_flags = extra_flags or []

        # Handle source as string
        temp_source = None
        if isinstance(source, str) and not Path(source).exists():
            temp_source = Path(tempfile.mktemp(suffix=".s"))
            temp_source.write_text(source)
            source_path = temp_source
        else:
            source_path = Path(source)

        # Generate output path
        if output is None:
            output = source_path.with_suffix(".o")

        try:
            # Build assembler command
            cmd = [str(self.path)]

            # Add architecture-specific flags for clang
            if self.is_clang:
                if self.architecture == "arm32":
                    cmd.extend(["--target=arm-linux-gnueabihf"])
                elif self.architecture == "arm64":
                    cmd.extend(["--target=aarch64-linux-gnu"])

            # Assemble only (no linking)
            cmd.extend([
                "-c",
                "-o", str(output),
                str(source_path),
            ])
            cmd.extend(extra_flags)

            _LOGGER.debug("Assembling with: %s", " ".join(cmd))

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )

            return CompilerResult(
                success=result.returncode == 0,
                output_path=output if result.returncode == 0 else None,
                stdout=result.stdout,
                stderr=result.stderr,
                command=" ".join(cmd),
                return_code=result.returncode,
                architecture=self.architecture,
                compiler_used=self.name,
            )

        except subprocess.TimeoutExpired:
            return CompilerResult(
                success=False,
                stderr="Assembly timed out after 60 seconds",
                return_code=-1,
                architecture=self.architecture,
                compiler_used=self.name,
            )
        except Exception as exc:
            return CompilerResult(
                success=False,
                stderr=f"Assembly failed: {exc}",
                return_code=-1,
                architecture=self.architecture,
                compiler_used=self.name,
            )
        finally:
            if temp_source and temp_source.exists():
                temp_source.unlink()


def _get_compiler_version(path: str) -> str:
    """Get compiler version string."""
    try:
        result = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            # Get first line of version output
            return result.stdout.split("\n")[0].strip()
    except Exception:
        pass
    return ""


def detect_compilers() -> dict[Architecture, list[Compiler]]:
    """Detect available cross-compilers on the system.

    Returns:
        Dictionary mapping architecture to list of available compilers
    """
    compilers: dict[Architecture, list[Compiler]] = {
        "arm32": [],
        "arm64": [],
        "x86": [],
        "x86_64": [],
    }

    # Check ARM32 compilers
    for compiler_name in ARM32_COMPILERS:
        path = shutil.which(compiler_name)
        if path:
            version = _get_compiler_version(path)
            compilers["arm32"].append(Compiler(
                name=compiler_name,
                path=Path(path),
                architecture="arm32",
                version=version,
                is_clang="clang" in compiler_name.lower(),
            ))

    # Check ARM64 compilers
    for compiler_name in ARM64_COMPILERS:
        path = shutil.which(compiler_name)
        if path:
            version = _get_compiler_version(path)
            compilers["arm64"].append(Compiler(
                name=compiler_name,
                path=Path(path),
                architecture="arm64",
                version=version,
                is_clang="clang" in compiler_name.lower(),
            ))

    # Check x86 compilers
    for compiler_name in X86_COMPILERS:
        path = shutil.which(compiler_name)
        if path:
            version = _get_compiler_version(path)
            compilers["x86"].append(Compiler(
                name=compiler_name,
                path=Path(path),
                architecture="x86",
                version=version,
                is_clang="clang" in compiler_name.lower(),
            ))
            # Also add to x86_64
            compilers["x86_64"].append(Compiler(
                name=compiler_name,
                path=Path(path),
                architecture="x86_64",
                version=version,
                is_clang="clang" in compiler_name.lower(),
            ))

    return compilers


def compile_c_source(
    source: Path | str,
    architecture: Architecture = "arm64",
    output: Path | None = None,
    optimization: str = "-O0",
) -> CompilerResult:
    """Compile C source to specified architecture.

    Args:
        source: Path to C source or inline C code
        architecture: Target architecture
        output: Output path (auto-generated if None)
        optimization: Optimization level

    Returns:
        CompilerResult with compilation status
    """
    compilers = detect_compilers()

    if not compilers[architecture]:
        return CompilerResult(
            success=False,
            stderr=f"No compiler found for architecture: {architecture}",
            architecture=architecture,
        )

    # Use first available compiler
    compiler = compilers[architecture][0]
    return compiler.compile_c(source, output, optimization)


def assemble_source(
    source: Path | str,
    architecture: Architecture = "arm64",
    output: Path | None = None,
) -> CompilerResult:
    """Assemble assembly source to specified architecture.

    Args:
        source: Path to assembly source or inline assembly code
        architecture: Target architecture
        output: Output path (auto-generated if None)

    Returns:
        CompilerResult with assembly status
    """
    compilers = detect_compilers()

    if not compilers[architecture]:
        return CompilerResult(
            success=False,
            stderr=f"No compiler/assembler found for architecture: {architecture}",
            architecture=architecture,
        )

    # Use first available compiler
    compiler = compilers[architecture][0]
    return compiler.assemble(source, output)


def get_available_architectures() -> list[Architecture]:
    """Get list of architectures with available compilers."""
    compilers = detect_compilers()
    return [arch for arch, comps in compilers.items() if comps]
