"""Compiler wrapper for GCC/Clang cross-compilation to ARM targets.

Supports:
- Native ARM cross-compilers (gcc-aarch64-linux-gnu, etc.)
- Docker-based compilation when native compilers aren't available
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

_LOGGER = logging.getLogger(__name__)

# Docker image for ARM compilation
DOCKER_COMPILER_IMAGE = "r2d2-compiler:latest"
DOCKER_FALLBACK_IMAGE = "debian:bookworm-slim"

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
    assembly: str | None = None  # Generated assembly code (when using -S)


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
            fd, temp_path = tempfile.mkstemp(suffix=".c")
            os.close(fd)
            temp_source = Path(temp_path)
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
            fd, temp_path = tempfile.mkstemp(suffix=".s")
            os.close(fd)
            temp_source = Path(temp_path)
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


def _is_docker_available() -> bool:
    """Check if Docker is available and running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _docker_image_exists(image: str) -> bool:
    """Check if a Docker image exists locally."""
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _compile_with_docker(
    source_code: str,
    architecture: Architecture,
    optimization: str = "-O0",
    extra_flags: list[str] | None = None,
    output_name: str = "output",
    emit_asm: bool = True,
) -> CompilerResult:
    """Compile C source using Docker container with ARM toolchain.
    
    This is used when native ARM cross-compilers are not available (e.g., on macOS).
    """
    extra_flags = extra_flags or []
    
    if not _is_docker_available():
        return CompilerResult(
            success=False,
            stderr="Docker is not available. Install Docker Desktop or run: docker-compose up -d compiler",
            return_code=-1,
            architecture=architecture,
            compiler_used="docker",
        )
    
    # Determine which compiler to use
    if architecture == "arm32":
        compiler_cmd = "arm-linux-gnueabihf-gcc"
    elif architecture == "arm64":
        compiler_cmd = "aarch64-linux-gnu-gcc"
    else:
        return CompilerResult(
            success=False,
            stderr=f"Docker compilation not supported for {architecture}",
            return_code=-1,
            architecture=architecture,
            compiler_used="docker",
        )
    
    # Determine Docker image to use
    image = DOCKER_COMPILER_IMAGE if _docker_image_exists(DOCKER_COMPILER_IMAGE) else None
    if not image:
        # Try building from Dockerfile.compiler or use a base Debian image
        return CompilerResult(
            success=False,
            stderr=(
                "Docker compiler image not found. Build it with:\n"
                "  docker build -t r2d2-compiler -f Dockerfile.compiler .\n"
                "Or run:\n"
                "  docker-compose up -d compiler"
            ),
            return_code=-1,
            architecture=architecture,
            compiler_used="docker",
        )
    
    # Create temp directory for compilation
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        source_file = tmppath / "source.c"
        output_elf = tmppath / output_name
        output_asm = tmppath / f"{output_name}.s"
        
        # Write source code
        source_file.write_text(source_code)
        
        # Build compilation command
        compile_flags = [
            optimization,
            "-g",
            "-fno-stack-protector",
        ]
        compile_flags.extend(extra_flags)
        
        # Build the flags string for shell command
        flags_str = " ".join(compile_flags)
        
        # First, generate assembly if requested
        asm_content = None
        if emit_asm:
            # Use -c to pass command to bash entrypoint
            asm_shell_cmd = f"{compiler_cmd} -S {flags_str} -o {output_name}.s source.c"
            asm_cmd = [
                "docker", "run", "--rm",
                "-v", f"{tmppath}:/compile",
                "-w", "/compile",
                image,
                "-c",  # Pass to bash entrypoint
                asm_shell_cmd,
            ]
            
            _LOGGER.debug("Docker ASM command: %s", " ".join(asm_cmd))
            
            try:
                asm_result = subprocess.run(
                    asm_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if asm_result.returncode == 0 and output_asm.exists():
                    asm_content = output_asm.read_text()
            except Exception as exc:
                _LOGGER.warning("ASM generation failed: %s", exc)
        
        # Compile to binary - use -c to pass command to bash entrypoint
        compile_shell_cmd = f"{compiler_cmd} {flags_str} -o {output_name} source.c"
        compile_cmd = [
            "docker", "run", "--rm",
            "-v", f"{tmppath}:/compile",
            "-w", "/compile",
            image,
            "-c",  # Pass to bash entrypoint
            compile_shell_cmd,
        ]
        
        _LOGGER.debug("Docker compile command: %s", " ".join(compile_cmd))
        
        try:
            result = subprocess.run(
                compile_cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            # Read output binary if successful
            output_path = None
            if result.returncode == 0 and output_elf.exists():
                # Copy to a persistent location
                persistent_dir = Path(os.path.expanduser("~/.cache/r2d2/uploads"))
                persistent_dir.mkdir(parents=True, exist_ok=True)
                persistent_path = persistent_dir / output_name
                
                # Copy the binary
                shutil.copy2(output_elf, persistent_path)
                output_path = persistent_path
                
                # Also copy ASM file if exists
                if asm_content and output_asm.exists():
                    asm_persistent = persistent_dir / f"{output_name}.s"
                    shutil.copy2(output_asm, asm_persistent)
            
            return CompilerResult(
                success=result.returncode == 0,
                output_path=output_path,
                stdout=result.stdout,
                stderr=result.stderr,
                command=" ".join(compile_cmd),
                return_code=result.returncode,
                architecture=architecture,
                compiler_used=f"docker:{compiler_cmd}",
                assembly=asm_content,
            )
            
        except subprocess.TimeoutExpired:
            return CompilerResult(
                success=False,
                stderr="Docker compilation timed out after 60 seconds",
                return_code=-1,
                architecture=architecture,
                compiler_used="docker",
            )
        except Exception as exc:
            return CompilerResult(
                success=False,
                stderr=f"Docker compilation failed: {exc}",
                return_code=-1,
                architecture=architecture,
                compiler_used="docker",
            )


def detect_compilers(include_docker: bool = True) -> dict[Architecture, list[Compiler]]:
    """Detect available cross-compilers on the system.

    Args:
        include_docker: If True, include Docker-based compilers as fallback

    Returns:
        Dictionary mapping architecture to list of available compilers
    """
    compilers: dict[Architecture, list[Compiler]] = {
        "arm32": [],
        "arm64": [],
        "x86": [],
        "x86_64": [],
    }

    # Check ARM32 compilers (prefer real GCC cross-compilers over clang)
    for compiler_name in ARM32_COMPILERS:
        path = shutil.which(compiler_name)
        if path:
            version = _get_compiler_version(path)
            is_clang = "clang" in compiler_name.lower()
            # Only add clang if it's not our only option (we'll fall back to Docker)
            if not is_clang:
                compilers["arm32"].append(Compiler(
                    name=compiler_name,
                    path=Path(path),
                    architecture="arm32",
                    version=version,
                    is_clang=is_clang,
                ))
    
    # Add clang as fallback only if no real cross-compiler found
    if not compilers["arm32"]:
        clang_path = shutil.which("clang")
        if clang_path:
            version = _get_compiler_version(clang_path)
            compilers["arm32"].append(Compiler(
                name="clang",
                path=Path(clang_path),
                architecture="arm32",
                version=version,
                is_clang=True,
            ))

    # Check ARM64 compilers (prefer real GCC cross-compilers over clang)
    for compiler_name in ARM64_COMPILERS:
        path = shutil.which(compiler_name)
        if path:
            version = _get_compiler_version(path)
            is_clang = "clang" in compiler_name.lower()
            if not is_clang:
                compilers["arm64"].append(Compiler(
                    name=compiler_name,
                    path=Path(path),
                    architecture="arm64",
                    version=version,
                    is_clang=is_clang,
                ))
    
    # Add clang as fallback only if no real cross-compiler found
    if not compilers["arm64"]:
        clang_path = shutil.which("clang")
        if clang_path:
            version = _get_compiler_version(clang_path)
            compilers["arm64"].append(Compiler(
                name="clang",
                path=Path(clang_path),
                architecture="arm64",
                version=version,
                is_clang=True,
            ))

    # Add Docker-based compilers if Docker is available and image exists
    if include_docker and _is_docker_available() and _docker_image_exists(DOCKER_COMPILER_IMAGE):
        if not any(not c.is_clang for c in compilers["arm32"]):
            compilers["arm32"].insert(0, Compiler(
                name="docker:arm-linux-gnueabihf-gcc",
                path=Path("/usr/bin/arm-linux-gnueabihf-gcc"),
                architecture="arm32",
                version="Docker container",
                is_clang=False,
            ))
        if not any(not c.is_clang for c in compilers["arm64"]):
            compilers["arm64"].insert(0, Compiler(
                name="docker:aarch64-linux-gnu-gcc",
                path=Path("/usr/bin/aarch64-linux-gnu-gcc"),
                architecture="arm64",
                version="Docker container",
                is_clang=False,
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
    extra_flags: list[str] | None = None,
) -> CompilerResult:
    """Compile C source to specified architecture.

    Args:
        source: Path to C source or inline C code
        architecture: Target architecture
        output: Output path (auto-generated if None)
        optimization: Optimization level
        extra_flags: Additional compiler flags (e.g., -ffreestanding -nostdlib)

    Returns:
        CompilerResult with compilation status
    """
    # Handle source - can be Path, path string, or inline code
    # Path objects are always treated as file paths
    # Strings are treated as file paths only if the file exists
    if isinstance(source, Path):
        if not source.exists():
            return CompilerResult(
                success=False,
                stderr=f"Source file not found: {source}",
                return_code=-1,
                architecture=architecture,
            )
        source_code = source.read_text()
    elif isinstance(source, str) and Path(source).exists():
        source_code = Path(source).read_text()
    else:
        # Treat as inline source code
        source_code = str(source)
    
    output_name = output.stem if output else "output"
    
    compilers = detect_compilers()
    
    # For ARM architectures, ALWAYS prefer Docker unless we have a REAL native cross-compiler
    # (clang on macOS can't link ARM binaries without a sysroot)
    if architecture in ("arm32", "arm64"):
        # Check if we have a real GCC cross-compiler (not clang, not docker)
        has_real_cross_compiler = any(
            not c.is_clang and not c.name.startswith("docker:")
            for c in compilers.get(architecture, [])
        )
        
        if has_real_cross_compiler:
            # Use the native cross-compiler
            compiler = next(
                c for c in compilers[architecture]
                if not c.is_clang and not c.name.startswith("docker:")
            )
            return compiler.compile_c(source, output, optimization, extra_flags)
        
        # Use Docker for ARM compilation
        return _compile_with_docker(
            source_code=source_code,
            architecture=architecture,
            optimization=optimization,
            extra_flags=extra_flags,
            output_name=output_name,
            emit_asm=True,
        )
    
    # For x86/x86_64, use native compilers
    if compilers[architecture]:
        compiler = compilers[architecture][0]
        return compiler.compile_c(source, output, optimization, extra_flags)
    
    return CompilerResult(
        success=False,
        stderr=f"No compiler found for architecture: {architecture}. Install ARM cross-compilers or use Docker.",
        architecture=architecture,
    )


def compile_to_asm(
    source: Path | str,
    architecture: Architecture = "arm64",
    optimization: str = "-O0",
    extra_flags: list[str] | None = None,
) -> CompilerResult:
    """Compile C source to assembly (not object code).

    Args:
        source: Path to C source or inline C code
        architecture: Target architecture
        optimization: Optimization level
        extra_flags: Additional compiler flags

    Returns:
        CompilerResult with assembly code in the 'assembly' field
    """
    extra_flags = extra_flags or []
    
    # Handle source - can be Path, path string, or inline code
    if isinstance(source, Path):
        if not source.exists():
            return CompilerResult(
                success=False,
                stderr=f"Source file not found: {source}",
                return_code=-1,
                architecture=architecture,
            )
        source_code = source.read_text()
        source_path = source
    elif isinstance(source, str) and Path(source).exists():
        source_code = Path(source).read_text()
        source_path = Path(source)
    else:
        source_code = str(source)
        source_path = None
    
    compilers = detect_compilers()
    
    # For ARM targets, use Docker unless we have a real native cross-compiler
    if architecture in ("arm32", "arm64"):
        has_real_cross_compiler = any(
            not c.is_clang and not c.name.startswith("docker:")
            for c in compilers.get(architecture, [])
        )
        
        if not has_real_cross_compiler:
            # Use Docker for assembly generation
            return _compile_with_docker(
                source_code=source_code,
                architecture=architecture,
                optimization=optimization,
                extra_flags=extra_flags,
                output_name="output",
                emit_asm=True,
            )
        
        # Use native cross-compiler
        compiler = next(
            c for c in compilers[architecture]
            if not c.is_clang and not c.name.startswith("docker:")
        )
    else:
        # For x86/x86_64, use native compilers
        if not compilers[architecture]:
            return CompilerResult(
                success=False,
                stderr=f"No compiler found for architecture: {architecture}",
                architecture=architecture,
            )
        compiler = compilers[architecture][0]

    # Handle source as string (inline source code)
    temp_source = None
    if source_path is None:
        fd, temp_path = tempfile.mkstemp(suffix=".c")
        os.close(fd)
        temp_source = Path(temp_path)
        temp_source.write_text(source_code)
        source_path = temp_source

    # Output to temp .s file
    fd, temp_asm_path = tempfile.mkstemp(suffix=".s")
    os.close(fd)
    temp_asm = Path(temp_asm_path)

    try:
        cmd = [str(compiler.path)]

        # Add architecture-specific flags for clang
        if compiler.is_clang:
            if architecture == "arm32":
                cmd.extend(["--target=arm-linux-gnueabihf", "-march=armv7-a"])
            elif architecture == "arm64":
                cmd.extend(["--target=aarch64-linux-gnu"])

        # Compile to assembly only (-S)
        cmd.extend([
            "-S",  # Output assembly
            optimization,
            "-fno-stack-protector",
            "-o", str(temp_asm),
            str(source_path),
        ])
        cmd.extend(extra_flags)

        _LOGGER.debug("Generating assembly with: %s", " ".join(cmd))

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assembly = None
        if result.returncode == 0 and temp_asm.exists():
            assembly = temp_asm.read_text()

        return CompilerResult(
            success=result.returncode == 0,
            output_path=temp_asm if result.returncode == 0 else None,
            stdout=result.stdout,
            stderr=result.stderr,
            command=" ".join(cmd),
            return_code=result.returncode,
            architecture=architecture,
            compiler_used=compiler.name,
            assembly=assembly,
        )

    except subprocess.TimeoutExpired:
        return CompilerResult(
            success=False,
            stderr="Assembly generation timed out after 60 seconds",
            return_code=-1,
            architecture=architecture,
            compiler_used=compiler.name,
        )
    except Exception as exc:
        return CompilerResult(
            success=False,
            stderr=f"Assembly generation failed: {exc}",
            return_code=-1,
            architecture=architecture,
            compiler_used=compiler.name,
        )
    finally:
        if temp_source and temp_source.exists():
            temp_source.unlink()
        # Don't delete temp_asm - caller may want to save it


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

    # Use first available native (non-Docker) compiler
    native_compilers = [c for c in compilers[architecture] if not c.name.startswith("docker:")]
    
    if not native_compilers:
        # TODO: Add Docker support for assembly
        return CompilerResult(
            success=False,
            stderr=f"No native assembler found for {architecture}. Docker assembly not yet supported.",
            architecture=architecture,
        )
    
    compiler = native_compilers[0]
    return compiler.assemble(source, output)


def get_available_architectures() -> list[Architecture]:
    """Get list of architectures with available compilers."""
    compilers = detect_compilers()
    return [arch for arch, comps in compilers.items() if comps]


def get_compile_command_preview(
    architecture: Architecture = "arm64",
    optimization: str = "-O0",
    freestanding: bool = False,
    output_name: str = "output",
) -> dict[str, str | bool]:
    """Get a preview of the compilation command that would run.
    
    Returns:
        Dictionary with:
        - command: The full command string
        - uses_docker: Whether Docker will be used
        - compiler: Name of the compiler
        - available: Whether compilation is possible
    """
    compilers = detect_compilers()
    
    # Build extra flags
    extra_flags = []
    if freestanding:
        extra_flags = ["-ffreestanding", "-nostdlib", "-static"]
    
    # Determine which compiler will be used
    if architecture in ("arm32", "arm64"):
        has_real_cross_compiler = any(
            not c.is_clang and not c.name.startswith("docker:")
            for c in compilers.get(architecture, [])
        )
        
        if has_real_cross_compiler:
            compiler = next(
                c for c in compilers[architecture]
                if not c.is_clang and not c.name.startswith("docker:")
            )
            cmd_parts = [compiler.name, optimization, "-g", "-fno-stack-protector"]
            cmd_parts.extend(extra_flags)
            cmd_parts.extend(["-o", output_name, "source.c"])
            return {
                "command": " ".join(cmd_parts),
                "uses_docker": False,
                "compiler": compiler.name,
                "available": True,
            }
        
        # Docker compilation
        docker_available = _is_docker_available()
        image_exists = docker_available and _docker_image_exists(DOCKER_COMPILER_IMAGE)
        
        if architecture == "arm32":
            docker_compiler = "arm-linux-gnueabihf-gcc"
        else:
            docker_compiler = "aarch64-linux-gnu-gcc"
        
        cmd_parts = [
            "docker", "run", "--rm", 
            "-v", "/path:/compile", "-w", "/compile",
            DOCKER_COMPILER_IMAGE, docker_compiler,
            optimization, "-g", "-fno-stack-protector",
        ]
        cmd_parts.extend(extra_flags)
        cmd_parts.extend(["-o", output_name, "source.c"])
        
        return {
            "command": " ".join(cmd_parts),
            "uses_docker": True,
            "compiler": f"docker:{docker_compiler}",
            "available": image_exists,
            "docker_running": docker_available,
            "image_exists": image_exists,
        }
    
    # x86/x86_64
    if compilers[architecture]:
        compiler = compilers[architecture][0]
        cmd_parts = [compiler.name, optimization, "-g", "-fno-stack-protector"]
        cmd_parts.extend(extra_flags)
        cmd_parts.extend(["-o", output_name, "source.c"])
        return {
            "command": " ".join(cmd_parts),
            "uses_docker": False,
            "compiler": compiler.name,
            "available": True,
        }
    
    return {
        "command": "",
        "uses_docker": False,
        "compiler": "none",
        "available": False,
    }
