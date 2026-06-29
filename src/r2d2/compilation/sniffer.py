"""Lightweight compiler capability probing for the web UI."""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .compiler import (
    ARM32_COMPILERS,
    ARM64_COMPILERS,
    DOCKER_COMPILER_IMAGE,
    X86_COMPILERS,
    X86_64_COMPILERS,
    Compiler,
    _docker_image_exists,
    _is_docker_available,
    detect_compilers,
    get_compile_command_preview,
)

ARCH_LABELS: dict[str, str] = {
    "arm32": "ARM32 (armhf)",
    "arm64": "ARM64 (AArch64)",
    "x86": "x86",
    "x86_64": "x86_64",
}

ARCH_CANDIDATES: dict[str, list[str]] = {
    "arm32": ARM32_COMPILERS,
    "arm64": ARM64_COMPILERS,
    "x86": X86_COMPILERS,
    "x86_64": X86_64_COMPILERS,
}


def sniff_compiler_capabilities() -> dict[str, Any]:
    """Return a no-compile snapshot of compiler and helper availability."""

    errors: list[str] = []
    try:
        compilers = detect_compilers()
    except Exception as exc:  # pragma: no cover - defensive UI fallback
        compilers = {"arm32": [], "arm64": [], "x86": [], "x86_64": []}
        errors.append(str(exc))

    docker_available = _is_docker_available()
    docker_image_exists = docker_available and _docker_image_exists(DOCKER_COMPILER_IMAGE)
    native_objdump = shutil.which("objdump")

    architectures = {
        arch: _architecture_snapshot(
            arch,
            compilers.get(arch, []),
            docker_available=docker_available,
            docker_image_exists=docker_image_exists,
            native_objdump=native_objdump,
        )
        for arch in ("arm32", "arm64", "x86", "x86_64")
    }

    available_architectures = [
        arch
        for arch, snapshot in architectures.items()
        if snapshot["operations"]["compile_c"]["supported"] or snapshot["operations"]["emit_asm"]["supported"]
    ]
    if all(arch["state"] == "missing" for arch in architectures.values()):
        state = "missing"
    elif errors:
        state = "error"
    elif any(arch["state"] == "ready" for arch in architectures.values()):
        state = "ready"
    else:
        state = "degraded"

    return {
        "state": state,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "compilers": {
            arch: [_compiler_to_dict(compiler) for compiler in compiler_list]
            for arch, compiler_list in compilers.items()
        },
        "available_architectures": available_architectures,
        "docker_available": docker_available,
        "docker_image_exists": docker_image_exists,
        "docker": {
            "available": docker_available,
            "image": DOCKER_COMPILER_IMAGE,
            "image_exists": docker_image_exists,
            "action": None if docker_image_exists else f"docker build -t {DOCKER_COMPILER_IMAGE} -f Dockerfile.compiler .",
        },
        "helpers": {
            "objdump": {
                "available": native_objdump is not None,
                "path": native_objdump,
                "action": None if native_objdump else "Install binutils/objdump or build the Docker compiler image",
            },
        },
        "architectures": architectures,
        "install_hints": _install_hints(docker_available=docker_available, docker_image_exists=docker_image_exists),
        "errors": errors,
    }


def preview_compile_with_capabilities(
    *,
    architecture: str = "arm64",
    optimization: str = "-O0",
    freestanding: bool = False,
    output_name: str = "output",
) -> dict[str, Any]:
    """Preserve the existing command preview while adding support diagnostics."""

    try:
        preview = dict(
            get_compile_command_preview(
                architecture=architecture,  # type: ignore[arg-type]
                optimization=optimization,
                freestanding=freestanding,
                output_name=output_name or "output",
            )
        )
    except Exception as exc:
        preview = {
            "command": "",
            "uses_docker": False,
            "compiler": "none",
            "available": False,
            "error": str(exc),
        }

    snapshot = sniff_compiler_capabilities()
    arch_snapshot = snapshot.get("architectures", {}).get(architecture)
    compile_op = arch_snapshot.get("operations", {}).get("compile_c") if isinstance(arch_snapshot, dict) else None
    if isinstance(compile_op, dict):
        preview.update(
            {
                "mode": compile_op.get("mode"),
                "reason": compile_op.get("reason"),
                "action": compile_op.get("action"),
                "requirements": compile_op.get("requirements", []),
                "capability_state": arch_snapshot.get("state"),
            }
        )
    return preview


def _architecture_snapshot(
    arch: str,
    compilers: list[Compiler],
    *,
    docker_available: bool,
    docker_image_exists: bool,
    native_objdump: str | None,
) -> dict[str, Any]:
    native = _preferred_native_compiler(compilers, arch)
    has_docker = arch in {"arm32", "arm64"} and docker_image_exists
    compile_supported = native is not None or has_docker
    checked = _checked_candidates(arch)
    operations = {
        "compile_c": _compile_operation(arch, native, docker_available=docker_available, docker_image_exists=docker_image_exists),
        "emit_asm": _compile_operation(arch, native, docker_available=docker_available, docker_image_exists=docker_image_exists),
        "assemble": _assemble_operation(arch, native, compilers),
        "listing": _listing_operation(arch, native_objdump=native_objdump, docker_image_exists=docker_image_exists),
    }
    if compile_supported and all(operation["supported"] for operation in operations.values()):
        state = "ready"
    elif compile_supported:
        state = "degraded"
    else:
        state = "missing"
    return {
        "arch": arch,
        "label": ARCH_LABELS.get(arch, arch),
        "state": state,
        "compilers": [_compiler_to_dict(compiler) for compiler in compilers],
        "checked_candidates": checked,
        "operations": operations,
        "recommended_arch": arch,
    }


def _preferred_native_compiler(compilers: list[Compiler], arch: str) -> Compiler | None:
    real_cross = [
        compiler
        for compiler in compilers
        if not compiler.name.startswith("docker:") and (arch not in {"arm32", "arm64"} or not compiler.is_clang)
    ]
    if real_cross:
        return real_cross[0]
    if arch not in {"arm32", "arm64"}:
        native = [compiler for compiler in compilers if not compiler.name.startswith("docker:")]
        if native:
            return native[0]
    return None


def _compile_operation(
    arch: str,
    native: Compiler | None,
    *,
    docker_available: bool,
    docker_image_exists: bool,
) -> dict[str, Any]:
    if native:
        return {
            "supported": True,
            "mode": "native",
            "compiler": native.name,
            "reason": f"Using native compiler at {native.path}",
            "action": None,
            "requirements": [],
        }
    if arch in {"arm32", "arm64"}:
        compiler = "arm-linux-gnueabihf-gcc" if arch == "arm32" else "aarch64-linux-gnu-gcc"
        if docker_image_exists:
            return {
                "supported": True,
                "mode": "docker",
                "compiler": f"docker:{compiler}",
                "reason": f"Using {DOCKER_COMPILER_IMAGE} for cross-compilation",
                "action": None,
                "requirements": [DOCKER_COMPILER_IMAGE],
            }
        if docker_available:
            return {
                "supported": False,
                "mode": "unavailable",
                "compiler": f"docker:{compiler}",
                "reason": f"Docker is running, but {DOCKER_COMPILER_IMAGE} is not built",
                "action": f"docker build -t {DOCKER_COMPILER_IMAGE} -f Dockerfile.compiler .",
                "requirements": [DOCKER_COMPILER_IMAGE],
            }
        return {
            "supported": False,
            "mode": "unavailable",
            "compiler": f"docker:{compiler}",
            "reason": "No native cross-compiler and Docker is not available",
            "action": "Start Docker Desktop or install an ARM cross-compiler",
            "requirements": ["docker"],
        }
    return {
        "supported": False,
        "mode": "unavailable",
        "compiler": None,
        "reason": f"No compiler found for {arch}",
        "action": "Install gcc or clang",
        "requirements": ARCH_CANDIDATES.get(arch, ["gcc", "clang"]),
    }


def _assemble_operation(arch: str, native: Compiler | None, compilers: list[Compiler]) -> dict[str, Any]:
    native_assembler = native or next((compiler for compiler in compilers if not compiler.name.startswith("docker:")), None)
    if native_assembler:
        return {
            "supported": True,
            "mode": "native",
            "compiler": native_assembler.name,
            "reason": "Assembly uses the native compiler/assembler path",
            "action": None,
            "requirements": [],
        }
    if arch in {"arm32", "arm64"} and any(compiler.name.startswith("docker:") for compiler in compilers):
        return {
            "supported": False,
            "mode": "unavailable",
            "compiler": None,
            "reason": "Docker assembly is not implemented yet; C-to-ELF and C-to-assembly are supported",
            "action": "Install a native assembler for this architecture",
            "requirements": ARCH_CANDIDATES.get(arch, []),
        }
    return {
        "supported": False,
        "mode": "unavailable",
        "compiler": None,
        "reason": f"No native assembler found for {arch}",
        "action": "Install gcc/binutils for this target",
        "requirements": ARCH_CANDIDATES.get(arch, []),
    }


def _listing_operation(arch: str, *, native_objdump: str | None, docker_image_exists: bool) -> dict[str, Any]:
    if docker_image_exists and arch in {"arm32", "arm64"}:
        return {
            "supported": True,
            "mode": "docker",
            "compiler": "objdump",
            "reason": f"Using objdump from {DOCKER_COMPILER_IMAGE}",
            "action": None,
            "requirements": [DOCKER_COMPILER_IMAGE],
        }
    if native_objdump:
        return {
            "supported": True,
            "mode": "native",
            "compiler": Path(native_objdump).name,
            "reason": f"Using native objdump at {native_objdump}",
            "action": None,
            "requirements": [],
        }
    return {
        "supported": False,
        "mode": "unavailable",
        "compiler": None,
        "reason": "No objdump helper found",
        "action": "Install binutils/objdump or build the Docker compiler image",
        "requirements": ["objdump"],
    }


def _checked_candidates(arch: str) -> list[dict[str, Any]]:
    checked = []
    for candidate in ARCH_CANDIDATES.get(arch, []):
        path = shutil.which(candidate)
        checked.append({"name": candidate, "path": path, "available": path is not None})
    return checked


def _compiler_to_dict(compiler: Compiler) -> dict[str, Any]:
    return {
        "name": compiler.name,
        "path": str(compiler.path),
        "version": compiler.version,
        "is_clang": compiler.is_clang,
    }


def _install_hints(*, docker_available: bool, docker_image_exists: bool) -> list[str]:
    hints = ["Install native gcc/clang for x86 targets or ARM cross-compilers for direct ARM builds"]
    if not docker_available:
        hints.append("Start Docker Desktop for ARM cross-compilation fallback")
    elif not docker_image_exists:
        hints.append(f"docker build -t {DOCKER_COMPILER_IMAGE} -f Dockerfile.compiler .")
    return hints
