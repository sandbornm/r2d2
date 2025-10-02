"""Environment detection and verification."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..config import AppConfig
from .ghidra import GhidraDetection, detect_ghidra


@dataclass(slots=True)
class ToolCheck:
    name: str
    command: str | None
    available: bool
    version: str | None = None
    path: Path | None = None
    details: str | None = None


@dataclass(slots=True)
class EnvironmentReport:
    python_version: str
    uv_available: bool
    openai_key_present: bool
    tools: list[ToolCheck] = field(default_factory=list)
    ghidra: GhidraDetection | None = None
    issues: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def missing_tools(self) -> list[str]:
        return [t.name for t in self.tools if not t.available]


_COMMANDS: dict[str, list[str]] = {
    "radare2": ["radare2", "r2"],
    "ghidra": ["ghidraRun", "analyzeHeadless"],
    "docker": ["docker"],
}


def _check_command(name: str, candidates: Iterable[str]) -> ToolCheck:
    for candidate in candidates:
        path = shutil.which(candidate)
        if not path:
            continue
        version = _probe_version(candidate)
        return ToolCheck(name=name, command=candidate, available=True, version=version, path=Path(path))
    return ToolCheck(name=name, command=None, available=False)


def _probe_version(command: str) -> str | None:
    try:
        output = subprocess.check_output([command, "--version"], stderr=subprocess.STDOUT, timeout=4)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return output.decode().splitlines()[0].strip()


def _check_python_module(module: str) -> ToolCheck:
    try:
        __import__(module)
    except ModuleNotFoundError:
        return ToolCheck(name=module, command=module, available=False)
    return ToolCheck(name=module, command=module, available=True)


def detect_environment(config: AppConfig) -> EnvironmentReport:
    report = EnvironmentReport(
        python_version=sys.version.split()[0],
        uv_available=shutil.which("uv") is not None,
        openai_key_present=config.llm.api_key_env in os.environ,
    )

    report.tools.append(_check_command("radare2", _COMMANDS["radare2"]))
    report.tools.append(_check_command("docker", _COMMANDS["docker"]))
    report.tools.append(_check_python_module("r2pipe"))
    report.tools.append(_check_python_module("capstone"))
    if config.analysis.enable_angr:
        report.tools.append(_check_python_module("angr"))

    ghidra_detection = detect_ghidra(config)
    report.ghidra = ghidra_detection
    report.notes.extend(ghidra_detection.notes)
    report.issues.extend(ghidra_detection.issues)

    for tool in report.tools:
        if not tool.available:
            report.issues.append(f"Missing dependency: {tool.name}")

    if not report.uv_available:
        report.issues.append("uv package manager not found on PATH.")

    if not report.openai_key_present:
        report.notes.append(
            f"Environment variable {config.llm.api_key_env} not detected; LLM calls will fail until set."
        )

    return report


__all__ = ["EnvironmentReport", "ToolCheck", "detect_environment"]
