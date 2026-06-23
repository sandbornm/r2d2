"""Environment detection and verification."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import httpx

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
class MCPConnectionCheck:
    name: str
    enabled: bool
    transport: str
    available: bool
    url: str | None = None
    active_url: str | None = None
    command: str | None = None
    args: list[str] = field(default_factory=list)
    command_available: bool | None = None
    start_command: list[str] = field(default_factory=list)
    working_dir: str | None = None
    status_code: int | None = None
    capabilities_count: int | None = None
    latency_ms: float | None = None
    description: str | None = None
    install_hint: str | None = None
    details: str | None = None


@dataclass(slots=True)
class EnvironmentReport:
    python_version: str
    uv_available: bool
    openai_key_present: bool
    tools: list[ToolCheck] = field(default_factory=list)
    mcp_connections: dict[str, MCPConnectionCheck] = field(default_factory=dict)
    ghidra: GhidraDetection | None = None
    issues: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def missing_tools(self) -> list[str]:
        return [t.name for t in self.tools if not t.available]


_COMMANDS: dict[str, list[str]] = {
    "radare2": ["radare2", "r2"],
    "ghidra": ["ghidraRun", "analyzeHeadless"],
    "docker": ["docker"],
    "ollama": ["ollama"],
    "qemu": ["qemu-system-x86_64", "qemu-system-aarch64"],
    "frida": ["frida-server", "frida"],
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
    except Exception as exc:
        # Handle import errors from broken dependencies (e.g. angr + msgspec mismatch)
        return ToolCheck(
            name=module,
            command=module,
            available=False,
            details=f"Import failed: {type(exc).__name__}: {exc}",
        )
    return ToolCheck(name=module, command=module, available=True)


def _join_url(base_url: str, path: str | None) -> str:
    if not path:
        return base_url
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def _http_status_means_reachable(status_code: int) -> bool:
    return status_code < 500 and status_code != 404


def _response_matches_expected_service(name: str, response: httpx.Response) -> bool:
    if not _http_status_means_reachable(response.status_code):
        return False
    content_type = response.headers.get("content-type", "").lower()
    if "text/html" in content_type:
        return False
    if name == "ghidra_gdb":
        try:
            payload = response.json()
        except ValueError:
            return False
        return (
            isinstance(payload, dict)
            and payload.get("status") == "ok"
            and any(key in payload for key in ("platform", "qemu_architectures", "note"))
        )
    return True


def _count_capabilities(payload: object) -> int | None:
    if isinstance(payload, list):
        return len(payload)
    if not isinstance(payload, dict):
        return None
    for key in ("methods", "tools", "capabilities"):
        value = payload.get(key)
        if isinstance(value, (list, dict)):
            return len(value)
    return len(payload)


def _check_mcp_command(command: str | None) -> bool | None:
    if not command:
        return None
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    executable = parts[0] if parts else command
    if "/" in executable:
        return Path(executable).expanduser().exists()
    return shutil.which(executable) is not None


def _probe_mcp_http(name: str, config: AppConfig) -> MCPConnectionCheck:
    settings = config.mcp.configured_servers()[name]
    command_available = _check_mcp_command(settings.command)
    urls = [url for url in [settings.url, *settings.fallback_urls] if url]
    errors: list[str] = []

    for base_url in urls:
        health_url = _join_url(base_url, settings.health_path)
        started = time.perf_counter()
        try:
            response = httpx.get(health_url, timeout=settings.timeout)
        except httpx.TimeoutException:
            errors.append(f"{health_url}: timeout after {settings.timeout}s")
            continue
        except httpx.HTTPError as exc:
            errors.append(f"{health_url}: {type(exc).__name__}: {exc}")
            continue

        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        capabilities_count: int | None = None
        if settings.capabilities_path:
            capabilities_url = _join_url(base_url, settings.capabilities_path)
            capabilities_response = response if capabilities_url == health_url else None
            try:
                if capabilities_response is None:
                    capabilities_response = httpx.get(capabilities_url, timeout=settings.timeout)
                if _http_status_means_reachable(capabilities_response.status_code):
                    capabilities_count = _count_capabilities(capabilities_response.json())
            except Exception:
                capabilities_count = None

        if _response_matches_expected_service(name, response):
            details = f"HTTP {response.status_code}"
            if capabilities_count is not None:
                details = f"{details}; {capabilities_count} capabilities"
            return MCPConnectionCheck(
                name=name,
                enabled=settings.enabled,
                transport=settings.transport,
                available=True,
                url=settings.url,
                active_url=base_url,
                command=settings.command,
                args=list(settings.args),
                command_available=command_available,
                start_command=list(settings.start_command),
                working_dir=settings.working_dir,
                status_code=response.status_code,
                capabilities_count=capabilities_count,
                latency_ms=latency_ms,
                description=settings.description,
                install_hint=settings.install_hint,
                details=details,
            )
        errors.append(f"{health_url}: unexpected response HTTP {response.status_code}")

    return MCPConnectionCheck(
        name=name,
        enabled=settings.enabled,
        transport=settings.transport,
        available=False,
        url=settings.url,
        command=settings.command,
        args=list(settings.args),
        command_available=command_available,
        start_command=list(settings.start_command),
        working_dir=settings.working_dir,
        description=settings.description,
        install_hint=settings.install_hint,
        details="; ".join(errors) if errors else "No URL configured.",
    )


def _probe_mcp_streamable_http(name: str, config: AppConfig) -> MCPConnectionCheck:
    settings = config.mcp.configured_servers()[name]
    command_available = _check_mcp_command(settings.command)
    urls = [url for url in [settings.url, *settings.fallback_urls] if url]
    errors: list[str] = []

    for base_url in urls:
        started = time.perf_counter()
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        initialize_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "r2d2", "version": "0.1.0"},
            },
        }
        try:
            response = httpx.post(base_url, json=initialize_payload, headers=headers, timeout=settings.timeout)
        except httpx.TimeoutException:
            errors.append(f"{base_url}: timeout after {settings.timeout}s")
            continue
        except httpx.HTTPError as exc:
            errors.append(f"{base_url}: {type(exc).__name__}: {exc}")
            continue

        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        payload = _mcp_json_payload(response)
        if not _http_status_means_reachable(response.status_code) or not isinstance(payload, dict) or payload.get("error"):
            errors.append(f"{base_url}: unexpected MCP initialize HTTP {response.status_code}")
            continue

        session_id = response.headers.get("Mcp-Session-Id")
        capabilities_count: int | None = None
        try:
            notify_headers = dict(headers)
            if session_id:
                notify_headers["Mcp-Session-Id"] = session_id
            httpx.post(
                base_url,
                json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                headers=notify_headers,
                timeout=settings.timeout,
            )
            tools_response = httpx.post(
                base_url,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                headers=notify_headers,
                timeout=settings.timeout,
            )
            tools_payload = _mcp_json_payload(tools_response)
            result = tools_payload.get("result") if isinstance(tools_payload, dict) else None
            if isinstance(result, dict) and isinstance(result.get("tools"), list):
                capabilities_count = len(result["tools"])
        except Exception:
            capabilities_count = None

        details = f"MCP initialize HTTP {response.status_code}"
        if capabilities_count is not None:
            details = f"{details}; {capabilities_count} tools"
        return MCPConnectionCheck(
            name=name,
            enabled=settings.enabled,
            transport=settings.transport,
            available=True,
            url=settings.url,
            active_url=base_url,
            command=settings.command,
            args=list(settings.args),
            command_available=command_available,
            start_command=list(settings.start_command),
            working_dir=settings.working_dir,
            status_code=response.status_code,
            capabilities_count=capabilities_count,
            latency_ms=latency_ms,
            description=settings.description,
            install_hint=settings.install_hint,
            details=details,
        )

    return MCPConnectionCheck(
        name=name,
        enabled=settings.enabled,
        transport=settings.transport,
        available=False,
        url=settings.url,
        command=settings.command,
        args=list(settings.args),
        command_available=command_available,
        start_command=list(settings.start_command),
        working_dir=settings.working_dir,
        description=settings.description,
        install_hint=settings.install_hint,
        details="; ".join(errors) if errors else "No URL configured.",
    )


def _mcp_json_payload(response: httpx.Response) -> dict[str, object]:
    content_type = response.headers.get("content-type", "").lower()
    if "text/event-stream" in content_type:
        text = response.text
        for line in text.splitlines():
            if not line.startswith("data:"):
                continue
            data = line.partition(":")[2].strip()
            if not data:
                continue
            try:
                parsed = json.loads(data)
            except ValueError:
                continue
            return parsed if isinstance(parsed, dict) else {"payload": parsed}
        return {"text": text[:1000]}
    try:
        parsed = response.json()
    except ValueError:
        return {"text": response.text[:1000]}
    return parsed if isinstance(parsed, dict) else {"payload": parsed}


def _probe_mcp_stdio(name: str, config: AppConfig) -> MCPConnectionCheck:
    settings = config.mcp.configured_servers()[name]
    command_available = _check_mcp_command(settings.command)
    return MCPConnectionCheck(
        name=name,
        enabled=settings.enabled,
        transport=settings.transport,
        available=bool(command_available),
        command=settings.command,
        args=list(settings.args),
        command_available=command_available,
        start_command=list(settings.start_command),
        working_dir=settings.working_dir,
        description=settings.description,
        install_hint=settings.install_hint,
        details="Command is on PATH." if command_available else "Command not found on PATH.",
    )


def detect_mcp_connections(config: AppConfig) -> dict[str, MCPConnectionCheck]:
    checks: dict[str, MCPConnectionCheck] = {}
    for name, settings in config.mcp.configured_servers().items():
        if not settings.enabled:
            checks[name] = MCPConnectionCheck(
                name=name,
                enabled=False,
                transport=settings.transport,
                available=False,
                url=settings.url,
                command=settings.command,
                args=list(settings.args),
                start_command=list(settings.start_command),
                working_dir=settings.working_dir,
                description=settings.description,
                install_hint=settings.install_hint,
                details="Disabled in configuration.",
            )
            continue

        transport = settings.transport.lower()
        if transport == "streamable-http":
            checks[name] = _probe_mcp_streamable_http(name, config)
        elif transport in {"http", "sse"}:
            checks[name] = _probe_mcp_http(name, config)
        elif transport == "stdio":
            checks[name] = _probe_mcp_stdio(name, config)
        else:
            checks[name] = MCPConnectionCheck(
                name=name,
                enabled=settings.enabled,
                transport=settings.transport,
                available=False,
                url=settings.url,
                command=settings.command,
                args=list(settings.args),
                start_command=list(settings.start_command),
                working_dir=settings.working_dir,
                description=settings.description,
                install_hint=settings.install_hint,
                details=f"Unsupported MCP transport: {settings.transport}",
            )
    return checks


def detect_environment(config: AppConfig) -> EnvironmentReport:
    report = EnvironmentReport(
        python_version=sys.version.split()[0],
        uv_available=shutil.which("uv") is not None,
        openai_key_present=config.llm.api_key_env in os.environ,
    )
    report.mcp_connections = detect_mcp_connections(config)

    report.tools.append(_check_command("radare2", _COMMANDS["radare2"]))
    report.tools.append(_check_command("docker", _COMMANDS["docker"]))
    if config.llm.provider.lower() in {"ollama", "local"} or (
        config.llm.enable_fallback and (config.llm.fallback_provider or "").lower() in {"ollama", "local"}
    ):
        report.tools.append(_check_command("ollama", _COMMANDS["ollama"]))
    report.tools.append(_check_python_module("r2pipe"))
    report.tools.append(_check_python_module("capstone"))
    if config.analysis.enable_angr:
        report.tools.append(_check_python_module("angr"))
    if config.llm.provider.lower() in {"anthropic", "claude"} or (
        config.llm.enable_fallback and (config.llm.fallback_provider or "").lower() in {"anthropic", "claude"}
    ):
        report.tools.append(_check_python_module("anthropic"))

    # Optional runtime tools helpful for replay/debugging.
    report.tools.append(_check_command("qemu", _COMMANDS["qemu"]))
    report.tools.append(_check_command("frida", _COMMANDS["frida"]))

    ghidra_detection = detect_ghidra(config)
    report.ghidra = ghidra_detection
    report.notes.extend(ghidra_detection.notes)
    report.issues.extend(ghidra_detection.issues)

    optional_tools = {"qemu", "frida"}
    for tool in report.tools:
        if not tool.available:
            if tool.name in optional_tools:
                report.notes.append(f"Optional tool missing: {tool.name}")
            else:
                report.issues.append(f"Missing dependency: {tool.name}")

    if not report.uv_available:
        report.issues.append("uv package manager not found on PATH.")

    if config.llm.provider.lower() not in {"ollama", "local"} and not report.openai_key_present:
        report.notes.append(
            f"Environment variable {config.llm.api_key_env} not detected; LLM calls will fail until set."
        )
    if config.llm.enable_fallback and config.llm.fallback_api_key_env:
        if config.llm.fallback_api_key_env not in os.environ:
            report.notes.append(
                f"Fallback LLM key {config.llm.fallback_api_key_env} not detected; fallback provider disabled."
            )

    return report


__all__ = ["EnvironmentReport", "MCPConnectionCheck", "ToolCheck", "detect_environment", "detect_mcp_connections"]
