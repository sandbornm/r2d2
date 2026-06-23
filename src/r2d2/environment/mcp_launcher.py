"""Launch configured MCP-adjacent analysis services."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..config import AppConfig, MCPServerSettings


class MCPLaunchError(RuntimeError):
    """Raised when a requested MCP service cannot be planned."""


@dataclass(slots=True)
class MCPLaunchResult:
    """Launch attempt or dry-run plan for one configured MCP service."""

    name: str
    status: str
    command: list[str] = field(default_factory=list)
    working_dir: str | None = None
    pid: int | None = None
    log_path: str | None = None
    details: str = ""
    url: str | None = None


def launch_mcp_services(
    config: AppConfig,
    *,
    selected: list[str] | None = None,
    dry_run: bool = False,
    foreground: bool = False,
    project_root: Path | None = None,
    log_dir: Path | None = None,
) -> dict[str, MCPLaunchResult]:
    """Launch configured MCP services using their start_command metadata."""

    servers = config.mcp.configured_servers()
    selected_names = selected or list(servers)
    unknown = sorted(set(selected_names) - set(servers))
    if unknown:
        raise MCPLaunchError(f"Unknown MCP service(s): {', '.join(unknown)}")

    project_root = project_root or Path(__file__).resolve().parents[3]
    log_dir = (log_dir or Path("~/.local/state/r2d2/mcp").expanduser()).expanduser()
    results: dict[str, MCPLaunchResult] = {}

    for name in selected_names:
        settings = servers[name]
        results[name] = _launch_one(
            name,
            settings,
            dry_run=dry_run,
            foreground=foreground,
            project_root=project_root,
            log_dir=log_dir,
        )

    return results


def _launch_one(
    name: str,
    settings: MCPServerSettings,
    *,
    dry_run: bool,
    foreground: bool,
    project_root: Path,
    log_dir: Path,
) -> MCPLaunchResult:
    command = _service_start_command(settings)
    working_dir = _resolve_working_dir(settings.working_dir, project_root=project_root)
    result = MCPLaunchResult(
        name=name,
        status="planned" if dry_run else "skipped",
        command=command,
        working_dir=str(working_dir) if working_dir else None,
        url=settings.url,
    )

    if not settings.enabled:
        result.status = "disabled"
        result.details = "Disabled in configuration."
        return result

    if not command:
        result.status = "skipped"
        result.details = settings.install_hint or "No start_command configured."
        return result

    if working_dir is not None and not working_dir.exists():
        result.status = "failed"
        result.details = f"Working directory does not exist: {working_dir}"
        return result

    executable = shutil.which(command[0])
    if executable is None:
        result.status = "failed"
        result.details = f"Command not found on PATH: {command[0]}"
        return result

    if dry_run:
        result.details = "Dry run; command was not executed."
        return result

    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{name}.log"
    result.log_path = str(log_path)

    with log_path.open("ab") as log_file:
        env = os.environ.copy()
        if foreground:
            completed = subprocess.run(command, cwd=working_dir, env=env, stdout=log_file, stderr=subprocess.STDOUT, check=False)
            result.status = "completed" if completed.returncode == 0 else "failed"
            result.details = f"Exited with code {completed.returncode}; output captured in {log_path}"
            return result

        process = subprocess.Popen(  # noqa: S603 - command is an argv list from config, not shell-expanded.
            command,
            cwd=working_dir,
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    result.status = "started"
    result.pid = process.pid
    result.details = f"Started in background; output captured in {log_path}"
    return result


def _service_start_command(settings: MCPServerSettings) -> list[str]:
    if settings.start_command:
        return list(settings.start_command)
    if settings.command:
        return [settings.command, *settings.args]
    return []


def _resolve_working_dir(value: str | None, *, project_root: Path) -> Path | None:
    if not value:
        return None
    path = Path(value).expanduser()
    if path.is_absolute():
        return path

    cwd_candidate = (Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate

    return (project_root / path).resolve()
