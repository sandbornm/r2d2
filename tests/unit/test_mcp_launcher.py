"""Unit tests for MCP service launching."""

from __future__ import annotations

import pytest

from r2d2.config import AppConfig, MCPServerSettings, MCPSettings
from r2d2.environment.mcp_launcher import MCPLaunchError, launch_mcp_services


def test_launch_mcp_services_dry_run_uses_configured_start_commands(tmp_path, monkeypatch):
    project_root = tmp_path / "r2d2"
    project_root.mkdir()
    (tmp_path / "GhidraMCP" / "docker").mkdir(parents=True)
    (tmp_path / "angr_mcp").mkdir()
    monkeypatch.chdir(project_root)
    monkeypatch.setattr("r2d2.environment.mcp_launcher.shutil.which", lambda command: f"/bin/{command}")

    results = launch_mcp_services(AppConfig(), dry_run=True, project_root=project_root)

    assert results["ghidra_mcp"].status == "skipped"
    assert results["ghidra_mcp"].command == []
    assert "GhidraMCP plugin" in results["ghidra_mcp"].details
    assert results["ghidra_gdb"].status == "planned"
    assert results["ghidra_gdb"].command == ["docker", "compose", "up", "-d", "--build"]
    assert results["ghidra_gdb"].working_dir == str(tmp_path / "GhidraMCP" / "docker")
    assert results["angr_mcp"].status == "planned"
    assert results["angr_mcp"].command[:3] == ["uv", "run", "angr-mcp-dev-server"]
    assert results["angr_mcp"].working_dir == str(tmp_path / "angr_mcp")


def test_launch_mcp_services_rejects_unknown_service():
    with pytest.raises(MCPLaunchError, match="Unknown MCP service"):
        launch_mcp_services(AppConfig(), selected=["missing"], dry_run=True)


def test_launch_mcp_services_reports_missing_working_dir(tmp_path, monkeypatch):
    config = AppConfig(
        mcp=MCPSettings(
            ghidra_mcp=MCPServerSettings(enabled=False),
            ghidra_gdb=MCPServerSettings(enabled=False),
            angr_mcp=MCPServerSettings(
                transport="streamable-http",
                url="http://127.0.0.1:8766/mcp",
                start_command=["uv", "run", "angr-mcp-dev-server"],
                working_dir=str(tmp_path / "missing"),
            ),
        )
    )
    monkeypatch.setattr("r2d2.environment.mcp_launcher.shutil.which", lambda command: f"/bin/{command}")

    results = launch_mcp_services(config, selected=["angr_mcp"], dry_run=True)

    assert results["angr_mcp"].status == "failed"
    assert "Working directory does not exist" in results["angr_mcp"].details


def test_launch_mcp_services_starts_background_process(tmp_path, monkeypatch):
    working_dir = tmp_path / "angr_mcp"
    working_dir.mkdir()
    config = AppConfig(
        mcp=MCPSettings(
            ghidra_mcp=MCPServerSettings(enabled=False),
            ghidra_gdb=MCPServerSettings(enabled=False),
            angr_mcp=MCPServerSettings(
                transport="streamable-http",
                url="http://127.0.0.1:8766/mcp",
                start_command=["uv", "run", "angr-mcp-dev-server"],
                working_dir=str(working_dir),
            ),
        )
    )
    calls: list[dict[str, object]] = []

    class FakeProcess:
        pid = 4242

    def fake_popen(command, **kwargs):  # noqa: ANN001
        calls.append({"command": command, **kwargs})
        return FakeProcess()

    monkeypatch.setattr("r2d2.environment.mcp_launcher.shutil.which", lambda command: f"/bin/{command}")
    monkeypatch.setattr("r2d2.environment.mcp_launcher.subprocess.Popen", fake_popen)

    results = launch_mcp_services(config, selected=["angr_mcp"], log_dir=tmp_path / "logs")

    assert results["angr_mcp"].status == "started"
    assert results["angr_mcp"].pid == 4242
    assert results["angr_mcp"].log_path == str(tmp_path / "logs" / "angr_mcp.log")
    assert calls[0]["command"] == ["uv", "run", "angr-mcp-dev-server"]
    assert calls[0]["cwd"] == working_dir
    assert calls[0]["start_new_session"] is True
