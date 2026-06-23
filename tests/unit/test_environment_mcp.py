"""Unit tests for MCP connection detection."""

from __future__ import annotations

import httpx

from r2d2.config import AppConfig, MCPServerSettings, MCPSettings
from r2d2.environment.detectors import detect_mcp_connections


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        payload: object | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers = headers or {"content-type": "application/json"}
        self.text = "" if isinstance(self._payload, dict) else str(self._payload)

    def json(self) -> object:
        return self._payload


def test_detect_mcp_connections_reports_http_and_stdio(monkeypatch):
    """Test MCP checks report reachable HTTP services and available stdio commands."""
    config = AppConfig(
        mcp=MCPSettings(
            ghidra_mcp=MCPServerSettings(
                transport="http",
                url="http://127.0.0.1:8080",
                health_path="/methods",
                capabilities_path="/methods",
            ),
            ghidra_gdb=MCPServerSettings(enabled=False, transport="http", url="http://127.0.0.1:5051"),
            angr_mcp=MCPServerSettings(transport="stdio", command="angr-mcp-dev-server"),
        )
    )

    def fake_get(url: str, timeout: float) -> FakeResponse:
        assert url == "http://127.0.0.1:8080/methods"
        assert timeout == 1.5
        return FakeResponse(200, {"currentProgram": {}, "listFunctions": {}})

    monkeypatch.setattr("r2d2.environment.detectors.httpx.get", fake_get)
    monkeypatch.setattr("r2d2.environment.detectors.shutil.which", lambda command: f"/bin/{command}")

    checks = detect_mcp_connections(config)

    assert checks["ghidra_mcp"].available is True
    assert checks["ghidra_mcp"].status_code == 200
    assert checks["ghidra_mcp"].capabilities_count == 2
    assert checks["ghidra_gdb"].available is False
    assert checks["ghidra_gdb"].details == "Disabled in configuration."
    assert checks["angr_mcp"].available is True
    assert checks["angr_mcp"].command_available is True


def test_detect_mcp_connections_uses_http_fallback(monkeypatch):
    """Test HTTP MCP checks try configured fallback URLs."""
    config = AppConfig(
        mcp=MCPSettings(
            ghidra_mcp=MCPServerSettings(
                transport="http",
                url="http://127.0.0.1:8080",
                fallback_urls=["http://127.0.0.1:18080"],
                health_path="/health",
            ),
            ghidra_gdb=MCPServerSettings(enabled=False),
            angr_mcp=MCPServerSettings(enabled=False),
        )
    )
    seen: list[str] = []

    def fake_get(url: str, timeout: float) -> FakeResponse:
        seen.append(url)
        if url == "http://127.0.0.1:8080/health":
            raise httpx.ConnectError("connection refused")
        return FakeResponse(200, {"ok": True})

    monkeypatch.setattr("r2d2.environment.detectors.httpx.get", fake_get)

    checks = detect_mcp_connections(config)

    assert seen == ["http://127.0.0.1:8080/health", "http://127.0.0.1:18080/health"]
    assert checks["ghidra_mcp"].available is True
    assert checks["ghidra_mcp"].active_url == "http://127.0.0.1:18080"


def test_detect_mcp_connections_rejects_spa_fallback_as_ghidra_gdb(monkeypatch):
    """Test unrelated HTML 200 responses do not count as GhidraMCP GDB health."""
    config = AppConfig(
        mcp=MCPSettings(
            ghidra_mcp=MCPServerSettings(enabled=False),
            ghidra_gdb=MCPServerSettings(
                transport="http",
                url="http://127.0.0.1:5051",
                health_path="/health",
            ),
            angr_mcp=MCPServerSettings(enabled=False),
        )
    )

    def fake_get(url: str, timeout: float) -> FakeResponse:
        return FakeResponse(200, "<html></html>", headers={"content-type": "text/html; charset=utf-8"})

    monkeypatch.setattr("r2d2.environment.detectors.httpx.get", fake_get)

    checks = detect_mcp_connections(config)

    assert checks["ghidra_gdb"].available is False
    assert "unexpected response" in (checks["ghidra_gdb"].details or "")


def test_detect_mcp_connections_probes_streamable_http_with_initialize(monkeypatch):
    """Test streamable HTTP MCP checks use JSON-RPC instead of a plain GET."""
    config = AppConfig(
        mcp=MCPSettings(
            ghidra_mcp=MCPServerSettings(enabled=False),
            ghidra_gdb=MCPServerSettings(enabled=False),
            angr_mcp=MCPServerSettings(
                transport="streamable-http",
                url="http://127.0.0.1:8766/mcp",
                command="angr-mcp-dev-server",
                args=["--transport", "streamable-http", "--host", "127.0.0.1", "--port", "8766"],
                start_command=[
                    "uv",
                    "run",
                    "angr-mcp-dev-server",
                    "--transport",
                    "streamable-http",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "8766",
                ],
                working_dir="../angr_mcp",
            ),
        )
    )
    seen_methods: list[str] = []

    def fake_post(url: str, *, json: dict[str, object], headers: dict[str, str], timeout: float) -> FakeResponse:
        assert url == "http://127.0.0.1:8766/mcp"
        seen_methods.append(str(json.get("method")))
        if json.get("method") == "initialize":
            return FakeResponse(
                200,
                {"jsonrpc": "2.0", "id": json.get("id"), "result": {"serverInfo": {"name": "angr_mcp"}}},
                headers={"content-type": "application/json", "Mcp-Session-Id": "sess-1"},
            )
        if json.get("method") == "tools/list":
            assert headers["Mcp-Session-Id"] == "sess-1"
            return FakeResponse(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": json.get("id"),
                    "result": {"tools": [{"name": "am_angr_entry"}, {"name": "am_angr_cfg"}]},
                },
            )
        return FakeResponse(202)

    monkeypatch.setattr("r2d2.environment.detectors.httpx.post", fake_post)
    monkeypatch.setattr("r2d2.environment.detectors.shutil.which", lambda command: f"/bin/{command}")

    checks = detect_mcp_connections(config)

    assert seen_methods == ["initialize", "notifications/initialized", "tools/list"]
    assert checks["angr_mcp"].available is True
    assert checks["angr_mcp"].capabilities_count == 2
    assert checks["angr_mcp"].command_available is True
    assert checks["angr_mcp"].args == ["--transport", "streamable-http", "--host", "127.0.0.1", "--port", "8766"]
    assert checks["angr_mcp"].start_command[0:3] == ["uv", "run", "angr-mcp-dev-server"]
    assert checks["angr_mcp"].working_dir == "../angr_mcp"
    assert "2 tools" in (checks["angr_mcp"].details or "")
