"""Unit tests for GhidraMCP-backed adapters."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from r2d2.adapters.angr_mcp import AngrMCPAdapter
from r2d2.adapters.ghidra_mcp import GhidraGDBMCPAdapter
from r2d2.config import MCPServerSettings
from r2d2.environment import MCPConnectionCheck


class FakeClient:
    def __init__(self, base_url: str, timeout: httpx.Timeout) -> None:
        self.base_url = base_url
        self.timeout = timeout
        self.requests: list[tuple[str, dict[str, Any] | None]] = []

    def __enter__(self) -> "FakeClient":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def post(
        self,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
    ) -> httpx.Response:
        self.requests.append((path, json or data))
        if path == "/upload":
            assert files and "file" in files
            filename = data["filename"] if data else "sample"
            return httpx.Response(200, json={"status": "uploaded", "path": f"/analysis/bins/{filename}"})
        if path == "/file_info":
            return httpx.Response(
                200,
                json={
                    "architecture": "x86_64",
                    "format": "ELF",
                    "sha256": "abc",
                    "is_elf": True,
                },
            )
        if path == "/sections":
            return httpx.Response(
                200,
                json={"sections": [{"name": ".text", "address": "0000000000401000", "size": "10"}], "count": 1},
            )
        if path == "/imports":
            return httpx.Response(200, json={"imports": [{"name": "malloc", "type": "function"}], "count": 1})
        if path == "/strings":
            return httpx.Response(200, json={"strings": ["firmware config"]})
        if path == "/checksec":
            return httpx.Response(200, json={"nx": True, "pie": False, "relro": "Partial", "canary": False})
        if path == "/angr/entry":
            return httpx.Response(200, json={"entry_point": "0x401000", "main": "0x401050"})
        if path == "/angr/cfg":
            return httpx.Response(
                200,
                json={
                    "node_count": 1,
                    "edge_count": 1,
                    "nodes": [{"addr": "0x401000", "size": 5}],
                    "edges": [{"from": "0x401000", "to": "0x401005"}],
                },
            )
        return httpx.Response(404, json={"error": "missing"})


def test_ghidra_gdb_mcp_adapter_uploads_and_collects_endpoint_evidence(
    monkeypatch,
    tmp_path: Path,
) -> None:
    binary = tmp_path / "sample.elf"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 32)
    settings = MCPServerSettings(
        transport="http",
        url="http://127.0.0.1:5051",
        health_path="/health",
    )
    adapter = GhidraGDBMCPAdapter(
        settings=settings,
        connection=MCPConnectionCheck(
            name="ghidra_gdb",
            enabled=True,
            transport="http",
            available=False,
            url=settings.url,
        ),
    )

    monkeypatch.setattr(
        "r2d2.adapters.ghidra_mcp.httpx.get",
        lambda *_args, **_kwargs: httpx.Response(
            200,
            json={"status": "ok", "platform": "linux/amd64", "qemu_architectures": []},
        ),
    )
    monkeypatch.setattr("r2d2.adapters.ghidra_mcp.httpx.Client", FakeClient)

    result = adapter.deep_scan(binary)

    assert result["uploaded"] is True
    assert result["remote_binary"].startswith("sample-")
    assert result["file_info"]["format"] == "ELF"
    assert result["sections"][0]["name"] == ".text"
    assert result["imports"][0]["name"] == "malloc"
    assert result["strings"] == ["firmware config"]
    assert result["checksec"]["nx"] is True
    assert result["entry"]["entry_point"] == "0x401000"
    assert result["cfg"]["node_count"] == 1


class FakeAngrMCPClient:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.requests: list[tuple[str, dict[str, Any] | None, dict[str, str] | None]] = []

    def __enter__(self) -> "FakeAngrMCPClient":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def post(
        self,
        url: str,
        *,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: Any = None,
    ) -> httpx.Response:
        self.requests.append((url, json, headers))
        method = json.get("method") if isinstance(json, dict) else None
        request_id = json.get("id") if isinstance(json, dict) else None
        request = httpx.Request("POST", url)
        response_headers = {"Mcp-Session-Id": "sess-1"} if method == "initialize" else {}

        if method == "initialize":
            return httpx.Response(
                200,
                headers=response_headers,
                request=request,
                json={"jsonrpc": "2.0", "id": request_id, "result": {"serverInfo": {"name": "angr_mcp"}}},
            )
        if method == "notifications/initialized":
            return httpx.Response(202, request=request)
        if method == "tools/list":
            return httpx.Response(
                200,
                request=request,
                json={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "tools": [
                            {"name": "am_angr_entry"},
                            {"name": "am_angr_cfg"},
                        ]
                    },
                },
            )
        if method == "tools/call":
            params = json.get("params", {}) if isinstance(json, dict) else {}
            tool_name = params.get("name") if isinstance(params, dict) else None
            payload = {"entry_point": "0x401000", "main": "0x401050"}
            if tool_name == "am_angr_cfg":
                payload = {"nodes": 12, "edges": 17}
            return httpx.Response(
                200,
                request=request,
                json={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": __import__("json").dumps(payload),
                            }
                        ]
                    },
                },
            )
        return httpx.Response(404, request=request, json={"error": "missing"})


def test_angr_mcp_adapter_calls_streamable_http_tools(monkeypatch, tmp_path: Path) -> None:
    binary = tmp_path / "sample.elf"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 32)
    settings = MCPServerSettings(
        transport="streamable-http",
        url="http://127.0.0.1:8766/mcp",
    )
    adapter = AngrMCPAdapter(
        settings=settings,
        connection=MCPConnectionCheck(
            name="angr_mcp",
            enabled=True,
            transport="streamable-http",
            available=True,
            url=settings.url,
        ),
    )

    monkeypatch.setattr("r2d2.adapters.angr_mcp.httpx.Client", FakeAngrMCPClient)

    result = adapter.deep_scan(binary)

    assert result["initialized"] is True
    assert result["tools"] == ["am_angr_entry", "am_angr_cfg"]
    assert result["entry"]["entry_point"] == "0x401000"
    assert result["main"] == "0x401050"
    assert result["cfg"]["node_count"] == 12
    assert result["cfg"]["edge_count"] == 17
    assert result["cfg_nodes"] == 12
    assert result["cfg_edges"] == 17
