"""Adapter for the angr_mcp streamable HTTP MCP server."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from ..config import MCPServerSettings
from ..environment import MCPConnectionCheck
from .base import AdapterUnavailable


@dataclass(slots=True)
class AngrMCPAdapter:
    """Use angr_mcp as a per-binary analyzer through MCP tools."""

    settings: MCPServerSettings
    connection: MCPConnectionCheck | None = None
    name: str = "angr_mcp"
    scan_timeout: float = 45.0

    def is_available(self) -> bool:
        if not self.settings.enabled or not self.settings.url:
            return False
        if self.connection and self.connection.available:
            return True
        return self._probe_initialize()

    def quick_scan(self, binary: Path, **kwargs: Any) -> dict[str, Any]:
        return {
            "mode": "angr_mcp",
            "available": self.is_available(),
            "binary": str(binary),
            "url": self.settings.url,
            "message": "angr_mcp analysis runs in deep scan only",
        }

    def deep_scan(self, binary: Path, **kwargs: Any) -> dict[str, Any]:
        if not self.settings.url:
            raise AdapterUnavailable("angr_mcp URL is not configured")
        binary = binary.resolve()
        if not binary.exists():
            raise AdapterUnavailable(f"Binary not found: {binary}")

        timeout = httpx.Timeout(
            connect=max(self.settings.timeout, 1.0),
            read=self.scan_timeout,
            write=15.0,
            pool=5.0,
        )
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        result: dict[str, Any] = {
            "mode": "angr_mcp",
            "url": self.settings.url,
            "binary": str(binary),
            "initialized": False,
            "tools": [],
            "calls": {},
            "errors": [],
        }

        try:
            with httpx.Client(timeout=timeout, headers=headers) as client:
                session = _MCPJsonRPCSession(client, self.settings.url)
                initialize = session.call(
                    "initialize",
                    {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "r2d2", "version": "0.1.0"},
                    },
                )
                result["initialize"] = initialize
                result["initialized"] = "error" not in initialize
                if not result["initialized"]:
                    raise AdapterUnavailable(str(initialize.get("error", "angr_mcp initialize failed")))

                initialized = session.notify("notifications/initialized", {})
                if initialized is not None:
                    result["initialized_notification"] = initialized

                tools_response = session.call("tools/list", {})
                tools = _extract_tools(tools_response)
                result["tools"] = tools

                for key, tool_name, arguments in [
                    ("entry", "am_angr_entry", {"binary_path": str(binary)}),
                    ("cfg", "am_angr_cfg", {"binary_path": str(binary)}),
                ]:
                    if tools and tool_name not in tools:
                        result["errors"].append({"tool": tool_name, "error": "tool not listed by server"})
                        continue
                    response = session.call(
                        "tools/call",
                        {"name": tool_name, "arguments": arguments},
                        read_timeout=self.scan_timeout,
                    )
                    result["calls"][key] = response
                    if "error" in response:
                        result["errors"].append({"tool": tool_name, "error": response["error"]})
                    else:
                        extracted = _extract_tool_payload(response)
                        result[key] = _normalize_named_payload(key, extracted)

        except AdapterUnavailable:
            raise
        except Exception as exc:
            raise AdapterUnavailable(f"angr_mcp analysis failed: {type(exc).__name__}: {exc}") from exc

        _promote_angr_mcp_fields(result)
        return result

    def _probe_initialize(self) -> bool:
        try:
            timeout = httpx.Timeout(connect=max(self.settings.timeout, 1.0), read=self.settings.timeout, write=5.0, pool=2.0)
            with httpx.Client(timeout=timeout, headers={"Accept": "application/json, text/event-stream"}) as client:
                session = _MCPJsonRPCSession(client, self.settings.url or "")
                response = session.call(
                    "initialize",
                    {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "r2d2", "version": "0.1.0"},
                    },
                )
            return "error" not in response
        except Exception:
            return False


class _MCPJsonRPCSession:
    def __init__(self, client: httpx.Client, url: str) -> None:
        self.client = client
        self.url = url
        self.session_id: str | None = None
        self._next_id = 1

    def call(self, method: str, params: dict[str, Any], *, read_timeout: float | None = None) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        response = self._post(payload, read_timeout=read_timeout)
        return _mcp_response_json(response)

    def notify(self, method: str, params: dict[str, Any]) -> dict[str, Any] | None:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        try:
            response = self._post(payload)
        except httpx.HTTPStatusError:
            return None
        if response.status_code == 202 or not response.content:
            return None
        return _mcp_response_json(response)

    def _post(self, payload: dict[str, Any], *, read_timeout: float | None = None) -> httpx.Response:
        headers = {}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        timeout = None
        if read_timeout is not None:
            timeout = httpx.Timeout(connect=5.0, read=read_timeout, write=15.0, pool=5.0)
        response = self.client.post(self.url, json=payload, headers=headers, timeout=timeout)
        session_id = response.headers.get("Mcp-Session-Id")
        if session_id:
            self.session_id = session_id
        response.raise_for_status()
        return response


def _mcp_response_json(response: httpx.Response) -> dict[str, Any]:
    content_type = response.headers.get("content-type", "").lower()
    if "text/event-stream" in content_type:
        payload = _json_from_sse(response.text)
    else:
        try:
            payload = response.json()
        except ValueError:
            payload = {"text": response.text[:4000]}
    if not isinstance(payload, dict):
        payload = {"payload": payload}
    payload.setdefault("status_code", response.status_code)
    if isinstance(payload.get("error"), dict):
        payload["error"] = payload["error"].get("message") or json.dumps(payload["error"])
    return payload


def _json_from_sse(text: str) -> dict[str, Any]:
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        data = line.partition(":")[2].strip()
        if not data or data == "[DONE]":
            continue
        try:
            payload = json.loads(data)
        except ValueError:
            continue
        if isinstance(payload, dict):
            return payload
    return {"text": text[:4000]}


def _extract_tools(response: dict[str, Any]) -> list[str]:
    result = response.get("result")
    if not isinstance(result, dict):
        return []
    tools = result.get("tools")
    if not isinstance(tools, list):
        return []
    names: list[str] = []
    for tool in tools:
        if isinstance(tool, dict) and isinstance(tool.get("name"), str):
            names.append(tool["name"])
    return names


def _extract_tool_payload(response: dict[str, Any]) -> dict[str, Any]:
    result = response.get("result", response)
    if isinstance(result, dict):
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            return structured
        content = result.get("content")
        if isinstance(content, list):
            for item in content:
                if not isinstance(item, dict) or item.get("type") != "text":
                    continue
                text = item.get("text")
                if not isinstance(text, str):
                    continue
                try:
                    parsed = json.loads(text)
                except ValueError:
                    return {"text": text}
                return parsed if isinstance(parsed, dict) else {"payload": parsed}
        return result
    return {"payload": result}


def _normalize_named_payload(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    if name != "cfg":
        return payload
    normalized = dict(payload)
    if "node_count" not in normalized:
        normalized["node_count"] = normalized.get("nodes")
    if "edge_count" not in normalized:
        normalized["edge_count"] = normalized.get("edges")
    return normalized


def _promote_angr_mcp_fields(result: dict[str, Any]) -> None:
    entry = result.get("entry")
    if isinstance(entry, dict):
        result["entry_point"] = entry.get("entry_point") or entry.get("entry") or entry.get("addr")
        result["main"] = entry.get("main")
    cfg = result.get("cfg")
    if isinstance(cfg, dict):
        result["cfg_nodes"] = cfg.get("node_count")
        result["cfg_edges"] = cfg.get("edge_count")


__all__ = ["AngrMCPAdapter"]
