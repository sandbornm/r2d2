"""Adapters for GhidraMCP-backed HTTP services."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from ..config import MCPServerSettings
from ..environment import MCPConnectionCheck
from .base import AdapterUnavailable


@dataclass(slots=True)
class GhidraGDBMCPAdapter:
    """Use the GhidraMCP GDB/Docker HTTP API as a per-binary analyzer."""

    settings: MCPServerSettings
    connection: MCPConnectionCheck | None = None
    name: str = "ghidra_gdb"
    scan_timeout: float = 45.0

    def is_available(self) -> bool:
        if not self.settings.enabled or not self.settings.url:
            return False
        if self.connection is None:
            return False
        return self._health_url() is not None

    def quick_scan(self, binary: Path, **kwargs: Any) -> dict[str, Any]:
        return {
            "mode": "ghidra_mcp_gdb",
            "available": self.is_available(),
            "binary": str(binary),
            "url": self._health_url() or self.settings.url,
            "message": "GhidraMCP GDB analysis runs in deep scan only",
        }

    def deep_scan(
        self,
        binary: Path,
        *,
        resource_tree: Any | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        base_url = self._health_url()
        if not base_url:
            raise AdapterUnavailable("GhidraMCP GDB API is not reachable")

        binary = binary.resolve()
        if not binary.exists():
            raise AdapterUnavailable(f"Binary not found: {binary}")

        remote_name = _remote_binary_name(binary)
        result: dict[str, Any] = {
            "mode": "ghidra_mcp_gdb",
            "url": base_url,
            "binary": str(binary),
            "remote_binary": remote_name,
            "uploaded": False,
            "endpoints": {},
            "errors": [],
        }

        timeout = httpx.Timeout(connect=max(self.settings.timeout, 1.0), read=self.scan_timeout, write=30.0, pool=5.0)
        with httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout) as client:
            upload = self._upload(client, binary, remote_name)
            result["upload"] = upload
            result["uploaded"] = upload.get("status") == "uploaded"
            if not result["uploaded"]:
                result["errors"].append({"endpoint": "upload", "error": upload.get("error", "upload failed")})
                return result

            endpoint_plan: list[tuple[str, str, dict[str, Any]]] = [
                ("file_info", "/file_info", {"binary": remote_name}),
                ("sections", "/sections", {"binary": remote_name}),
                ("imports", "/imports", {"binary": remote_name}),
                ("strings", "/strings", {"binary": remote_name, "min_length": 6}),
                ("checksec", "/checksec", {"binary": remote_name}),
                ("angr_entry", "/angr/entry", {"binary": remote_name}),
                ("angr_cfg", "/angr/cfg", {"binary": remote_name, "timeout": min(self.scan_timeout, 60)}),
            ]
            for key, path, payload in endpoint_plan:
                response = self._post_json(client, path, payload)
                if "error" in response:
                    result["errors"].append({"endpoint": key, "error": response["error"]})
                result["endpoints"][key] = response

        _promote_endpoint_fields(result)
        return result

    def _health_url(self) -> str | None:
        for base_url in [self.settings.url, *self.settings.fallback_urls]:
            if not base_url:
                continue
            try:
                response = httpx.get(_join_url(base_url, self.settings.health_path), timeout=self.settings.timeout)
            except httpx.HTTPError:
                continue
            if _is_ghidra_gdb_health(response):
                return base_url.rstrip("/")
        return None

    def _upload(self, client: httpx.Client, binary: Path, remote_name: str) -> dict[str, Any]:
        try:
            with binary.open("rb") as fh:
                response = client.post(
                    "/upload",
                    data={"filename": remote_name},
                    files={"file": (remote_name, fh, "application/octet-stream")},
                )
            return _response_json(response)
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}

    def _post_json(self, client: httpx.Client, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = client.post(path, json=payload)
            return _response_json(response)
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}


def _response_json(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except ValueError:
        payload = {"text": response.text[:4000]}
    if not isinstance(payload, dict):
        payload = {"payload": payload}
    payload.setdefault("status_code", response.status_code)
    if response.status_code >= 400:
        payload.setdefault("error", f"HTTP {response.status_code}")
    return payload


def _join_url(base_url: str, path: str | None) -> str:
    if not path:
        return base_url
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def _is_ghidra_gdb_health(response: httpx.Response) -> bool:
    if response.status_code >= 500 or response.status_code == 404:
        return False
    if "text/html" in response.headers.get("content-type", "").lower():
        return False
    try:
        payload = response.json()
    except ValueError:
        return False
    return (
        isinstance(payload, dict)
        and payload.get("status") == "ok"
        and any(key in payload for key in ("platform", "qemu_architectures", "note"))
    )


def _remote_binary_name(binary: Path) -> str:
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()[:12]
    safe_stem = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in binary.stem)[:64] or "binary"
    return f"{safe_stem}-{digest}{binary.suffix}"


def _promote_endpoint_fields(result: dict[str, Any]) -> None:
    endpoints = result.get("endpoints")
    if not isinstance(endpoints, dict):
        return
    file_info = endpoints.get("file_info")
    sections = endpoints.get("sections")
    imports = endpoints.get("imports")
    strings = endpoints.get("strings")
    checksec = endpoints.get("checksec")
    angr_entry = endpoints.get("angr_entry")
    angr_cfg = endpoints.get("angr_cfg")

    if isinstance(file_info, dict):
        result["file_info"] = file_info
    if isinstance(sections, dict):
        result["sections"] = sections.get("sections", [])
        result["section_count"] = sections.get("count", len(result["sections"]))
    if isinstance(imports, dict):
        result["imports"] = imports.get("imports", [])
        result["import_count"] = imports.get("count", len(result["imports"]))
    if isinstance(strings, dict):
        result["strings"] = strings.get("strings", [])
        result["string_count"] = len(result["strings"])
    if isinstance(checksec, dict):
        result["checksec"] = checksec
    if isinstance(angr_entry, dict):
        result["entry"] = angr_entry
    if isinstance(angr_cfg, dict):
        result["cfg"] = angr_cfg


__all__ = ["GhidraGDBMCPAdapter"]
