"""Graph-shaped analysis model for unifying tool evidence.

The graph is intentionally compact: raw adapter payloads remain available in
``quick_scan`` and ``deep_scan``, while this model gives the UI and chat layer a
stable JSON contract for cross-tool relationships.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


GRAPH_SCHEMA_VERSION = "r2d2.analysis_graph.v1"
_MAX_PROPERTY_STRING = 4000


class AnalysisGraphNode(BaseModel):
    """A normalized evidence node emitted by one or more analysis tools."""

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str
    label: str
    source: str
    address: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)


class AnalysisGraphEdge(BaseModel):
    """A directed relationship between graph nodes."""

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str
    source: str
    target: str
    source_tool: str
    confidence: float = 1.0
    properties: dict[str, Any] = Field(default_factory=dict)


class AnalysisGraph(BaseModel):
    """Stable JSON graph contract for a single binary analysis."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = GRAPH_SCHEMA_VERSION
    binary: str
    generated_at: str
    nodes: list[AnalysisGraphNode] = Field(default_factory=list)
    edges: list[AnalysisGraphEdge] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


class _GraphAccumulator:
    def __init__(self, binary: Path) -> None:
        self.binary = binary
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.binary_node_id = "binary:root"
        self.add_node(
            self.binary_node_id,
            kind="binary",
            label=binary.name,
            source="r2d2",
            properties={"path": str(binary)},
        )

    def add_node(
        self,
        node_id: str,
        *,
        kind: str,
        label: str,
        source: str,
        address: str | None = None,
        properties: dict[str, Any] | None = None,
    ) -> str:
        properties = _json_dict(properties or {})
        if node_id not in self.nodes:
            properties.setdefault("sources", [source])
            self.nodes[node_id] = {
                "id": node_id,
                "kind": kind,
                "label": str(label),
                "source": source,
                "address": address,
                "properties": properties,
            }
            return node_id

        existing = self.nodes[node_id]
        existing_sources = set(existing["properties"].get("sources", []))
        existing_sources.add(source)
        existing["properties"]["sources"] = sorted(existing_sources)
        if len(existing_sources) > 1:
            existing["source"] = "merged"
        if address and not existing.get("address"):
            existing["address"] = address
        if label and existing.get("label") != label:
            aliases = set(existing["properties"].get("aliases", []))
            aliases.add(str(label))
            existing["properties"]["aliases"] = sorted(aliases)
        for key, value in properties.items():
            if key == "sources":
                continue
            if key not in existing["properties"]:
                existing["properties"][key] = value
            elif existing["properties"][key] != value:
                source_values = existing["properties"].setdefault("source_values", {})
                source_values.setdefault(source, {})[key] = value
        return node_id

    def add_edge(
        self,
        kind: str,
        source_id: str,
        target_id: str,
        *,
        source_tool: str,
        confidence: float = 1.0,
        properties: dict[str, Any] | None = None,
    ) -> str:
        edge_id = _stable_id("edge", kind, source_id, target_id, source_tool)
        properties = _json_dict(properties or {})
        if edge_id not in self.edges:
            properties.setdefault("sources", [source_tool])
            self.edges[edge_id] = {
                "id": edge_id,
                "kind": kind,
                "source": source_id,
                "target": target_id,
                "source_tool": source_tool,
                "confidence": confidence,
                "properties": properties,
            }
            return edge_id

        existing_sources = set(self.edges[edge_id]["properties"].get("sources", []))
        existing_sources.add(source_tool)
        self.edges[edge_id]["properties"]["sources"] = sorted(existing_sources)
        for key, value in properties.items():
            self.edges[edge_id]["properties"].setdefault(key, value)
        return edge_id

    def add_tool(self, name: str, status: dict[str, Any] | bool | None) -> None:
        tool_id = _node_id("tool", name)
        props = status if isinstance(status, dict) else {"available": bool(status)}
        self.add_node(tool_id, kind="tool", label=name, source="r2d2", properties=props)
        self.add_edge("observed_by", self.binary_node_id, tool_id, source_tool="r2d2")

    def add_function(self, source: str, func: dict[str, Any]) -> str | None:
        address = _normalize_address(
            func.get("offset") or func.get("addr") or func.get("address") or func.get("entry")
        )
        name = _first_text(func.get("name"), func.get("function_name"), func.get("symbol"), default=address or "function")
        node_key = address or f"{source}:{name}"
        node_id = _node_id("function", node_key)
        props = _pick(
            func,
            [
                "name",
                "size",
                "nargs",
                "nlocals",
                "is_plt",
                "is_syscall",
                "has_return",
                "block_count",
                "signature",
                "return_type",
                "calling_convention",
            ],
        )
        props[f"{source}_name"] = name
        self.add_node(node_id, kind="function", label=name, source=source, address=address, properties=props)
        self.add_edge("contains_function", self.binary_node_id, node_id, source_tool=source)
        return node_id

    def add_block(
        self,
        source: str,
        block: dict[str, Any],
        *,
        function_id: str | None = None,
        function_address: str | None = None,
    ) -> str | None:
        address = _normalize_address(block.get("offset") or block.get("addr") or block.get("address"))
        if not address:
            return None
        node_id = _node_id("block", address)
        instructions = block.get("disassembly") or block.get("instructions") or []
        props = _pick(block, ["size", "instruction_count", "type", "jump", "fail"])
        if isinstance(instructions, list):
            props["instruction_preview"] = _json_value(instructions[:8])
        if function_address:
            props["function_address"] = function_address
        self.add_node(node_id, kind="basic_block", label=address, source=source, address=address, properties=props)
        if function_id:
            self.add_edge("contains_block", function_id, node_id, source_tool=source)
        return node_id

    def to_graph(self) -> dict[str, Any]:
        nodes = [AnalysisGraphNode.model_validate(node) for node in self.nodes.values()]
        edges = [AnalysisGraphEdge.model_validate(edge) for edge in self.edges.values()]
        graph = AnalysisGraph(
            binary=str(self.binary),
            generated_at=datetime.now(timezone.utc).isoformat(),
            nodes=nodes,
            edges=edges,
            summary=_build_summary(nodes, edges),
        )
        return graph.model_dump(mode="json")


def build_analysis_graph(result: Any) -> dict[str, Any]:
    """Build a compact, validated JSON graph from an ``AnalysisResult``."""

    binary = Path(getattr(result, "binary"))
    acc = _GraphAccumulator(binary)
    quick = getattr(result, "quick_scan", {}) or {}
    deep = getattr(result, "deep_scan", {}) or {}

    for name, available in (getattr(result, "tool_availability", {}) or {}).items():
        status = dict((getattr(result, "tool_status", {}) or {}).get(name, {}))
        status.setdefault("available", available)
        acc.add_tool(name, status)

    _add_radare_quick(acc, quick.get("radare2", {}) if isinstance(quick, dict) else {})
    _add_autoprofile(acc, quick.get("autoprofile", {}) if isinstance(quick, dict) else {})
    _add_firmware_quick(acc, quick.get("firmware", {}) if isinstance(quick, dict) else {})
    _add_radare_deep(acc, deep.get("radare2", {}) if isinstance(deep, dict) else {})
    _add_angr_deep(acc, deep.get("angr", {}) if isinstance(deep, dict) else {})
    _add_angr_mcp_deep(acc, deep.get("angr_mcp", {}) if isinstance(deep, dict) else {})
    _add_ghidra_deep(acc, deep.get("ghidra", {}) if isinstance(deep, dict) else {})
    _add_ghidra_gdb_deep(acc, deep.get("ghidra_gdb", {}) if isinstance(deep, dict) else {})
    _add_firmware_children(acc, deep.get("firmware_children", {}) if isinstance(deep, dict) else {})

    for issue in getattr(result, "issues", []) or []:
        issue_id = _stable_id("issue", issue)
        acc.add_node(issue_id, kind="issue", label=str(issue)[:120], source="r2d2", properties={"message": issue})
        acc.add_edge("has_issue", acc.binary_node_id, issue_id, source_tool="r2d2", confidence=0.8)

    return acc.to_graph()


def _add_radare_quick(acc: _GraphAccumulator, r2: Any) -> None:
    if not isinstance(r2, dict):
        return

    info = r2.get("info", {})
    bin_info = info.get("bin", {}) if isinstance(info, dict) else {}
    core_info = info.get("core", {}) if isinstance(info, dict) else {}
    if isinstance(bin_info, dict) or isinstance(core_info, dict):
        acc.add_node(
            acc.binary_node_id,
            kind="binary",
            label=acc.binary.name,
            source="radare2",
            properties={
                "arch": _json_value((bin_info or info).get("arch") if isinstance(bin_info or info, dict) else None),
                "bits": _json_value((bin_info or info).get("bits") if isinstance(bin_info or info, dict) else None),
                "format": _json_value(core_info.get("format") if isinstance(core_info, dict) else None),
                "os": _json_value((bin_info or info).get("os") if isinstance(bin_info or info, dict) else None),
            },
        )

    for item in _as_list(r2.get("imports"))[:200]:
        if not isinstance(item, dict):
            continue
        name = _first_text(item.get("name"), item.get("libname"))
        if not name:
            continue
        import_id = _node_id("import", name)
        acc.add_node(import_id, kind="import", label=name, source="radare2", properties=_pick(item, ["type", "bind", "libname", "plt"]))
        acc.add_edge("imports", acc.binary_node_id, import_id, source_tool="radare2")

    for item in _as_list(r2.get("strings"))[:200]:
        if not isinstance(item, dict):
            continue
        value = _first_text(item.get("string"), item.get("value"), item.get("text"))
        if not value:
            continue
        offset = _normalize_address(item.get("offset") or item.get("vaddr") or item.get("paddr"))
        string_id = _node_id("string", offset or hashlib.sha1(value.encode()).hexdigest()[:12])
        acc.add_node(
            string_id,
            kind="string",
            label=value[:80],
            source="radare2",
            address=offset,
            properties={"value": value, **_pick(item, ["type", "length", "size", "section"])},
        )
        acc.add_edge("contains_string", acc.binary_node_id, string_id, source_tool="radare2")

    for item in _as_list(r2.get("sections"))[:100]:
        if not isinstance(item, dict):
            continue
        name = _first_text(item.get("name"), default="section")
        section_id = _node_id("section", name)
        acc.add_node(
            section_id,
            kind="section",
            label=name,
            source="radare2",
            address=_normalize_address(item.get("vaddr") or item.get("paddr")),
            properties=_pick(item, ["size", "vsize", "perm", "type"]),
        )
        acc.add_edge("contains_section", acc.binary_node_id, section_id, source_tool="radare2")


def _add_autoprofile(acc: _GraphAccumulator, profile: Any) -> None:
    if not isinstance(profile, dict):
        return
    profile_id = _node_id("profile", "autoprofile")
    acc.add_node(
        profile_id,
        kind="profile",
        label="AutoProfile",
        source="autoprofile",
        properties=_pick(profile, ["risk_score", "risk_level", "security_features", "findings"]),
    )
    acc.add_edge("has_profile", acc.binary_node_id, profile_id, source_tool="autoprofile")


def _add_firmware_quick(acc: _GraphAccumulator, firmware: Any) -> None:
    if not isinstance(firmware, dict):
        return

    profile_id = _node_id("firmware_profile", "inventory")
    acc.add_node(
        profile_id,
        kind="firmware_profile",
        label="Firmware Inventory",
        source="firmware",
        properties=_pick(
            firmware,
            [
                "size_bytes",
                "sha256",
                "is_elf",
                "top_level_format",
                "container_type",
                "scan",
                "string_signals",
                "entropy",
                "notes",
            ],
        ),
    )
    acc.add_edge("has_inventory", acc.binary_node_id, profile_id, source_tool="firmware")

    for signal in _as_list((firmware.get("string_signals") or {}).get("top_signals"))[:100]:
        if not isinstance(signal, dict):
            continue
        value = _first_text(signal.get("value"))
        if not value:
            continue
        offset = signal.get("offset")
        category = _first_text(signal.get("category"), default="firmware_signal")
        signal_id = _node_id("firmware_signal", f"{offset}:{category}:{value}")
        acc.add_node(
            signal_id,
            kind="string",
            label=value[:100],
            source="firmware",
            address=_normalize_address(offset),
            properties=_pick(
                signal,
                ["category", "label", "value", "offset", "offset_hex", "confidence"],
            ),
        )
        acc.add_edge("has_string_signal", profile_id, signal_id, source_tool="firmware", confidence=0.75)

    recommended_offsets = {
        int(item.get("offset"))
        for item in _as_list(firmware.get("recommended_targets"))
        if isinstance(item, dict) and isinstance(item.get("offset"), int)
    }
    for item in _as_list(firmware.get("embedded_artifacts"))[:300]:
        if not isinstance(item, dict):
            continue
        offset = item.get("offset")
        kind = _first_text(item.get("kind"), default="embedded_artifact")
        name = _first_text(item.get("name"), item.get("description"), default=kind)
        address = _normalize_address(offset)
        artifact_id = _node_id("artifact", f"{offset}:{kind}:{name}")
        props = _pick(
            item,
            [
                "offset",
                "offset_hex",
                "kind",
                "name",
                "description",
                "source",
                "confidence",
                "recommended",
                "declared_size",
                "payload_size",
                "load_address",
                "entrypoint",
                "image_name",
                "kind_hint",
                "description_hint",
                "analysis_role",
                "fanout_tools",
                "carved_path",
                "carved_size",
                "carved_sha256",
                "carved_signature",
                "carve_start",
                "carve_end",
            ],
        )
        acc.add_node(
            artifact_id,
            kind="embedded_artifact",
            label=name[:100],
            source="firmware",
            address=address,
            properties=props,
        )
        acc.add_edge("contains_artifact", acc.binary_node_id, artifact_id, source_tool="firmware")
        if isinstance(offset, int) and offset in recommended_offsets:
            acc.add_edge("suggests_target", profile_id, artifact_id, source_tool="firmware", confidence=0.8)
        for tool in _as_list(item.get("fanout_tools"))[:10]:
            tool_name = _first_text(tool)
            if not tool_name:
                continue
            tool_id = _node_id("tool", tool_name)
            acc.add_node(tool_id, kind="tool", label=tool_name, source="firmware", properties={"planned": True})
            acc.add_edge("candidate_for", artifact_id, tool_id, source_tool="firmware", confidence=0.7)


def _add_firmware_children(acc: _GraphAccumulator, children: Any) -> None:
    if not isinstance(children, dict):
        return
    for analysis in _as_list(children.get("analyses"))[:100]:
        if not isinstance(analysis, dict):
            continue
        target = _first_text(analysis.get("target"))
        tool = _first_text(analysis.get("tool"), default="firmware_child")
        if not target:
            continue
        target_id = _node_id("artifact_analysis", f"{target}:{tool}")
        acc.add_node(
            target_id,
            kind="artifact_analysis",
            label=f"{Path(target).name} via {tool}",
            source=tool,
            properties=_pick(analysis, ["target", "offset", "kind", "tool", "status", "error"]),
        )
        acc.add_edge("analyzed_as_child", acc.binary_node_id, target_id, source_tool=tool)


def _add_radare_deep(acc: _GraphAccumulator, r2: Any) -> None:
    if not isinstance(r2, dict):
        return

    for func in _as_list(r2.get("functions"))[:500]:
        if isinstance(func, dict):
            acc.add_function("radare2", func)

    for cfg in _as_list(r2.get("function_cfgs"))[:100]:
        if not isinstance(cfg, dict):
            continue
        function_address = _normalize_address(cfg.get("offset") or cfg.get("addr"))
        function_id = acc.add_function("radare2", cfg)
        block_ids: dict[str, str] = {}
        for block in _as_list(cfg.get("blocks"))[:200]:
            if not isinstance(block, dict):
                continue
            block_id = acc.add_block("radare2", block, function_id=function_id, function_address=function_address)
            block_addr = _normalize_address(block.get("offset") or block.get("addr"))
            if block_id and block_addr:
                block_ids[block_addr] = block_id
        for block in _as_list(cfg.get("blocks"))[:200]:
            if not isinstance(block, dict):
                continue
            source_block = block_ids.get(_normalize_address(block.get("offset") or block.get("addr")) or "")
            if not source_block:
                continue
            for edge_kind, target_key in (("jump", "jump"), ("fallthrough", "fail")):
                target_addr = _normalize_address(block.get(target_key))
                target_block = block_ids.get(target_addr or "") or (_node_id("block", target_addr) if target_addr else None)
                if target_block:
                    acc.add_edge("control_flow", source_block, target_block, source_tool="radare2", properties={"edge": edge_kind})

    for target, refs in (r2.get("xref_map") or {}).items():
        target_addr = _normalize_address(target)
        if not target_addr:
            continue
        target_id = _node_id("function", target_addr)
        for ref in _as_list(refs)[:50]:
            if not isinstance(ref, dict):
                continue
            source_addr = _normalize_address(ref.get("from") or ref.get("from_address"))
            if not source_addr:
                continue
            acc.add_edge("xref", _node_id("function", source_addr), target_id, source_tool="radare2", properties=_pick(ref, ["type", "opcode"]))


def _add_angr_deep(acc: _GraphAccumulator, angr: Any) -> None:
    if not isinstance(angr, dict):
        return

    for func in _as_list(angr.get("functions"))[:500]:
        if isinstance(func, dict):
            acc.add_function("angr", func)

    cfg = angr.get("cfg", {})
    if not isinstance(cfg, dict):
        return

    for node in _as_list(cfg.get("nodes"))[:500]:
        if not isinstance(node, dict):
            continue
        function_address = _normalize_address(node.get("function"))
        function_id = _node_id("function", function_address) if function_address else None
        if function_address:
            acc.add_function(
                "angr",
                {
                    "addr": function_address,
                    "name": node.get("function_name") or function_address,
                },
            )
        acc.add_block("angr", node, function_id=function_id, function_address=function_address)

    for edge in _as_list(cfg.get("edges"))[:1000]:
        if not isinstance(edge, dict):
            continue
        source_addr = _normalize_address(edge.get("source"))
        target_addr = _normalize_address(edge.get("target"))
        if not source_addr or not target_addr:
            continue
        acc.add_edge(
            "control_flow",
            _node_id("block", source_addr),
            _node_id("block", target_addr),
            source_tool="angr",
                properties=_pick(edge, ["type"]),
        )


def _add_angr_mcp_deep(acc: _GraphAccumulator, angr_mcp: Any) -> None:
    if not isinstance(angr_mcp, dict):
        return

    entry = angr_mcp.get("entry") if isinstance(angr_mcp.get("entry"), dict) else {}
    if isinstance(entry, dict):
        entry_addr = _normalize_address(
            entry.get("entry_point") or entry.get("entry") or entry.get("addr") or angr_mcp.get("entry_point")
        )
        main_addr = _normalize_address(entry.get("main") or angr_mcp.get("main"))
        if entry_addr:
            acc.add_function("angr_mcp", {"addr": entry_addr, "name": "entry"})
        if main_addr:
            acc.add_function("angr_mcp", {"addr": main_addr, "name": "main"})

    cfg = angr_mcp.get("cfg")
    if not isinstance(cfg, dict):
        return

    nodes = _as_list(cfg.get("nodes"))
    edges = _as_list(cfg.get("edges"))
    node_count = cfg.get("node_count") if cfg.get("node_count") is not None else cfg.get("nodes")
    edge_count = cfg.get("edge_count") if cfg.get("edge_count") is not None else cfg.get("edges")

    if nodes:
        for node in nodes[:500]:
            if isinstance(node, dict):
                acc.add_block("angr_mcp", node)
    else:
        summary_id = _node_id("cfg_summary", "angr_mcp")
        acc.add_node(
            summary_id,
            kind="cfg_summary",
            label="angr_mcp CFG",
            source="angr_mcp",
            properties={
                "node_count": _json_value(node_count),
                "edge_count": _json_value(edge_count),
                "mode": angr_mcp.get("mode"),
                "url": angr_mcp.get("url"),
            },
        )
        acc.add_edge("has_cfg_summary", acc.binary_node_id, summary_id, source_tool="angr_mcp")

    for edge in edges[:1000]:
        if not isinstance(edge, dict):
            continue
        source_addr = _normalize_address(edge.get("source") or edge.get("from"))
        target_addr = _normalize_address(edge.get("target") or edge.get("to"))
        if not source_addr or not target_addr:
            continue
        acc.add_edge(
            "control_flow",
            _node_id("block", source_addr),
            _node_id("block", target_addr),
            source_tool="angr_mcp",
            properties=_pick(edge, ["type"]),
        )


def _add_ghidra_deep(acc: _GraphAccumulator, ghidra: Any) -> None:
    if not isinstance(ghidra, dict):
        return

    for func in _as_list(ghidra.get("functions"))[:500]:
        if isinstance(func, dict):
            acc.add_function("ghidra", func)

    for item in _as_list(ghidra.get("decompiled"))[:100]:
        if not isinstance(item, dict):
            continue
        function_id = acc.add_function("ghidra", item)
        if not function_id:
            continue
        address = _normalize_address(item.get("address"))
        decomp_id = _node_id("decompilation", address or item.get("name") or function_id)
        code = _first_text(item.get("decompiled_c"), default="")
        acc.add_node(
            decomp_id,
            kind="decompilation",
            label=f"{item.get('name', 'function')} decompilation",
            source="ghidra",
            address=address,
            properties={
                "signature": item.get("signature"),
                "return_type": item.get("return_type"),
                "parameter_count": len(item.get("parameters") or []),
                "code_preview": code[:_MAX_PROPERTY_STRING],
            },
        )
        acc.add_edge("decompiled_as", function_id, decomp_id, source_tool="ghidra")

    for item in _as_list(ghidra.get("types"))[:200]:
        if not isinstance(item, dict):
            continue
        name = _first_text(item.get("name"), default="type")
        type_id = _node_id("type", name)
        acc.add_node(type_id, kind="type", label=name, source="ghidra", properties=_pick(item, ["category", "size", "kind", "members"]))
        acc.add_edge("defines_type", acc.binary_node_id, type_id, source_tool="ghidra")

    for item in _as_list(ghidra.get("strings"))[:200]:
        if not isinstance(item, dict):
            continue
        value = _first_text(item.get("string"), item.get("value"), item.get("text"))
        if not value:
            continue
        address = _normalize_address(item.get("address") or item.get("offset"))
        string_id = _node_id("string", address or hashlib.sha1(value.encode()).hexdigest()[:12])
        acc.add_node(string_id, kind="string", label=value[:80], source="ghidra", address=address, properties={"value": value})
        acc.add_edge("contains_string", acc.binary_node_id, string_id, source_tool="ghidra")

    xref_map = ghidra.get("xref_map") or {}
    if isinstance(xref_map, dict):
        for addr, refs in xref_map.items():
            current_addr = _normalize_address(addr)
            if not current_addr or not isinstance(refs, dict):
                continue
            current_id = _node_id("function", current_addr)
            for ref in _as_list(refs.get("to"))[:50]:
                if isinstance(ref, dict):
                    source_addr = _normalize_address(ref.get("from_address") or ref.get("from"))
                    if source_addr:
                        acc.add_edge("xref", _node_id("function", source_addr), current_id, source_tool="ghidra")
            for ref in _as_list(refs.get("from"))[:50]:
                if isinstance(ref, dict):
                    target_addr = _normalize_address(ref.get("to_address") or ref.get("to"))
                    if target_addr:
                        acc.add_edge("calls", current_id, _node_id("function", target_addr), source_tool="ghidra")


def _add_ghidra_gdb_deep(acc: _GraphAccumulator, ghidra_gdb: Any) -> None:
    if not isinstance(ghidra_gdb, dict):
        return

    file_info = ghidra_gdb.get("file_info")
    if isinstance(file_info, dict):
        acc.add_node(
            acc.binary_node_id,
            kind="binary",
            label=acc.binary.name,
            source="ghidra_gdb",
            properties=_pick(
                file_info,
                [
                    "type",
                    "size_bytes",
                    "md5",
                    "sha256",
                    "architecture",
                    "emulator",
                    "native_execution",
                    "format",
                    "is_elf",
                    "bits",
                    "endian",
                    "elf_type",
                    "is_pie",
                ],
            ),
        )

    for item in _as_list(ghidra_gdb.get("sections"))[:100]:
        if not isinstance(item, dict):
            continue
        name = _first_text(item.get("name"), default="section")
        section_id = _node_id("section", name)
        acc.add_node(
            section_id,
            kind="section",
            label=name,
            source="ghidra_gdb",
            address=_normalize_address(_hexish_address(item.get("address"))),
            properties=_pick(item, ["index", "type", "offset", "size"]),
        )
        acc.add_edge("contains_section", acc.binary_node_id, section_id, source_tool="ghidra_gdb")

    for item in _as_list(ghidra_gdb.get("imports"))[:200]:
        if not isinstance(item, dict):
            continue
        name = _first_text(item.get("name"))
        if not name:
            continue
        import_id = _node_id("import", name)
        acc.add_node(import_id, kind="import", label=name, source="ghidra_gdb", properties=_pick(item, ["type"]))
        acc.add_edge("imports", acc.binary_node_id, import_id, source_tool="ghidra_gdb")

    for value in _as_list(ghidra_gdb.get("strings"))[:200]:
        text = _first_text(value)
        if not text:
            continue
        string_id = _node_id("string", hashlib.sha1(text.encode()).hexdigest()[:12])
        acc.add_node(
            string_id,
            kind="string",
            label=text[:80],
            source="ghidra_gdb",
            properties={"value": text},
        )
        acc.add_edge("contains_string", acc.binary_node_id, string_id, source_tool="ghidra_gdb")

    checksec = ghidra_gdb.get("checksec")
    if isinstance(checksec, dict):
        profile_id = _node_id("mitigation_profile", "ghidra_gdb_checksec")
        acc.add_node(
            profile_id,
            kind="mitigation_profile",
            label="GhidraMCP Checksec",
            source="ghidra_gdb",
            properties=_pick(checksec, ["nx", "pie", "relro", "canary", "file_info"]),
        )
        acc.add_edge("has_mitigations", acc.binary_node_id, profile_id, source_tool="ghidra_gdb")

    entry = ghidra_gdb.get("entry")
    if isinstance(entry, dict) and entry.get("entry_point"):
        acc.add_function(
            "ghidra_gdb",
            {
                "addr": entry.get("entry_point"),
                "name": "entry",
            },
        )
        if entry.get("main"):
            acc.add_function(
                "ghidra_gdb",
                {
                    "addr": entry.get("main"),
                    "name": "main",
                },
            )

    cfg = ghidra_gdb.get("cfg")
    if isinstance(cfg, dict):
        for node in _as_list(cfg.get("nodes"))[:500]:
            if isinstance(node, dict):
                acc.add_block("ghidra_gdb", {"addr": node.get("addr"), "size": node.get("size")})
        for edge in _as_list(cfg.get("edges"))[:1000]:
            if not isinstance(edge, dict):
                continue
            source_addr = _normalize_address(edge.get("from"))
            target_addr = _normalize_address(edge.get("to"))
            if source_addr and target_addr:
                acc.add_edge(
                    "control_flow",
                    _node_id("block", source_addr),
                    _node_id("block", target_addr),
                    source_tool="ghidra_gdb",
                )


def _build_summary(nodes: list[AnalysisGraphNode], edges: list[AnalysisGraphEdge]) -> dict[str, Any]:
    node_kinds = Counter(node.kind for node in nodes)
    edge_kinds = Counter(edge.kind for edge in edges)
    tools = sorted(
        node.label
        for node in nodes
        if node.kind == "tool" and node.properties.get("available", node.properties.get("status") != "failed")
    )
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "node_kinds": dict(sorted(node_kinds.items())),
        "edge_kinds": dict(sorted(edge_kinds.items())),
        "tools": tools,
        "tool_count": len(tools),
    }


def _normalize_address(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, int):
        return f"0x{value:x}"
    text = str(value).strip()
    if not text or text == "?":
        return None
    match = re.search(r"0x[0-9a-fA-F]+", text)
    if match:
        return f"0x{int(match.group(0), 16):x}"
    if re.fullmatch(r"[0-9a-fA-F]{4,}", text) and (text.startswith("0") or re.search(r"[a-fA-F]", text)):
        return f"0x{int(text, 16):x}"
    try:
        return f"0x{int(text, 10):x}"
    except ValueError:
        return text.lower()


def _hexish_address(value: Any) -> Any:
    if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{4,}", value.strip()):
        return f"0x{value.strip()}"
    return value


def _node_id(kind: str, key: Any) -> str:
    text = str(key)
    safe = re.sub(r"[^a-zA-Z0-9_.:-]+", "_", text).strip("_")[:96]
    if safe:
        return f"{kind}:{safe}"
    return _stable_id(kind, text)


def _stable_id(prefix: str, *parts: Any) -> str:
    digest = hashlib.sha1("|".join(str(part) for part in parts).encode()).hexdigest()[:16]
    return f"{prefix}:{digest}"


def _first_text(*values: Any, default: str = "") -> str:
    for value in values:
        if isinstance(value, str) and value:
            return value
        if value is not None and not isinstance(value, (dict, list, tuple, set)):
            return str(value)
    return default


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _pick(payload: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    return {key: _json_value(payload[key]) for key in keys if key in payload and payload[key] is not None}


def _json_dict(payload: dict[str, Any]) -> dict[str, Any]:
    return {str(key): _json_value(value) for key, value in payload.items() if value is not None}


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return value[:_MAX_PROPERTY_STRING]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _json_value(v) for k, v in value.items() if v is not None}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in list(value)[:200]]
    return str(value)


__all__ = [
    "AnalysisGraph",
    "AnalysisGraphEdge",
    "AnalysisGraphNode",
    "GRAPH_SCHEMA_VERSION",
    "build_analysis_graph",
]
