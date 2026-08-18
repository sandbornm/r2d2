"""Rank important binary regions and emit Qwen-sized snippet asks.

The live analysis dump is an adapter-shaped bag. This module is the
orchestrator that turns that bag into a small number of concrete regions,
each with a compact dis/asm (or inventory) excerpt and a four-bullet ask
whose answers should sum to a next action.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

BRIEFING_SCHEMA_VERSION = "r2d2.briefing.v1"
MAX_REGIONS = 6
MAX_ASM_LINES = 18
MAX_SNIPPET_CHARS = 1400
MAX_ASK_CHARS = 900

_DANGEROUS_IMPORTS = {
    "system",
    "popen",
    "execve",
    "execl",
    "execlp",
    "execvp",
    "execv",
    "execlpe",
    "execvpe",
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "gets",
    "scanf",
    "sscanf",
    "memcpy",
    "memmove",
    "realpath",
    "tmpnam",
}
_INTERESTING_IMPORTS = {
    "socket",
    "bind",
    "listen",
    "accept",
    "connect",
    "send",
    "recv",
    "sendto",
    "recvfrom",
    "dlopen",
    "dlsym",
    "prctl",
    "ioctl",
    "mmap",
    "mprotect",
    "setuid",
    "setgid",
    "fork",
    "clone",
    "ptrace",
    "system",
}
_NAME_HINTS = (
    "main",
    "entry",
    "http",
    "cgi",
    "login",
    "auth",
    "passwd",
    "password",
    "decrypt",
    "encrypt",
    "aes",
    "md5",
    "sha",
    "nvram",
    "tdp",
    "upgrade",
    "upload",
    "download",
    "cmd",
    "exec",
    "parse",
    "handler",
    "socket",
)
_FIRMWARE_KIND_SCORE = {
    "vendor_wrapper": 96,
    "elf_binary": 94,
    "squashfs_filesystem": 93,
    "uimage": 88,
    "credential_material": 92,
    "device_tree": 78,
    "compressed_stream": 70,
    "firmware_marker": 68,
    "jffs2_marker": 35,
}
_NOISY_FIRMWARE_KINDS = {"jffs2_marker", "firmware_marker"}
_WEAK_STRINGS = {
    "rootpath",
    "rootfs",
    "root",
    "login",
    "auth",
    "tftp",
    "bootcmd=tftp",
}


@dataclass(slots=True)
class RegionSnippet:
    source: str
    kind: str
    text: str
    address: str | None = None
    function: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "kind": self.kind,
            "text": self.text,
            "address": self.address,
            "function": self.function,
        }


@dataclass(slots=True)
class RegionAsk:
    id: str
    title: str
    why: str
    score: float
    tags: list[str] = field(default_factory=list)
    snippet: RegionSnippet | None = None
    ask: str = ""
    next_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "why": self.why,
            "score": self.score,
            "tags": list(self.tags),
            "snippet": self.snippet.to_dict() if self.snippet else None,
            "ask": self.ask,
            "next_actions": list(self.next_actions),
        }


@dataclass(slots=True)
class AnalysisBriefing:
    binary: str
    summary: str
    overall_ask: str
    regions: list[RegionAsk] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    subject: dict[str, Any] = field(default_factory=dict)
    schema_version: str = BRIEFING_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "binary": self.binary,
            "subject": dict(self.subject),
            "summary": self.summary,
            "regions": [region.to_dict() for region in self.regions],
            "overall_ask": self.overall_ask,
            "next_steps": list(self.next_steps),
        }


def build_briefing(
    source: Any,
    *,
    max_regions: int = MAX_REGIONS,
) -> dict[str, Any]:
    """Build a ranked briefing from an AnalysisResult or public analysis dict."""
    analysis = _as_analysis_dict(source)
    binary = str(analysis.get("binary") or "unknown")
    name = Path(binary).name
    quick = _dict(analysis.get("quick_scan"))
    deep = _dict(analysis.get("deep_scan"))
    firmware = _dict(quick.get("firmware"))
    profile = _profile_from_quick(quick)
    r2_quick = _dict(quick.get("radare2"))
    r2_deep = _dict(deep.get("radare2"))
    ghidra = _dict(deep.get("ghidra"))
    children = _dict(deep.get("firmware_children"))

    subject = _subject(name, binary, firmware, profile, r2_quick, r2_deep, analysis)
    candidates = _collect_regions(
        name=name,
        firmware=firmware,
        profile=profile,
        r2_quick=r2_quick,
        r2_deep=r2_deep,
        ghidra=ghidra,
        children=children,
        graph=_dict(analysis.get("analysis_graph")),
        issues=list(analysis.get("issues") or []),
    )
    candidates.sort(key=lambda region: (-region.score, region.id))
    regions = _dedupe_regions(candidates)[: max(1, max_regions)]
    for index, region in enumerate(regions, start=1):
        region.ask = _region_ask(region, index=index, total=len(regions), subject=subject)
        if not region.next_actions:
            region.next_actions = _default_next_actions(region)

    next_steps = _overall_next_steps(subject, regions, firmware, children)
    summary = _summary_line(subject, regions)
    overall_ask = _overall_ask(subject, regions, next_steps)
    return AnalysisBriefing(
        binary=binary,
        subject=subject,
        summary=summary,
        regions=regions,
        overall_ask=overall_ask,
        next_steps=next_steps,
    ).to_dict()


def render_briefing_markdown(
    briefing: dict[str, Any] | AnalysisBriefing,
    *,
    max_regions: int | None = None,
    include_asks: bool = True,
) -> str:
    data = briefing.to_dict() if isinstance(briefing, AnalysisBriefing) else briefing
    regions = list(data.get("regions") or [])
    if max_regions is not None:
        regions = regions[:max_regions]
    subject = _dict(data.get("subject"))
    lines = [
        f"# Briefing: {subject.get('name') or Path(str(data.get('binary') or 'binary')).name}",
        "",
        str(data.get("summary") or "").strip(),
        "",
        "Facts: "
        + ", ".join(
            part
            for part in (
                subject.get("format"),
                subject.get("arch"),
                f"{subject.get('function_count')} functions" if subject.get("function_count") else None,
                f"{subject.get('import_count')} imports" if subject.get("import_count") else None,
                f"risk={subject.get('risk_level')}" if subject.get("risk_level") else None,
            )
            if part
        ),
    ]
    if subject.get("dangerous_imports"):
        lines.append("Dangerous imports: " + ", ".join(subject["dangerous_imports"][:8]))
    if data.get("next_steps"):
        lines.extend(["", "## Next steps"])
        for step in data["next_steps"][:6]:
            lines.append(f"- {step}")
    if regions:
        lines.extend(["", "## Regions"])
    for index, region in enumerate(regions, start=1):
        if not isinstance(region, dict):
            continue
        tags = ", ".join(str(tag) for tag in (region.get("tags") or [])[:5])
        snippet = _dict(region.get("snippet"))
        addr = snippet.get("address") or ""
        func = snippet.get("function") or ""
        loc = " ".join(part for part in (func, addr) if part)
        lines.append(f"\n### {index}. {region.get('title')} ({loc or 'no addr'})")
        if tags:
            lines.append(f"Tags: {tags}")
        if region.get("why"):
            lines.append(f"Why: {region['why']}")
        text = str(snippet.get("text") or "").strip()
        if text:
            fence = "asm" if snippet.get("kind") in {"disasm", "decompile"} else "text"
            lines.append(f"```{fence}")
            lines.append(_clamp(text, MAX_SNIPPET_CHARS))
            lines.append("```")
        if include_asks and region.get("ask"):
            lines.append("Ask:")
            lines.append(_clamp(str(region["ask"]), MAX_ASK_CHARS))
        for action in (region.get("next_actions") or [])[:4]:
            lines.append(f"- {action}")
    if include_asks and data.get("overall_ask"):
        lines.extend(["", "## Overall ask", str(data["overall_ask"]).strip()])
    return "\n".join(lines).strip() + "\n"


def extract_code_snippets(deep_scan: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Flatten adapter snippet bags into a stable list for session persistence."""
    snippets: list[dict[str, Any]] = []
    if not isinstance(deep_scan, dict):
        return snippets

    angr_data = _dict(deep_scan.get("angr"))
    for snippet in _list(angr_data.get("snippets"))[:100]:
        if isinstance(snippet, dict) and snippet.get("instructions"):
            snippets.append(
                {
                    "source": "angr",
                    "address": snippet.get("addr", "0x0"),
                    "function": snippet.get("function_name") or snippet.get("function"),
                    "instructions": list(snippet.get("instructions") or [])[:20],
                }
            )

    r2_data = _dict(deep_scan.get("radare2"))
    for snippet in _list(r2_data.get("snippets"))[:100]:
        if not isinstance(snippet, dict):
            continue
        for block in _list(snippet.get("blocks"))[:10]:
            if isinstance(block, dict) and block.get("disassembly"):
                snippets.append(
                    {
                        "source": "radare2",
                        "address": block.get("offset", "0x0"),
                        "function": snippet.get("function"),
                        "instructions": list(block.get("disassembly") or [])[:20],
                    }
                )
    return snippets[:200]


def _as_analysis_dict(source: Any) -> dict[str, Any]:
    if isinstance(source, dict):
        return source
    plan = getattr(source, "plan", None)
    return {
        "type": "analysis_result",
        "binary": str(getattr(source, "binary", "")),
        "plan": asdict(plan) if plan is not None and hasattr(plan, "__dataclass_fields__") else {},
        "quick_scan": dict(getattr(source, "quick_scan", {}) or {}),
        "deep_scan": dict(getattr(source, "deep_scan", {}) or {}),
        "notes": list(getattr(source, "notes", []) or []),
        "issues": list(getattr(source, "issues", []) or []),
        "trajectory_id": getattr(source, "trajectory_id", None),
        "tool_availability": dict(getattr(source, "tool_availability", {}) or {}),
        "tool_status": dict(getattr(source, "tool_status", {}) or {}),
        "evidence_coverage": dict(getattr(source, "evidence_coverage", {}) or {}),
        "analysis_graph": dict(getattr(source, "analysis_graph", {}) or {}),
    }


def _subject(
    name: str,
    binary: str,
    firmware: dict[str, Any],
    profile: dict[str, Any],
    r2_quick: dict[str, Any],
    r2_deep: dict[str, Any],
    analysis: dict[str, Any],
) -> dict[str, Any]:
    info = _dict(_dict(r2_quick.get("info")).get("bin"))
    core = _dict(_dict(r2_quick.get("info")).get("core"))
    imports = [_import_name(item) for item in _list(r2_quick.get("imports"))]
    dangerous = sorted({item for item in imports if _basename(item) in _DANGEROUS_IMPORTS})
    interesting = sorted({item for item in imports if _basename(item) in _INTERESTING_IMPORTS})
    functions = _list(r2_deep.get("functions"))
    return {
        "name": name,
        "binary": binary,
        "format": firmware.get("top_level_format") or core.get("format") or profile.get("file_type"),
        "arch": _arch_label(info, profile),
        "os": info.get("os") or firmware.get("container_type"),
        "function_count": r2_deep.get("function_count") or len(functions),
        "import_count": len(imports),
        "dangerous_imports": dangerous,
        "interesting_imports": interesting,
        "risk_level": profile.get("risk_level"),
        "risk_factors": list(profile.get("risk_factors") or [])[:6],
        "stripped": profile.get("is_stripped"),
        "issues": list(analysis.get("issues") or [])[:6],
        "firmware_kind": firmware.get("container_type") or firmware.get("top_level_format"),
        "carved_count": len(_list(firmware.get("carved_targets"))),
    }


def _collect_regions(
    *,
    name: str,
    firmware: dict[str, Any],
    profile: dict[str, Any],
    r2_quick: dict[str, Any],
    r2_deep: dict[str, Any],
    ghidra: dict[str, Any],
    children: dict[str, Any],
    graph: dict[str, Any],
    issues: list[Any],
) -> list[RegionAsk]:
    regions: list[RegionAsk] = []
    regions.extend(_firmware_regions(firmware))
    regions.extend(_signal_regions(firmware, profile))
    regions.extend(_import_regions(r2_quick))
    regions.extend(_entry_regions(r2_deep, name))
    regions.extend(_function_regions(r2_deep))
    regions.extend(_ghidra_regions(ghidra))
    regions.extend(_child_regions(children))
    regions.extend(_issue_regions(issues, graph))
    if not regions:
        regions.append(
            RegionAsk(
                id="overview",
                title=f"Characterize {name}",
                why="No high-signal region was isolated; start from file identity and imports.",
                score=40,
                tags=["overview"],
                snippet=RegionSnippet(
                    source="r2d2",
                    kind="inventory",
                    text=_overview_snippet(firmware, profile, r2_quick, r2_deep),
                ),
                next_actions=[
                    "Run a deep radare2 scan (`aaa; afl`) if this was triage-only.",
                    "If this is a vendor wrapper, unpack and re-run on the carved ELF.",
                ],
            )
        )
    return regions


def _firmware_regions(firmware: dict[str, Any]) -> list[RegionAsk]:
    regions: list[RegionAsk] = []
    artifacts = _list(firmware.get("embedded_artifacts")) or _list(firmware.get("recommended_targets"))
    seen_wrappers: set[str] = set()
    for artifact in artifacts[:12]:
        if not isinstance(artifact, dict):
            continue
        kind = str(artifact.get("kind") or "artifact")
        if kind in _NOISY_FIRMWARE_KINDS and not artifact.get("carved_path"):
            continue
        if kind == "vendor_wrapper":
            wrapper_key = str(artifact.get("name") or kind)
            if wrapper_key in seen_wrappers:
                continue
            seen_wrappers.add(wrapper_key)
        score = _FIRMWARE_KIND_SCORE.get(kind, 62)
        if artifact.get("recommended"):
            score += 4
        offset = _hex(artifact.get("offset_hex") or artifact.get("offset"))
        title = str(artifact.get("name") or kind)
        why = str(artifact.get("description") or f"{kind} at {offset or 'unknown offset'}")
        lines = [
            f"kind={kind}",
            f"offset={offset or '?'}",
            f"role={artifact.get('analysis_role') or 'unknown'}",
        ]
        if artifact.get("carved_path"):
            lines.append(f"carved={artifact['carved_path']}")
        if artifact.get("carved_sha256"):
            lines.append(f"sha256={artifact['carved_sha256']}")
        if artifact.get("fanout_tools"):
            lines.append("fanout=" + ",".join(str(tool) for tool in artifact["fanout_tools"][:6]))
        regions.append(
            RegionAsk(
                id=f"fw:{kind}:{offset or title}",
                title=f"Firmware region: {title}",
                why=why,
                score=score,
                tags=["firmware", kind],
                snippet=RegionSnippet(
                    source="firmware",
                    kind="inventory",
                    text="\n".join(lines),
                    address=offset,
                ),
                next_actions=_firmware_next_actions(kind, artifact),
            )
        )
    return regions


def _signal_regions(firmware: dict[str, Any], profile: dict[str, Any]) -> list[RegionAsk]:
    regions: list[RegionAsk] = []
    signals = _dict(firmware.get("string_signals"))
    top = _list(signals.get("top_signals"))
    if not top:
        for key, bucket in (
            ("credential", profile.get("suspicious_strings") or profile.get("network_strings")),
            ("crypto", profile.get("crypto_strings")),
            ("network", profile.get("network_strings")),
        ):
            for value in _list(bucket)[:3]:
                top.append({"category": key, "value": value, "label": key})
    by_cat: dict[str, list[dict[str, Any]]] = {}
    for signal in top:
        if not isinstance(signal, dict):
            continue
        by_cat.setdefault(str(signal.get("category") or "string"), []).append(signal)
    for category, items in by_cat.items():
        if category not in {"credential", "crypto", "network", "command"}:
            continue
        items = [
            item for item in items
            if str(item.get("value") or "").strip().lower() not in _WEAK_STRINGS
            and "tftp" not in str(item.get("value") or "").lower()
        ]
        if not items:
            continue
        score = {"credential": 91, "crypto": 84, "network": 80, "command": 82}.get(category, 70)
        lines = []
        for item in items[:6]:
            offset = _hex(item.get("offset_hex") or item.get("offset"))
            value = _clamp(str(item.get("value") or ""), 80)
            lines.append(f"{offset or '?'}  {value}")
        first = items[0]
        regions.append(
            RegionAsk(
                id=f"signal:{category}",
                title=f"{category.title()} strings",
                why=str(first.get("label") or f"{category} material in the image"),
                score=score,
                tags=["string", category],
                snippet=RegionSnippet(
                    source="firmware",
                    kind="strings",
                    text="\n".join(lines),
                    address=_hex(first.get("offset_hex") or first.get("offset")),
                ),
                next_actions=[
                    f"In r2: `iz~{category}` then `axt` on the first hit.",
                    "Name the function that references the string before going wider.",
                ],
            )
        )
    return regions


def _import_regions(r2_quick: dict[str, Any]) -> list[RegionAsk]:
    imports = [_import_name(item) for item in _list(r2_quick.get("imports"))]
    hits = [name for name in imports if _basename(name) in _DANGEROUS_IMPORTS | _INTERESTING_IMPORTS]
    if not hits:
        return []
    dangerous = [name for name in hits if _basename(name) in _DANGEROUS_IMPORTS]
    score = 93 if dangerous else 76
    text = "\n".join(hits[:16])
    return [
        RegionAsk(
            id="imports:plt",
            title="PLT / imported libc surface",
            why=(
                "Dangerous or network imports are the cheapest cross-refs to follow."
                if dangerous
                else "Network/loader imports mark the user-facing surface."
            ),
            score=score,
            tags=["imports", "plt"] + (["dangerous"] if dangerous else []),
            snippet=RegionSnippet(source="radare2", kind="inventory", text=text),
            next_actions=[
                "r2: `ii` then `axt @ sym.imp.<name>` for each dangerous import.",
                "Rank callers of system/strcpy/sprintf before reading random large functions.",
            ],
        )
    ]


def _entry_regions(r2_deep: dict[str, Any], name: str) -> list[RegionAsk]:
    entry_fn = _dict(r2_deep.get("entry_function"))
    disasm = r2_deep.get("entry_disassembly")
    if not isinstance(disasm, str) or not disasm.strip():
        disasm = r2_deep.get("disassembly")
    if not isinstance(disasm, str) or not disasm.strip():
        return []
    func_name = str(entry_fn.get("name") or "entry")
    offset = _hex(entry_fn.get("offset"))
    return [
        RegionAsk(
            id=f"entry:{func_name}",
            title=f"Entry / {func_name}",
            why=f"Start of {name}; establish calling convention and first callees before hunting bugs.",
            score=89,
            tags=["entry", "disasm"],
            snippet=RegionSnippet(
                source="radare2",
                kind="disasm",
                text=_trim_asm(disasm),
                address=offset,
                function=func_name,
            ),
            next_actions=[
                f"r2: `pdf @ {offset or func_name}` and list calls (`agc`).",
                "If stripped, rename this function after the first identified callee.",
            ],
        )
    ]


def _function_regions(r2_deep: dict[str, Any]) -> list[RegionAsk]:
    regions: list[RegionAsk] = []
    snippets_by_name: dict[str, dict[str, Any]] = {}
    for snippet in _list(r2_deep.get("snippets")):
        if isinstance(snippet, dict) and snippet.get("function"):
            snippets_by_name[str(snippet["function"])] = snippet

    functions = [item for item in _list(r2_deep.get("functions")) if isinstance(item, dict)]
    ranked: list[tuple[float, dict[str, Any]]] = []
    for func in functions:
        name = str(func.get("name") or "")
        size = int(func.get("size") or 0)
        score = min(size / 32.0, 40.0)
        lowered = name.lower()
        if any(hint in lowered for hint in _NAME_HINTS):
            score += 40
        if name in {"main", "entry0", "sym.main", "_main", "entry"}:
            score += 20
        if score >= 36:
            ranked.append((score, func))
    ranked.sort(key=lambda item: -item[0])

    for score, func in ranked[:8]:
        name = str(func.get("name") or "fcn")
        if name in {"main", "entry0", "sym.main", "_main", "entry"}:
            continue
        offset = _hex(func.get("offset"))
        snippet = snippets_by_name.get(name)
        text = _snippet_to_asm(snippet) if snippet else f"{name} @ {offset or '?'} size={func.get('size')}"
        regions.append(
            RegionAsk(
                id=f"func:{name}:{offset or 'unk'}",
                title=f"Function {name}",
                why=f"Name/size heuristic ({func.get('size') or 0} bytes) makes this worth a first look.",
                score=min(88, 50 + score / 2),
                tags=["function", "disasm"],
                snippet=RegionSnippet(
                    source="radare2",
                    kind="disasm" if snippet else "inventory",
                    text=text,
                    address=offset,
                    function=name,
                ),
                next_actions=[
                    f"r2: `pdf @ {offset or name}` and `axt @ {offset or name}`.",
                    "If this takes a buffer, track the source with one xref hop only.",
                ],
            )
        )
    return regions


def _ghidra_regions(ghidra: dict[str, Any]) -> list[RegionAsk]:
    regions: list[RegionAsk] = []
    for func in _list(ghidra.get("decompiled"))[:4]:
        if not isinstance(func, dict):
            continue
        name = str(func.get("name") or "ghidra_fn")
        addr = _hex(func.get("address"))
        body = str(func.get("decompiled_c") or func.get("signature") or "").strip()
        if not body:
            continue
        regions.append(
            RegionAsk(
                id=f"ghidra:{name}:{addr or 'unk'}",
                title=f"Decompiled {name}",
                why="Ghidra C is the cheapest way to name args and see libc calls.",
                score=87,
                tags=["ghidra", "decompile"],
                snippet=RegionSnippet(
                    source="ghidra",
                    kind="decompile",
                    text=_clamp(body, MAX_SNIPPET_CHARS),
                    address=addr,
                    function=name,
                ),
                next_actions=[
                    "Confirm each libc call against the r2 listing before trusting types.",
                    f"Next: xrefs to {addr or name}, then rename from the decompiler signature.",
                ],
            )
        )
    return regions


def _child_regions(children: dict[str, Any]) -> list[RegionAsk]:
    regions: list[RegionAsk] = []
    for analysis in _list(children.get("analyses"))[:6]:
        if not isinstance(analysis, dict):
            continue
        target = str(analysis.get("target") or "child")
        tool = str(analysis.get("tool") or "child")
        deep = _dict(analysis.get("deep"))
        quick = _dict(analysis.get("quick"))
        disasm = deep.get("entry_disassembly") or deep.get("disassembly")
        func_count = deep.get("function_count") or len(_list(deep.get("functions")))
        info = _dict(_dict(quick.get("info")).get("bin"))
        text_parts = [
            f"child={Path(target).name}",
            f"tool={tool} status={analysis.get('status')}",
            f"offset={_hex(analysis.get('offset')) or '?'}",
            f"arch={info.get('arch') or '?'} bits={info.get('bits') or '?'}",
            f"functions={func_count}",
        ]
        kind = "inventory"
        if isinstance(disasm, str) and disasm.strip():
            text_parts.append(_trim_asm(disasm))
            kind = "disasm"
        regions.append(
            RegionAsk(
                id=f"child:{Path(target).name}:{tool}",
                title=f"Carved child {Path(target).name}",
                why="This ELF was carved out of the firmware wrapper and is a better Qwen target than the blob.",
                score=95,
                tags=["firmware-child", tool],
                snippet=RegionSnippet(
                    source=tool,
                    kind=kind,
                    text="\n".join(text_parts),
                    address=_hex(analysis.get("offset")),
                    function=Path(target).name,
                ),
                next_actions=[
                    f"Re-run `r2d2 brief {target}` and send those region asks, not the wrapper blob.",
                    "Prefer httpd/tdpServer/busybox children over kernel or squashfs here.",
                ],
            )
        )
    for skipped in _list(children.get("skipped"))[:2]:
        if not isinstance(skipped, dict):
            continue
        reason = str(skipped.get("reason") or "child fanout skipped")
        regions.append(
            RegionAsk(
                id=f"child-skip:{reason[:24]}",
                title="Firmware child fanout skipped",
                why=reason,
                score=60,
                tags=["firmware-child", "gap"],
                snippet=RegionSnippet(source="firmware", kind="inventory", text=reason),
                next_actions=["Unpack with the firmware skill, then brief an extracted ELF."],
            )
        )
    return regions


def _issue_regions(issues: list[Any], graph: dict[str, Any]) -> list[RegionAsk]:
    regions: list[RegionAsk] = []
    for issue in issues[:3]:
        text = str(issue)
        regions.append(
            RegionAsk(
                id=f"issue:{text[:32]}",
                title="Analysis issue",
                why=text,
                score=72,
                tags=["issue"],
                snippet=RegionSnippet(source="r2d2", kind="inventory", text=text),
                next_actions=["Fix the tooling gap named in the issue before asking the model to guess."],
            )
        )
    for node in _list(graph.get("nodes")):
        if not isinstance(node, dict) or node.get("kind") != "issue":
            continue
        label = str(node.get("label") or "graph issue")
        regions.append(
            RegionAsk(
                id=f"graph-issue:{label[:32]}",
                title=label,
                why="Marked as an issue node on the analysis graph.",
                score=74,
                tags=["issue", "graph"],
                snippet=RegionSnippet(
                    source=str(node.get("source") or "graph"),
                    kind="inventory",
                    text=label,
                    address=_hex(node.get("address")),
                ),
            )
        )
    return regions


def _region_ask(region: RegionAsk, *, index: int, total: int, subject: dict[str, Any]) -> str:
    snippet = region.snippet
    loc = ""
    excerpt = ""
    if snippet:
        loc = " ".join(part for part in (snippet.function, snippet.address) if part)
        excerpt = _clamp(snippet.text, 700)
    lines = [
        f"REGION {index}/{total}: {region.title}" + (f" ({loc})" if loc else ""),
        f"Binary: {subject.get('name')} {subject.get('arch') or ''} {subject.get('format') or ''}".strip(),
        f"Why this region: {region.why}",
    ]
    if excerpt:
        fence = "asm" if snippet and snippet.kind in {"disasm", "decompile"} else "text"
        lines.extend(["", f"```{fence}", excerpt, "```", ""])
    lines.extend(
        [
            "You are briefing a professional RE. Do not define terms. Do not restate the listing.",
            "Answer in exactly 4 bullets:",
            "1. The non-obvious claim this snippet supports (or 'nothing interesting')",
            "2. Trust boundary / attacker-controlled data visible HERE only",
            "3. Highest-value next address, callee, or carved file — and why it could surprise",
            "4. One exact next command (r2, Ghidra headless, or unpack)",
            "Rules: do not invent symbols absent from the snippet; no exploit/PoC; no tutorial.",
        ]
    )
    return _clamp("\n".join(lines), MAX_ASK_CHARS)


def _overall_ask(subject: dict[str, Any], regions: list[RegionAsk], next_steps: list[str]) -> str:
    region_lines = []
    for index, region in enumerate(regions, start=1):
        loc = ""
        if region.snippet:
            loc = " ".join(part for part in (region.snippet.function, region.snippet.address) if part)
        region_lines.append(f"{index}. {region.title}" + (f" @ {loc}" if loc else "") + f" — {region.why}")
    facts = [
        f"Binary: {subject.get('name')}",
        f"Format/arch: {subject.get('format') or '?'} {subject.get('arch') or '?'}",
        f"Functions: {subject.get('function_count') or 0}; imports: {subject.get('import_count') or 0}",
    ]
    if subject.get("dangerous_imports"):
        facts.append("Dangerous imports: " + ", ".join(subject["dangerous_imports"][:8]))
    if subject.get("firmware_kind"):
        facts.append(f"Firmware container: {subject['firmware_kind']} ({subject.get('carved_count') or 0} carved)")
    if subject.get("risk_level"):
        facts.append(f"Autoprofile risk: {subject['risk_level']}")
    lines = [
        "PROFESSIONAL TRIAGE — facts and region titles only. No lecture.",
        *facts,
        "",
        "Ranked regions:",
        *region_lines,
        "",
        "Answer in exactly 6 bullets:",
        "1. What is actually unusual (not 'it is firmware')",
        "2. Highest-leverage region and the claim it supports",
        "3. Best next ELF/function — prefer httpd/tdpServer/sink callers over size",
        "4. What is still unknown (missing carve, stripped names, dead tool)",
        "5. Exact next r2 or Ghidra-headless command",
        "6. Exact next unpack step if this is still a wrapper",
        "Rules: defensive only; no exploit steps; do not invent symbols.",
    ]
    if next_steps:
        lines.extend(["", "Analyst next steps already queued:"] + [f"- {step}" for step in next_steps[:4]])
    return _clamp("\n".join(lines), 1600)


def _overall_next_steps(
    subject: dict[str, Any],
    regions: list[RegionAsk],
    firmware: dict[str, Any],
    children: dict[str, Any],
) -> list[str]:
    steps: list[str] = []
    if firmware.get("top_level_format") and not _list(children.get("analyses")):
        steps.append("Unpack the vendor wrapper and brief a carved ELF (httpd/tdpServer), not the .bin.")
    if subject.get("dangerous_imports"):
        first = subject["dangerous_imports"][0]
        steps.append(f"r2: `axt @ sym.imp.{_basename(first)}` and brief that caller.")
    if regions:
        top = regions[0]
        addr = top.snippet.address if top.snippet else None
        if addr:
            steps.append(f"Open {top.title} at {addr} and send that region ask first.")
        else:
            steps.append(f"Send region ask #1 ({top.title}) before a whole-binary question.")
    if subject.get("stripped"):
        steps.append("Binary looks stripped: rename from Ghidra signatures before asking about 'unknown functions'.")
    if not steps:
        steps.append("Ask the overall briefing question, then one region, then stop.")
    return steps[:6]


def _default_next_actions(region: RegionAsk) -> list[str]:
    addr = region.snippet.address if region.snippet else None
    if addr:
        return [f"r2: `pd 32 @ {addr}`", f"r2: `axt @ {addr}`"]
    return ["Inspect this region in r2/Ghidra before expanding scope."]


def _firmware_next_actions(kind: str, artifact: dict[str, Any]) -> list[str]:
    carved = artifact.get("carved_path")
    if kind in {"vendor_wrapper", "firmware_marker"}:
        return [
            "Identify the wrapper (ver. 2.0 / Cloud / IMG0 / fwup-ptn) and carve kernel + rootfs.",
            "Do not send the wrapper blob to the model; brief the extracted ELF instead.",
        ]
    if kind == "squashfs_filesystem":
        return [
            "unsquashfs/sasquatch the filesystem, then brief usr/bin/httpd or tdpServer.",
            f"Carve offset {artifact.get('offset_hex') or artifact.get('offset')} if not already extracted.",
        ]
    if kind == "elf_binary" and carved:
        return [f"r2d2 brief {carved}", "Prefer this child over the container for Qwen asks."]
    if carved:
        return [f"Inspect carved file {carved} with file(1) then r2d2 brief."]
    return [f"Carve at {artifact.get('offset_hex') or artifact.get('offset')} and identify the payload."]


def _summary_line(subject: dict[str, Any], regions: list[RegionAsk]) -> str:
    parts = [
        f"{subject.get('name')} looks like {subject.get('format') or 'an unidentified image'}",
        f"{subject.get('arch') or 'unknown arch'}",
    ]
    if subject.get("function_count"):
        parts.append(f"{subject['function_count']} functions")
    if subject.get("dangerous_imports"):
        parts.append("imports " + ", ".join(subject["dangerous_imports"][:4]))
    top = regions[0].title if regions else "no ranked region"
    return f"{'; '.join(parts)}. First region: {top}."


def _overview_snippet(
    firmware: dict[str, Any],
    profile: dict[str, Any],
    r2_quick: dict[str, Any],
    r2_deep: dict[str, Any],
) -> str:
    info = _dict(_dict(r2_quick.get("info")).get("bin"))
    lines = [
        f"file_type={profile.get('file_type') or firmware.get('top_level_format') or '?'}",
        f"arch={info.get('arch') or profile.get('architecture') or '?'}",
        f"functions={r2_deep.get('function_count') or len(_list(r2_deep.get('functions')))}",
        f"imports={len(_list(r2_quick.get('imports')))}",
    ]
    if firmware.get("top_level_format"):
        lines.append(f"firmware={firmware.get('top_level_format')} / {firmware.get('container_type')}")
    return "\n".join(lines)


def _profile_from_quick(quick: dict[str, Any]) -> dict[str, Any]:
    raw = quick.get("autoprofile")
    if not isinstance(raw, dict):
        return {}
    profile = raw.get("profile")
    return profile if isinstance(profile, dict) else raw


def _snippet_to_asm(snippet: dict[str, Any] | None) -> str:
    if not snippet:
        return ""
    lines: list[str] = []
    for block in _list(snippet.get("blocks"))[:4]:
        if not isinstance(block, dict):
            continue
        for op in _list(block.get("disassembly"))[:MAX_ASM_LINES]:
            if not isinstance(op, dict):
                continue
            addr = op.get("addr") or ""
            opcode = op.get("opcode") or " ".join(
                part for part in (op.get("mnemonic"), op.get("op_str")) if part
            )
            raw = op.get("bytes") or ""
            lines.append(f"{addr}  {raw}  {opcode}".rstrip())
        if len(lines) >= MAX_ASM_LINES:
            break
    return "\n".join(lines[:MAX_ASM_LINES])


def _trim_asm(text: str) -> str:
    cleaned = []
    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped:
            cleaned.append(stripped)
        if len(cleaned) >= MAX_ASM_LINES:
            break
    return "\n".join(cleaned)


def _dedupe_regions(regions: Iterable[RegionAsk]) -> list[RegionAsk]:
    seen: set[str] = set()
    unique: list[RegionAsk] = []
    for region in regions:
        key = region.id
        if region.snippet and region.snippet.address and region.snippet.function:
            key = f"{region.snippet.function}:{region.snippet.address}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(region)
    return unique


def _import_name(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("name") or item.get("plt") or "")
    return str(item or "")


def _basename(symbol: str) -> str:
    return re.sub(r"^(sym\.imp\.|imp\.|sym\.)", "", symbol).split("@", 1)[0]


def _arch_label(info: dict[str, Any], profile: dict[str, Any]) -> str | None:
    arch = info.get("arch") or profile.get("architecture")
    bits = info.get("bits") or profile.get("bits")
    if arch and bits:
        return f"{arch}/{bits}"
    if arch:
        return str(arch)
    return None


def _hex(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("0x") or text.startswith("0X"):
            return text.lower()
        if text.isdigit():
            return hex(int(text))
        return text
    if isinstance(value, int):
        return hex(value)
    return str(value)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _clamp(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 16)].rstrip() + "\n...[truncated]"


__all__ = [
    "BRIEFING_SCHEMA_VERSION",
    "AnalysisBriefing",
    "RegionAsk",
    "RegionSnippet",
    "build_briefing",
    "extract_code_snippets",
    "render_briefing_markdown",
]
