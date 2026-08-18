"""Durable, tagged, per-binary analysis records.

A record is content-addressed by SHA-256 and stored as a directory of
JSON/Markdown files. Re-running analysis *merges* into the existing
record instead of replacing it, so tool blobs, region commentary, and
serialized CFGs stay revisitable and extensible.

This is the backing store for "one binary, many passes." Chat sessions
and analysis bundles remain views over a record; they are not the
source of truth.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .briefing import render_briefing_markdown
from .result_dto import analysis_result_core_dict, ensure_analysis_briefing

RECORD_SCHEMA_VERSION = "r2d2.analysis_record.v1"
_MAX_STRINGS = 80
_MAX_FUNCTIONS = 400
_MAX_IMPORTS = 120
_MAX_CFG_FUNCS = 40
_MAX_CFG_BLOCKS = 48
_MAX_CFG_OPS = 40


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


class AnalysisRecordStore:
    """Filesystem store: ``<root>/records/<aa>/<sha256>/``."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).expanduser()
        self.records_root = self.root / "records"

    def record_dir(self, record_id: str) -> Path:
        digest = _normalize_id(record_id)
        return self.records_root / digest[:2] / digest

    def persist(
        self,
        analysis: Any,
        *,
        binary: Path | None = None,
        extra_tags: Iterable[str] | None = None,
        extra_meta: dict[str, Any] | None = None,
        session_id: str | None = None,
        parent_id: str | None = None,
    ) -> dict[str, Any]:
        payload = _as_analysis_dict(analysis)
        path = Path(binary or payload.get("binary") or "")
        if not path or not path.exists():
            raise FileNotFoundError(f"Cannot persist analysis without a readable binary: {path}")

        digest = sha256_file(path)
        directory = self.record_dir(digest)
        directory.mkdir(parents=True, exist_ok=True)

        existing = _read_json(directory / "record.json") or {}
        briefing = ensure_analysis_briefing(payload)
        subject = _build_subject(path, digest, payload, extra_meta)
        tags = sorted(
            set(_derive_tags(path, payload, subject, briefing))
            | set(extra_tags or [])
            | set(existing.get("tags") or [])
        )
        tools = _collect_tool_blobs(payload)
        cfgs = _collect_cfgs(payload)
        regions = _regions_from_briefing(briefing)
        artifacts = _collect_artifacts(payload)
        children = _collect_children(payload)

        stamp = utcnow()
        created = existing.get("created_at") or stamp
        revision = int(existing.get("revision") or 0) + 1

        _write_json(directory / "subject.json", subject)
        _write_json(directory / "briefing.json", briefing)
        (directory / "briefing.md").write_text(
            render_briefing_markdown(briefing, include_asks=True),
            encoding="utf-8",
        )
        if payload.get("analysis_graph"):
            _write_json(directory / "graphs" / "analysis_graph.json", payload["analysis_graph"])

        tool_index: dict[str, Any] = dict(existing.get("tools") or {})
        for name, blob in tools.items():
            merged = _merge_tool_blob(_read_json(directory / "tools" / f"{name}.json"), blob)
            _write_json(directory / "tools" / f"{name}.json", merged)
            status = _dict(payload.get("tool_status")).get(name) if isinstance(payload.get("tool_status"), dict) else {}
            tool_index[name] = {
                "status": _dict(status).get("status") or ("completed" if merged else "unknown"),
                "updated_at": stamp,
                "blob": f"tools/{name}.json",
                "keys": sorted(merged)[:24] if isinstance(merged, dict) else [],
            }

        cfg_files: list[str] = list(existing.get("graphs", {}).get("cfgs") or []) if isinstance(existing.get("graphs"), dict) else []
        for cfg in cfgs:
            name = _safe_name(str(cfg.get("name") or cfg.get("offset") or "func"))
            rel = f"graphs/cfg/{name}.json"
            _write_json(directory / rel, cfg)
            if rel not in cfg_files:
                cfg_files.append(rel)

        region_index: list[dict[str, Any]] = list(existing.get("regions") or [])
        seen_regions = {item.get("id") for item in region_index if isinstance(item, dict)}
        for region in regions:
            region_id = str(region.get("id") or "region")
            rel_json = f"regions/{_safe_name(region_id)}.json"
            rel_md = f"regions/{_safe_name(region_id)}.md"
            _write_json(directory / rel_json, region)
            (directory / rel_md).parent.mkdir(parents=True, exist_ok=True)
            (directory / rel_md).write_text(_region_markdown(region), encoding="utf-8")
            entry = {
                "id": region_id,
                "title": region.get("title"),
                "tags": region.get("tags") or [],
                "score": region.get("score"),
                "path": rel_json,
                "commentary": rel_md,
            }
            if region_id in seen_regions:
                region_index = [entry if item.get("id") == region_id else item for item in region_index]
            else:
                region_index.append(entry)
                seen_regions.add(region_id)

        artifact_manifest = {
            "schema_version": "r2d2.record_artifacts.v1",
            "files": artifacts,
        }
        _write_json(directory / "artifacts" / "manifest.json", artifact_manifest)

        analyst_notes = _extract_analyst_notes(directory / "commentary.md")
        commentary = _render_commentary(subject, tags, tool_index, regions, artifacts, analyst_notes)
        (directory / "commentary.md").write_text(commentary, encoding="utf-8")

        record = {
            "schema_version": RECORD_SCHEMA_VERSION,
            "record_id": digest,
            "sha256": digest,
            "size_bytes": path.stat().st_size,
            "paths": _unique([*(existing.get("paths") or []), str(path.resolve())]),
            "names": _unique([*(existing.get("names") or []), path.name]),
            "tags": tags,
            "created_at": created,
            "updated_at": stamp,
            "revision": revision,
            "parent_id": parent_id or existing.get("parent_id"),
            "children": _merge_children(existing.get("children") or [], children),
            "session_ids": _unique([*(existing.get("session_ids") or []), session_id]),
            "trajectory_ids": _unique([*(existing.get("trajectory_ids") or []), payload.get("trajectory_id")]),
            "subject": "subject.json",
            "commentary": "commentary.md",
            "briefing": "briefing.json",
            "tools": tool_index,
            "regions": region_index,
            "graphs": {
                "analysis_graph": "graphs/analysis_graph.json" if payload.get("analysis_graph") else None,
                "cfgs": cfg_files[:_MAX_CFG_FUNCS],
            },
            "artifacts": "artifacts/manifest.json",
            "metadata": extra_meta or existing.get("metadata") or {},
            "notes": list(payload.get("notes") or existing.get("notes") or []),
            "issues": list(payload.get("issues") or existing.get("issues") or []),
        }
        if existing.get("metadata") and extra_meta:
            record["metadata"] = {**_dict(existing.get("metadata")), **extra_meta}

        _write_json(directory / "record.json", record)
        _write_json(
            directory / "revisions" / f"{revision:04d}-{_safe_name(stamp)}.json",
            {
                "revision": revision,
                "updated_at": stamp,
                "session_id": session_id,
                "tools": sorted(tools),
                "region_ids": [region.get("id") for region in regions],
                "tags_added": sorted(set(tags) - set(existing.get("tags") or [])),
            },
        )
        _update_index(self.records_root, record_summary(record, directory))
        return record_summary(record, directory)

    def load(self, record_id: str, *, include_blobs: bool = False) -> dict[str, Any] | None:
        directory = self.record_dir(record_id)
        record = _read_json(directory / "record.json")
        if not record:
            return None
        summary = record_summary(record, directory)
        if not include_blobs:
            return summary
        summary["subject_blob"] = _read_json(directory / "subject.json")
        summary["briefing_blob"] = _read_json(directory / "briefing.json")
        summary["commentary_text"] = _read_text(directory / "commentary.md")
        summary["analysis_graph"] = _read_json(directory / "graphs" / "analysis_graph.json")
        summary["tool_blobs"] = {
            name: _read_json(directory / meta["blob"])
            for name, meta in _dict(record.get("tools")).items()
            if isinstance(meta, dict) and meta.get("blob")
        }
        summary["region_blobs"] = [
            _read_json(directory / item["path"])
            for item in (record.get("regions") or [])
            if isinstance(item, dict) and item.get("path")
        ]
        summary["cfg_blobs"] = [
            _read_json(directory / rel)
            for rel in ((record.get("graphs") or {}).get("cfgs") or [])
        ]
        summary["artifact_manifest"] = _read_json(directory / "artifacts" / "manifest.json")
        return summary

    def list_records(self, *, tag: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        index = _read_json(self.records_root / "index.json") or {"records": []}
        rows = [row for row in index.get("records") or [] if isinstance(row, dict)]
        if tag:
            wanted = tag.lower()
            rows = [row for row in rows if wanted in [str(item).lower() for item in (row.get("tags") or [])]]
        rows.sort(key=lambda row: str(row.get("updated_at") or ""), reverse=True)
        return rows[: max(1, limit)]


def record_summary(record: dict[str, Any], directory: Path) -> dict[str, Any]:
    return {
        "schema_version": record.get("schema_version") or RECORD_SCHEMA_VERSION,
        "record_id": record.get("record_id"),
        "sha256": record.get("sha256"),
        "names": record.get("names") or [],
        "paths": record.get("paths") or [],
        "tags": record.get("tags") or [],
        "revision": record.get("revision") or 1,
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
        "parent_id": record.get("parent_id"),
        "children": record.get("children") or [],
        "session_ids": record.get("session_ids") or [],
        "trajectory_ids": record.get("trajectory_ids") or [],
        "tool_names": sorted(_dict(record.get("tools"))),
        "region_count": len(record.get("regions") or []),
        "cfg_count": len(((record.get("graphs") or {}).get("cfgs")) or []),
        "issues": record.get("issues") or [],
        "directory": str(directory),
        "commentary": record.get("commentary"),
    }


def _as_analysis_dict(source: Any) -> dict[str, Any]:
    if isinstance(source, dict):
        return source
    return analysis_result_core_dict(source)


def _build_subject(
    path: Path,
    digest: str,
    analysis: dict[str, Any],
    extra_meta: dict[str, Any] | None,
) -> dict[str, Any]:
    quick = _dict(analysis.get("quick_scan"))
    firmware = _dict(quick.get("firmware"))
    profile = _profile(quick)
    r2 = _dict(quick.get("radare2"))
    info = _dict(_dict(r2.get("info")).get("bin"))
    core = _dict(_dict(r2.get("info")).get("core"))
    subject = {
        "name": path.name,
        "path": str(path.resolve()),
        "sha256": digest,
        "size_bytes": path.stat().st_size,
        "format": firmware.get("top_level_format") or core.get("format") or profile.get("file_type"),
        "arch": info.get("arch") or profile.get("architecture"),
        "bits": info.get("bits") or profile.get("bits"),
        "os": info.get("os") or firmware.get("container_type"),
        "stripped": profile.get("is_stripped"),
        "risk_level": profile.get("risk_level"),
        "firmware_kind": firmware.get("container_type") or firmware.get("top_level_format"),
    }
    if extra_meta:
        subject["lab"] = extra_meta
    return subject


def _derive_tags(
    path: Path,
    analysis: dict[str, Any],
    subject: dict[str, Any],
    briefing: dict[str, Any],
) -> list[str]:
    tags: set[str] = set()
    fmt = str(subject.get("format") or "").lower()
    file_type = str(_profile(_dict(analysis.get("quick_scan"))).get("file_type") or "").lower()
    if "elf" in fmt or "elf" in file_type:
        tags.add("elf")
    if subject.get("firmware_kind") or "firmware" in fmt or "container" in fmt:
        tags.add("firmware")
    if subject.get("arch"):
        bits = subject.get("bits")
        tags.add(str(subject["arch"]).lower())
        if bits:
            tags.add(f"{str(subject['arch']).lower()}{bits}")
    if subject.get("stripped"):
        tags.add("stripped")
    if subject.get("risk_level"):
        tags.add(f"risk-{subject['risk_level']}")
    stem = path.name.lower()
    for hint in ("httpd", "tdpserver", "busybox", "dropbear", "uhttpd", "tmpServer".lower()):
        if hint in stem:
            tags.add(hint)
    for region in briefing.get("regions") or []:
        if not isinstance(region, dict):
            continue
        for tag in region.get("tags") or []:
            tags.add(str(tag))
    imports = [
        str(item.get("name") if isinstance(item, dict) else item).lower()
        for item in _list(_dict(_dict(analysis.get("quick_scan")).get("radare2")).get("imports"))
    ]
    if any("system" in name or "strcpy" in name for name in imports):
        tags.add("dangerous-imports")
    if any(name for name in imports if "socket" in name or "accept" in name):
        tags.add("network")
    return sorted(tag for tag in tags if tag)


def _collect_tool_blobs(analysis: dict[str, Any]) -> dict[str, dict[str, Any]]:
    blobs: dict[str, dict[str, Any]] = {}
    for stage_name in ("quick_scan", "deep_scan"):
        stage = _dict(analysis.get(stage_name))
        for name, payload in stage.items():
            if not isinstance(payload, dict):
                continue
            compacted = _compact_tool_blob(name, payload)
            existing = blobs.get(name, {})
            blobs[name] = _merge_tool_blob(existing, compacted)
    return blobs


def _compact_tool_blob(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    if name == "radare2":
        functions = []
        for func in _list(payload.get("functions"))[:_MAX_FUNCTIONS]:
            if not isinstance(func, dict):
                continue
            functions.append(
                {
                    "name": func.get("name"),
                    "offset": func.get("offset"),
                    "size": func.get("size"),
                }
            )
        return {
            "info": payload.get("info"),
            "imports": _list(payload.get("imports"))[:_MAX_IMPORTS],
            "strings": _list(payload.get("strings"))[:_MAX_STRINGS],
            "sections": _list(payload.get("sections"))[:40],
            "entry_points": payload.get("entry_points"),
            "entry_function": payload.get("entry_function"),
            "entry_disassembly": payload.get("entry_disassembly"),
            "function_count": payload.get("function_count") or len(functions),
            "functions": functions,
            "snippets": payload.get("snippets") or [],
        }
    if name == "firmware":
        return {
            "top_level_format": payload.get("top_level_format"),
            "container_type": payload.get("container_type"),
            "sha256": payload.get("sha256"),
            "size_bytes": payload.get("size_bytes"),
            "scan": payload.get("scan"),
            "embedded_artifacts": payload.get("embedded_artifacts") or [],
            "recommended_targets": payload.get("recommended_targets") or [],
            "carved_targets": payload.get("carved_targets") or [],
            "string_signals": payload.get("string_signals") or {},
        }
    if name == "sniff":
        return {
            "mode": payload.get("mode"),
            "file": payload.get("file"),
            "sha256": payload.get("sha256"),
            "size_bytes": payload.get("size_bytes"),
            "hex_head": payload.get("hex_head"),
            "strings": _list(payload.get("strings"))[:_MAX_STRINGS],
            "readelf": payload.get("readelf"),
            "tools": payload.get("tools"),
        }
    if name in {"autoprofile", "libmagic", "identification", "runtime"}:
        return payload
    if name == "ghidra":
        return {
            "mode": payload.get("mode"),
            "function_count": payload.get("function_count"),
            "decompiled": _list(payload.get("decompiled"))[:12],
            "error": payload.get("error"),
        }
    if name == "firmware_children":
        compact_children = []
        for item in _list(payload.get("analyses"))[:8]:
            if not isinstance(item, dict):
                continue
            compact_children.append(
                {
                    "target": item.get("target"),
                    "offset": item.get("offset"),
                    "kind": item.get("kind"),
                    "tool": item.get("tool"),
                    "status": item.get("status"),
                    "function_count": _dict(item.get("deep")).get("function_count"),
                }
            )
        return {"mode": payload.get("mode"), "analyses": compact_children, "skipped": payload.get("skipped") or []}
    keep = {key: payload[key] for key in list(payload)[:20]}
    return keep


def _collect_cfgs(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    deep = _dict(analysis.get("deep_scan"))
    r2 = _dict(deep.get("radare2"))
    cfgs: list[dict[str, Any]] = []
    for func in _list(r2.get("function_cfgs"))[:_MAX_CFG_FUNCS]:
        if not isinstance(func, dict):
            continue
        blocks = []
        for block in _list(func.get("blocks"))[:_MAX_CFG_BLOCKS]:
            if not isinstance(block, dict):
                continue
            blocks.append(
                {
                    "offset": block.get("offset"),
                    "size": block.get("size"),
                    "jump": block.get("jump"),
                    "fail": block.get("fail"),
                    "disassembly": _list(block.get("disassembly"))[:_MAX_CFG_OPS],
                }
            )
        cfgs.append(
            {
                "schema_version": "r2d2.function_cfg.v1",
                "source": "radare2",
                "name": func.get("name"),
                "offset": func.get("offset"),
                "size": func.get("size"),
                "block_count": func.get("block_count") or len(blocks),
                "blocks": blocks,
            }
        )
    angr = _dict(deep.get("angr"))
    cfg = _dict(angr.get("cfg"))
    if cfg.get("nodes") or cfg.get("edges"):
        cfgs.append(
            {
                "schema_version": "r2d2.function_cfg.v1",
                "source": "angr",
                "name": "angr_cfg",
                "nodes": _list(cfg.get("nodes"))[:200],
                "edges": _list(cfg.get("edges"))[:400],
            }
        )
    return cfgs


def _collect_artifacts(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    firmware = _dict(_dict(analysis.get("quick_scan")).get("firmware"))
    files: list[dict[str, Any]] = []
    for target in _list(firmware.get("carved_targets")):
        if not isinstance(target, dict):
            continue
        files.append(
            {
                "kind": target.get("kind"),
                "role": target.get("analysis_role") or "artifact",
                "path": target.get("carved_path"),
                "offset": target.get("offset") or target.get("offset_hex"),
                "sha256": target.get("carved_sha256"),
                "size_bytes": target.get("carved_size"),
            }
        )
    return files


def _collect_children(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    children: list[dict[str, Any]] = []
    firmware = _dict(_dict(analysis.get("quick_scan")).get("firmware"))
    for target in _list(firmware.get("carved_targets")):
        if not isinstance(target, dict):
            continue
        if target.get("analysis_role") != "code" or not target.get("carved_path"):
            continue
        child_path = Path(str(target["carved_path"]))
        entry = {
            "path": str(child_path),
            "kind": target.get("kind"),
            "role": "code",
            "offset": target.get("offset"),
        }
        if child_path.is_file():
            try:
                entry["sha256"] = sha256_file(child_path)
                entry["record_id"] = entry["sha256"]
            except OSError:
                pass
        children.append(entry)
    return children


def _regions_from_briefing(briefing: dict[str, Any]) -> list[dict[str, Any]]:
    regions = []
    for region in briefing.get("regions") or []:
        if isinstance(region, dict):
            regions.append(dict(region))
    return regions


def _region_markdown(region: dict[str, Any]) -> str:
    snippet = region.get("snippet") if isinstance(region.get("snippet"), dict) else {}
    lines = [
        f"# {region.get('title') or region.get('id')}",
        "",
        f"Why: {region.get('why') or ''}",
        "",
    ]
    if region.get("tags"):
        lines.append("Tags: " + ", ".join(str(tag) for tag in region["tags"]))
        lines.append("")
    text = str((snippet or {}).get("text") or "").strip()
    if text:
        fence = "asm" if snippet.get("kind") in {"disasm", "decompile"} else "text"
        lines.extend([f"```{fence}", text, "```", ""])
    if region.get("next_actions"):
        lines.append("Next:")
        for action in region["next_actions"]:
            lines.append(f"- {action}")
    return "\n".join(lines).strip() + "\n"


def _render_commentary(
    subject: dict[str, Any],
    tags: list[str],
    tools: dict[str, Any],
    regions: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    analyst_notes: str,
) -> str:
    lines = [
        f"# Analysis: {subject.get('name')}",
        "",
        f"SHA-256: `{subject.get('sha256')}`",
        f"Format: {subject.get('format') or '?'} · {subject.get('arch') or '?'}/{subject.get('bits') or '?'}",
        f"Tags: {', '.join(tags) if tags else '(none)'}",
        "",
        "## Tools",
    ]
    if tools:
        for name, meta in sorted(tools.items()):
            status = _dict(meta).get("status") or "?"
            lines.append(f"- `{name}`: {status}")
    else:
        lines.append("- (none recorded)")
    lines.extend(["", "## Interesting regions"])
    if regions:
        for index, region in enumerate(regions, start=1):
            loc = ""
            snippet = region.get("snippet") if isinstance(region.get("snippet"), dict) else {}
            if snippet:
                loc = " ".join(part for part in (snippet.get("function"), snippet.get("address")) if part)
            lines.append(f"### {index}. {region.get('title')}" + (f" ({loc})" if loc else ""))
            if region.get("why"):
                lines.append(region["why"])
            lines.append("")
    else:
        lines.append("No ranked regions yet.")
        lines.append("")
    if artifacts:
        lines.extend(["## Artifacts"])
        for item in artifacts[:20]:
            lines.append(
                f"- {item.get('kind') or 'file'} {item.get('path') or ''} "
                f"@ {item.get('offset') or '?'}"
            )
        lines.append("")
    lines.extend(["## Analyst notes", analyst_notes or "_Add notes here; this section is preserved across re-runs._", ""])
    return "\n".join(lines)


def _extract_analyst_notes(path: Path) -> str:
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8")
    marker = "## Analyst notes"
    if marker not in text:
        return ""
    notes = text.split(marker, 1)[1].strip()
    lines = [
        line
        for line in notes.splitlines()
        if line.strip() and not line.startswith("_Add notes here")
    ]
    return "\n".join(lines).strip()


def _merge_tool_blob(old: dict[str, Any] | None, new: dict[str, Any] | None) -> dict[str, Any]:
    if not old:
        return dict(new or {})
    if not new:
        return dict(old)
    merged = dict(old)
    for key, value in new.items():
        if value in (None, [], {}, ""):
            continue
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


def _merge_children(old: list[Any], new: list[Any]) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for item in [*old, *new]:
        if not isinstance(item, dict):
            continue
        key = str(item.get("sha256") or item.get("path") or len(by_key))
        by_key[key] = {**by_key.get(key, {}), **item}
    return list(by_key.values())


def _update_index(records_root: Path, summary: dict[str, Any]) -> None:
    path = records_root / "index.json"
    index = _read_json(path) or {"schema_version": "r2d2.record_index.v1", "records": []}
    rows = [row for row in index.get("records") or [] if isinstance(row, dict)]
    rows = [row for row in rows if row.get("record_id") != summary.get("record_id")]
    rows.append(
        {
            "record_id": summary.get("record_id"),
            "sha256": summary.get("sha256"),
            "names": summary.get("names"),
            "tags": summary.get("tags"),
            "updated_at": summary.get("updated_at"),
            "revision": summary.get("revision"),
            "directory": summary.get("directory"),
            "region_count": summary.get("region_count"),
        }
    )
    rows.sort(key=lambda row: str(row.get("updated_at") or ""), reverse=True)
    _write_json(path, {"schema_version": "r2d2.record_index.v1", "updated_at": utcnow(), "records": rows[:500]})


def _profile(quick: dict[str, Any]) -> dict[str, Any]:
    raw = quick.get("autoprofile")
    if not isinstance(raw, dict):
        return {}
    profile = raw.get("profile")
    return profile if isinstance(profile, dict) else raw


def _normalize_id(record_id: str) -> str:
    text = record_id.strip().lower()
    if "/" in text:
        text = Path(text).name
    if not re.fullmatch(r"[0-9a-f]{16,64}", text):
        raise ValueError(f"Invalid record id: {record_id}")
    return text


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return cleaned[:80] or "item"


def _unique(values: Iterable[Any]) -> list[Any]:
    seen: set[str] = set()
    items: list[Any] = []
    for value in values:
        if value in (None, ""):
            continue
        key = str(value)
        if key in seen:
            continue
        seen.add(key)
        items.append(value)
    return items


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


__all__ = [
    "RECORD_SCHEMA_VERSION",
    "AnalysisRecordStore",
    "record_summary",
    "sha256_file",
]
