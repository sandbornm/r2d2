"""Cross-record pattern cards.

This is *not* a skill factory. It only reports facts that appear in at
least two persisted records. One binary is a briefing; two siblings are
the first reusable pattern. Auto-writing SKILL.md from a thin corpus
produces lectures, not skills.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .record import AnalysisRecordStore, utcnow

INSIGHTS_SCHEMA_VERSION = "r2d2.insights.v1"
MIN_SIBLINGS = 2
_WEAK_TAGS = {
    "disasm",
    "entry",
    "function",
    "decompile",
    "strings",
    "inventory",
    "overview",
    "graph",
    "issue",
    "dangerous",
    "plt",
}


def extract_insights(
    store: AnalysisRecordStore,
    *,
    focus_id: str | None = None,
    tag: str | None = None,
    limit: int = 8,
) -> dict[str, Any]:
    catalog = store.list_records(tag=tag, limit=200)
    if focus_id:
        focus = store.load(focus_id)
        if not focus:
            return _empty(reason=f"record {focus_id} not found", focus_id=focus_id)
        catalog = _siblings(catalog, focus)
    if len(catalog) < MIN_SIBLINGS:
        return _empty(
            reason=(
                f"Need at least {MIN_SIBLINGS} tagged sibling records to distill patterns. "
                "Analyze another related binary (same httpd / wrapper family) first."
            ),
            focus_id=focus_id,
            siblings=catalog,
        )

    dossiers = []
    for row in catalog:
        record_id = str(row.get("record_id") or "")
        loaded = store.load(record_id, include_blobs=True) if record_id else None
        if loaded:
            dossiers.append(loaded)

    if len(dossiers) < MIN_SIBLINGS:
        return _empty(reason="Sibling records could not be loaded.", focus_id=focus_id, siblings=catalog)

    patterns = [
        *_import_patterns(dossiers),
        *_wrapper_patterns(dossiers),
        *_region_patterns(dossiers),
        *_tag_patterns(dossiers),
    ]
    kind_rank = {"wrapper": 0, "import": 1, "region": 2, "tag": 3}
    patterns.sort(
        key=lambda item: (
            kind_rank.get(str(item.get("kind")), 9),
            -item["support"],
            -item["confidence"],
            item["title"],
        )
    )
    patterns = patterns[:limit]
    note = _lab_note(dossiers, patterns)
    return {
        "schema_version": INSIGHTS_SCHEMA_VERSION,
        "ready": True,
        "reason": None,
        "focus_id": focus_id,
        "sibling_count": len(dossiers),
        "siblings": [_sibling_ref(item) for item in dossiers],
        "patterns": patterns,
        "lab_note": note,
        "skill_ready": False,
        "skill_hint": (
            "Do not promote this to a Grok skill until a pattern has held on a third binary "
            "and the next action is a concrete command, not a summary."
        ),
    }


def save_lab_note(store: AnalysisRecordStore, insights: dict[str, Any]) -> Path:
    directory = store.root / "insights"
    directory.mkdir(parents=True, exist_ok=True)
    stamp = utcnow().replace(":", "").replace("+00:00", "Z")
    path = directory / f"lab-note-{stamp}.md"
    path.write_text(str(insights.get("lab_note") or ""), encoding="utf-8")
    return path


def _siblings(catalog: list[dict[str, Any]], focus: dict[str, Any]) -> list[dict[str, Any]]:
    focus_tags = _strong_tags(focus.get("tags") or [])
    focus_id = focus.get("record_id")
    siblings = []
    for row in catalog:
        if row.get("record_id") == focus_id:
            siblings.append(row)
            continue
        if focus_tags & _strong_tags(row.get("tags") or []):
            siblings.append(row)
    if focus_id and not any(row.get("record_id") == focus_id for row in siblings):
        siblings.insert(0, focus)
    return siblings


def _import_patterns(dossiers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    owners: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for dossier in dossiers:
        names = _import_names(dossier)
        for name in names:
            counts[name] += 1
            owners[name].append(_sibling_ref(dossier))
    patterns = []
    total = len(dossiers)
    for name, support in counts.most_common(12):
        if support < MIN_SIBLINGS:
            continue
        patterns.append(
            _pattern(
                kind="import",
                title=f"`{name}` imported in {support}/{total} siblings",
                why="Shared libc/PLT surface is the cheapest xref to reuse on the next binary.",
                support=support,
                total=total,
                evidence=owners[name],
                next_action=f"r2: `ii~{name}` then `axt @ sym.imp.{name}` before reading random functions.",
            )
        )
    return patterns


def _wrapper_patterns(dossiers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    owners: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for dossier in dossiers:
        firmware = _dict(_dict(dossier.get("tool_blobs")).get("firmware"))
        kind = firmware.get("top_level_format") or firmware.get("container_type")
        if not kind:
            subject = _dict(dossier.get("subject_blob"))
            kind = subject.get("firmware_kind") or subject.get("format")
        if not kind:
            continue
        key = str(kind)
        counts[key] += 1
        owners[key].append(_sibling_ref(dossier))
    patterns = []
    total = len(dossiers)
    for kind, support in counts.most_common(6):
        if support < MIN_SIBLINGS:
            continue
        patterns.append(
            _pattern(
                kind="wrapper",
                title=f"Same container `{kind}` in {support}/{total} images",
                why="Wrapper family decides the carve order. Do not send this blob to Ghidra.",
                support=support,
                total=total,
                evidence=owners[kind],
                next_action="Unpack with /unpack-firmware, then brief the carved httpd/tdpServer — not the .bin.",
            )
        )
    return patterns


def _region_patterns(dossiers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    owners: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for dossier in dossiers:
        titles = set()
        for region in dossier.get("region_blobs") or []:
            if not isinstance(region, dict):
                continue
            title = str(region.get("title") or "").strip()
            if title:
                titles.add(title)
        for title in titles:
            counts[title] += 1
            owners[title].append(_sibling_ref(dossier))
    patterns = []
    total = len(dossiers)
    for title, support in counts.most_common(8):
        if support < MIN_SIBLINGS:
            continue
        if title.lower().startswith("characterize "):
            continue
        patterns.append(
            _pattern(
                kind="region",
                title=f"Region `{title}` ranked in {support}/{total} siblings",
                why="If the same region keeps winning the briefing, start there on the next sample.",
                support=support,
                total=total,
                evidence=owners[title],
                next_action="Open that region first and send its 4-bullet ask, not a whole-binary question.",
            )
        )
    return patterns


def _tag_patterns(dossiers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    owners: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for dossier in dossiers:
        for tag in _strong_tags(dossier.get("tags") or []):
            counts[tag] += 1
            owners[tag].append(_sibling_ref(dossier))
    patterns = []
    total = len(dossiers)
    for tag, support in counts.most_common(8):
        if support < MIN_SIBLINGS:
            continue
        patterns.append(
            _pattern(
                kind="tag",
                title=f"Tag `{tag}` shared by {support}/{total} records",
                why="Use this tag to pull the sibling set next time (`r2d2 insights --tag`).",
                support=support,
                total=total,
                evidence=owners[tag],
                next_action=f"r2d2 records list --tag {tag}",
            )
        )
    return patterns


def _import_names(dossier: dict[str, Any]) -> set[str]:
    r2 = _dict(_dict(dossier.get("tool_blobs")).get("radare2"))
    names: set[str] = set()
    for item in r2.get("imports") or []:
        raw = item.get("name") if isinstance(item, dict) else item
        name = str(raw or "")
        name = name.split("@", 1)[0]
        name = name.removeprefix("sym.imp.").removeprefix("imp.").removeprefix("sym.")
        if name:
            names.add(name)
    return names


def _pattern(
    *,
    kind: str,
    title: str,
    why: str,
    support: int,
    total: int,
    evidence: list[dict[str, Any]],
    next_action: str,
) -> dict[str, Any]:
    return {
        "id": f"{kind}:{title[:48]}",
        "kind": kind,
        "title": title,
        "why": why,
        "support": support,
        "total": total,
        "confidence": round(support / max(total, 1), 2),
        "evidence": evidence,
        "next_action": next_action,
    }


def _lab_note(dossiers: list[dict[str, Any]], patterns: list[dict[str, Any]]) -> str:
    names = ", ".join(_label(item) for item in dossiers[:8])
    lines = [
        "# Lab note (not a skill)",
        "",
        f"Distilled from {len(dossiers)} records: {names}",
        "",
        "These are recurring facts. Promote to a skill only after a third confirming sample.",
        "",
    ]
    if not patterns:
        lines.append("No pattern met the two-record bar.")
        return "\n".join(lines) + "\n"
    for index, pattern in enumerate(patterns, start=1):
        lines.append(f"{index}. **{pattern['title']}**")
        lines.append(f"   Why: {pattern['why']}")
        lines.append(f"   Next: `{pattern['next_action']}`")
        lines.append("")
    return "\n".join(lines)


def _empty(
    *,
    reason: str,
    focus_id: str | None,
    siblings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    refs = [_sibling_ref(item) for item in (siblings or [])]
    return {
        "schema_version": INSIGHTS_SCHEMA_VERSION,
        "ready": False,
        "reason": reason,
        "focus_id": focus_id,
        "sibling_count": len(refs),
        "siblings": refs,
        "patterns": [],
        "lab_note": "",
        "skill_ready": False,
        "skill_hint": "Analyze two related binaries first. Skills need a third confirming sample.",
    }


def _sibling_ref(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_id": item.get("record_id"),
        "name": _label(item),
        "tags": list(item.get("tags") or [])[:8],
    }


def _label(item: dict[str, Any]) -> str:
    names = item.get("names") or []
    if names:
        return str(names[0])
    subject = item.get("subject_blob") if isinstance(item.get("subject_blob"), dict) else {}
    return str(subject.get("name") or item.get("record_id") or "binary")


def _strong_tags(tags: list[Any]) -> set[str]:
    strong: set[str] = set()
    for tag in tags:
        text = str(tag).strip().lower()
        if not text or text in _WEAK_TAGS:
            continue
        strong.add(text)
    return strong


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


__all__ = ["INSIGHTS_SCHEMA_VERSION", "extract_insights", "save_lab_note"]
