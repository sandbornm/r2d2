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
_ELF_SUBJECT_CLASSES = frozenset({"linux_elf", "baremetal_elf"})
_CONTAINER_SUBJECT_CLASSES = frozenset({"firmware_container", "uimage"})
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
    "firmware",
    "string",
    "elf",
    "elf_binary",
}
_WEAK_REGION_TITLES = {
    "crypto strings",
    "network strings",
    "credential strings",
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

    groups = _family_groups(dossiers)
    family_summaries = [_family_summary(key, members) for key, members in groups.items()]
    chosen_key, chosen = _pick_family(groups, focus_id=focus_id)
    if chosen is None or len(chosen) < MIN_SIBLINGS:
        return _empty(
            reason=(
                "Need at least two records in the same subject class "
                "(and wrapper family, for containers). "
                + _family_hint(family_summaries)
            ),
            focus_id=focus_id,
            siblings=catalog,
            families=family_summaries,
        )

    subject_class, family_id = chosen_key
    patterns = _patterns_for_family(chosen, subject_class, family_id, limit=limit)
    note = _lab_note(chosen, patterns, subject_class=subject_class, family_id=family_id)
    return {
        "schema_version": INSIGHTS_SCHEMA_VERSION,
        "ready": True,
        "reason": None,
        "focus_id": focus_id,
        "family": {"subject_class": subject_class, "id": family_id, "sibling_count": len(chosen)},
        "families": family_summaries,
        "sibling_count": len(chosen),
        "siblings": [_sibling_ref(item) for item in chosen],
        "patterns": patterns,
        "lab_note": note,
        "skill_ready": False,
        "skill_hint": (
            "Do not promote this to a Grok skill until a pattern has held on a third binary "
            "in the same family and the next action is a concrete command, not a summary."
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
        family = _dossier_family(dossier)
        if not family:
            continue
        counts[family] += 1
        owners[family].append(_sibling_ref(dossier))
    patterns = []
    total = len(dossiers)
    for family, support in counts.most_common(6):
        if support < MIN_SIBLINGS:
            continue
        patterns.append(
            _pattern(
                kind="wrapper",
                title=f"Same wrapper family `{family}` in {support}/{total} images",
                why="Wrapper family decides the carve order. Do not send this blob to Ghidra.",
                support=support,
                total=total,
                evidence=owners[family],
                next_action="r2d2 brief a carved child ELF (httpd/tdpServer), not the wrapper .bin.",
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
        if title.lower() in _WEAK_REGION_TITLES:
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


def _lab_note(
    dossiers: list[dict[str, Any]],
    patterns: list[dict[str, Any]],
    *,
    subject_class: str = "",
    family_id: str = "",
) -> str:
    names = ", ".join(_label(item) for item in dossiers[:8])
    family = f"{subject_class}/{family_id}".strip("/") if subject_class or family_id else "mixed"
    lines = [
        "# Lab note (not a skill)",
        "",
        f"Family `{family}` from {len(dossiers)} records: {names}",
        "",
        "These are recurring facts. Promote to a skill only after a third confirming sample in this family.",
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
    families: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    refs = [_sibling_ref(item) for item in (siblings or [])]
    return {
        "schema_version": INSIGHTS_SCHEMA_VERSION,
        "ready": False,
        "reason": reason,
        "focus_id": focus_id,
        "family": None,
        "families": families or [],
        "sibling_count": len(refs),
        "siblings": refs,
        "patterns": [],
        "lab_note": "",
        "skill_ready": False,
        "skill_hint": "Analyze two related binaries first. Skills need a third confirming sample.",
    }


def _sibling_ref(item: dict[str, Any]) -> dict[str, Any]:
    cls, family = _family_key(item)
    return {
        "record_id": item.get("record_id"),
        "name": _label(item),
        "tags": list(item.get("tags") or [])[:8],
        "subject_class": cls,
        "family": family,
    }


def _patterns_for_family(
    dossiers: list[dict[str, Any]],
    subject_class: str,
    family_id: str,
    *,
    limit: int,
) -> list[dict[str, Any]]:
    if subject_class in _ELF_SUBJECT_CLASSES:
        patterns = [
            *_import_patterns(dossiers),
            *_region_patterns(dossiers),
            *_tag_patterns(dossiers),
        ]
        kind_rank = {"import": 0, "region": 1, "tag": 2}
    elif subject_class == "firmware_container":
        patterns = [
            *_wrapper_patterns(dossiers),
            *_region_patterns(dossiers),
            *_tag_patterns(dossiers),
        ]
        kind_rank = {"wrapper": 0, "region": 1, "tag": 2}
    else:
        patterns = [*_region_patterns(dossiers), *_tag_patterns(dossiers)]
        kind_rank = {"region": 0, "tag": 1}
    if not any(item.get("kind") == "wrapper" for item in patterns) and subject_class == "firmware_container":
        patterns.insert(
            0,
            _pattern(
                kind="wrapper",
                title=f"Wrapper family `{family_id}` ({len(dossiers)} images)",
                why="Same vendor wrapper. Arrive at a child ELF before asking about functions.",
                support=len(dossiers),
                total=len(dossiers),
                evidence=[_sibling_ref(item) for item in dossiers],
                next_action="r2d2 brief a carved child ELF (httpd/tdpServer), not the wrapper .bin.",
            ),
        )
    if subject_class == "uimage":
        patterns.insert(
            0,
            _pattern(
                kind="wrapper",
                title=f"uImage family ({len(dossiers)} images)",
                why="This is a boot header, not userspace. Extract the payload next.",
                support=len(dossiers),
                total=len(dossiers),
                evidence=[_sibling_ref(item) for item in dossiers],
                next_action="Extract the uImage payload; do not treat this header as httpd.",
            ),
        )
    patterns.sort(
        key=lambda item: (
            kind_rank.get(str(item.get("kind")), 9),
            -item["support"],
            -item["confidence"],
            item["title"],
        )
    )
    return patterns[:limit]


def _family_groups(dossiers: list[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for dossier in dossiers:
        groups[_family_key(dossier)].append(dossier)
    return groups


def _pick_family(
    groups: dict[tuple[str, str], list[dict[str, Any]]],
    *,
    focus_id: str | None,
) -> tuple[tuple[str, str], list[dict[str, Any]] | None]:
    if focus_id:
        for key, members in groups.items():
            if any(str(item.get("record_id")) == focus_id for item in members):
                return key, members
    ranked = sorted(
        groups.items(),
        key=lambda item: (-len(item[1]), item[0][0], item[0][1]),
    )
    if not ranked:
        return ("unknown", "unknown"), None
    return ranked[0]


def _family_summary(key: tuple[str, str], members: list[dict[str, Any]]) -> dict[str, Any]:
    subject_class, family_id = key
    return {
        "subject_class": subject_class,
        "id": family_id,
        "count": len(members),
        "names": [_label(item) for item in members[:8]],
    }


def _family_hint(summaries: list[dict[str, Any]]) -> str:
    if not summaries:
        return ""
    parts = [f"{item['subject_class']}/{item['id']} ({item['count']})" for item in summaries]
    return "Seen: " + ", ".join(parts) + "."


def _family_key(item: dict[str, Any]) -> tuple[str, str]:
    subject_class = _dossier_class(item)
    if subject_class == "firmware_container":
        return subject_class, _dossier_family(item) or "container"
    if subject_class == "uimage":
        return subject_class, "uimage"
    if subject_class in _ELF_SUBJECT_CLASSES:
        return subject_class, subject_class
    return subject_class or "unknown", "unknown"


def _dossier_class(item: dict[str, Any]) -> str:
    briefing = _dict(_dict(item.get("briefing_blob")).get("subject"))
    if briefing.get("subject_class"):
        return str(briefing["subject_class"])
    subject = _dict(item.get("subject_blob"))
    if subject.get("subject_class"):
        return str(subject["subject_class"])
    firmware = _dict(_dict(item.get("tool_blobs")).get("firmware"))
    if firmware.get("is_elf") or str(firmware.get("top_level_format") or "").lower() == "elf":
        bits = firmware.get("bits") or _dict(subject).get("bits")
        try:
            bits_n = int(bits) if bits is not None else None
        except (TypeError, ValueError):
            bits_n = None
        if bits_n == 16:
            return "baremetal_elf"
        return "linux_elf"
    top = str(firmware.get("top_level_format") or subject.get("format") or "").lower()
    if top == "uimage":
        return "uimage"
    if "firmware" in top or "container" in top or firmware.get("wrapper_family"):
        return "firmware_container"
    tags = {str(tag).lower() for tag in (item.get("tags") or [])}
    for cls in ("baremetal_elf", "linux_elf", "firmware_container", "uimage"):
        if cls in tags:
            return cls
    return "unknown"


def _dossier_family(item: dict[str, Any]) -> str | None:
    briefing = _dict(_dict(item.get("briefing_blob")).get("subject"))
    if briefing.get("wrapper_family"):
        return str(briefing["wrapper_family"])
    subject = _dict(item.get("subject_blob"))
    if subject.get("wrapper_family"):
        return str(subject["wrapper_family"])
    firmware = _dict(_dict(item.get("tool_blobs")).get("firmware"))
    if firmware.get("wrapper_family"):
        return str(firmware["wrapper_family"])
    tags = {str(tag).lower() for tag in (item.get("tags") or [])}
    for name in ("safeloader", "img0", "cloud", "ver20"):
        if name in tags:
            return name
    return None


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
