"""Read-only Unix sniff of a sample.

file(1), strings(1), readelf(1), and a hex peek. These do not need a
container: they never execute the guest. A later qemu-user jail is for
*running* httpd, not for this intake.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Any

_MAX_STRINGS = 48
_MAX_READELF_LINES = 64
_HEX_BYTES = 256
_INTERESTING = (
    "http",
    "cgi",
    "nvram",
    "login",
    "passwd",
    "upgrade",
    "tdp",
    "tmpServer",
    "system(",
    "popen",
    "execl",
    "sprintf",
    "admin",
    "/tmp",
    "fw-type",
    "fwup-ptn",
    "squash",
    "hsqs",
)


def sniff_binary(path: Path) -> dict[str, Any]:
    target = Path(path)
    payload: dict[str, Any] = {
        "mode": "sniff",
        "path": str(target),
        "size_bytes": target.stat().st_size if target.is_file() else None,
        "sha256": _sha256(target) if target.is_file() else None,
        "file": _run(["file", "-b", str(target)]),
        "hex_head": _hex_head(target),
        "strings": _interesting_strings(target),
        "readelf": None,
        "tools": {
            "file": bool(shutil.which("file")),
            "strings": bool(shutil.which("strings")),
            "readelf": bool(shutil.which("readelf")),
        },
    }
    file_text = str(payload.get("file") or "")
    if "ELF" in file_text and shutil.which("readelf"):
        payload["readelf"] = _run(
            ["readelf", "-h", "-d", "-l", str(target)],
            max_lines=_MAX_READELF_LINES,
        )
    return payload


def render_intake(analysis: dict[str, Any]) -> str:
    """Compact triage card injected into the LLM system prompt."""
    quick = analysis.get("quick_scan") if isinstance(analysis.get("quick_scan"), dict) else {}
    sniff = quick.get("sniff") if isinstance(quick.get("sniff"), dict) else {}
    firmware = quick.get("firmware") if isinstance(quick.get("firmware"), dict) else {}
    briefing = analysis.get("briefing") if isinstance(analysis.get("briefing"), dict) else {}
    subject = briefing.get("subject") if isinstance(briefing.get("subject"), dict) else {}
    lines = ["## Triage intake"]
    if sniff.get("file"):
        lines.append(f"file(1): {sniff['file']}")
    if subject.get("format") or firmware.get("top_level_format"):
        lines.append(
            f"container: {subject.get('format') or firmware.get('top_level_format')} "
            f"{subject.get('arch') or ''}".strip()
        )
    if subject.get("dangerous_imports"):
        lines.append("sinks: " + ", ".join(str(item) for item in subject["dangerous_imports"][:8]))
    strings = sniff.get("strings") if isinstance(sniff.get("strings"), list) else []
    if strings:
        preview = ", ".join(str(item.get("value") if isinstance(item, dict) else item)[:40] for item in strings[:8])
        lines.append(f"strings: {preview}")
    if briefing.get("inferred_goal"):
        source = briefing.get("goal_source") or "inferred"
        lines.append(f"thesis ({source}): {briefing['inferred_goal']}")
    if briefing.get("summary"):
        lines.append(f"briefing: {briefing['summary']}")
    issues = analysis.get("issues") or []
    if issues:
        lines.append("issues: " + "; ".join(str(item) for item in issues[:4]))
    return "\n".join(lines)


def _interesting_strings(path: Path) -> list[dict[str, Any]]:
    if not shutil.which("strings"):
        return []
    raw = _run(["strings", "-n", "6", str(path)], max_lines=4000)
    if not raw:
        return []
    ranked: list[tuple[int, str]] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        text = line.strip()
        if 6 <= len(text) <= 96 and text not in seen:
            seen.add(text)
            score = sum(4 for needle in _INTERESTING if needle.lower() in text.lower())
            ranked.append((score, text))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    interesting = [text for score, text in ranked if score > 0][:_MAX_STRINGS]
    return [{"value": text} for text in interesting]


def _hex_head(path: Path) -> str:
    try:
        data = path.read_bytes()[:_HEX_BYTES]
    except OSError:
        return ""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{offset:08x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


def _run(command: list[str], *, max_lines: int | None = None) -> str:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    text = (completed.stdout or completed.stderr or "").strip()
    if max_lines is not None:
        text = "\n".join(text.splitlines()[:max_lines])
    return text[:8000]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


__all__ = ["render_intake", "sniff_binary"]
