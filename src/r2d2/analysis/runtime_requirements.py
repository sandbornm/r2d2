"""Runtime requirements extraction for ELF binaries."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def get_runtime_requirements(binary: Path) -> dict[str, Any]:
    try:  # Optional dependency
        from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]
    except ModuleNotFoundError as exc:
        return {"error": f"pyelftools not installed: {exc}"}

    try:
        with binary.open("rb") as handle:
            elf = ELFFile(handle)
            header = elf.header

            sections: list[dict[str, Any]] = []
            segments: list[dict[str, Any]] = []
            interp = None
            needed: list[str] = []

            for segment in elf.iter_segments():
                if segment.header.p_type == "PT_INTERP":
                    data = segment.data()
                    interp = data.decode("utf-8", errors="replace").strip("\x00")
                segments.append({
                    "type": str(segment.header.p_type),
                    "flags": str(segment.header.p_flags),
                    "vaddr": hex(segment.header.p_vaddr),
                    "memsz": int(segment.header.p_memsz),
                    "filesz": int(segment.header.p_filesz),
                })

            for section in elf.iter_sections():
                if section.header.sh_type == "SHT_DYNAMIC":
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            needed.append(str(tag.needed))
                name = section.name
                size = int(section.header.sh_size)
                entropy = None
                if size > 0:
                    try:
                        data = section.data()[: min(size, 1024 * 1024)]
                        entropy = round(_shannon_entropy(data), 2)
                    except Exception:
                        entropy = None
                sections.append({
                    "name": name,
                    "type": str(section.header.sh_type),
                    "size": size,
                    "entropy": entropy,
                })

            upx_sections = [s for s in sections if s["name"].lower().startswith(".upx")]
            high_entropy = [
                s for s in sections
                if s["entropy"] is not None and s["entropy"] >= 7.2 and s["size"] > 4096
            ]
            rwx_segments = [
                s for s in segments if "R" in s["flags"] and "W" in s["flags"] and "X" in s["flags"]
            ]

            packer_matches: list[str] = []
            if upx_sections:
                packer_matches.append("UPX")
            if high_entropy:
                packer_matches.append("High entropy sections")
            if rwx_segments:
                packer_matches.append("RWX segment")

            packer = {
                "detected": len(packer_matches) > 0,
                "matches": packer_matches,
                "upx_sections": upx_sections,
                "high_entropy_sections": high_entropy,
                "rwx_segments": rwx_segments,
            }

            return {
                "runtime": {
                    "format": "ELF",
                    "arch": str(header.get("e_machine", "unknown")),
                    "bits": int(elf.elfclass),
                    "endianness": "little" if elf.little_endian else "big",
                    "osabi": str(header.get("e_ident", {}).get("EI_OSABI", "unknown")),
                    "abi_version": str(header.get("e_ident", {}).get("EI_ABIVERSION", "unknown")),
                    "entrypoint": hex(header.get("e_entry", 0)),
                    "interp": interp,
                    "needed": needed,
                },
                "readelf": {
                    "header": {
                        "type": str(header.get("e_type", "unknown")),
                        "machine": str(header.get("e_machine", "unknown")),
                        "entrypoint": hex(header.get("e_entry", 0)),
                    },
                    "sections": sections,
                    "segments": segments,
                },
                "packer": packer,
            }
    except Exception as exc:  # pragma: no cover - best effort
        return {"error": f"runtime requirements failed: {exc}"}
