"""Lightweight firmware container inventory.

This adapter is intentionally dependency-free for the common path. It turns a
generic firmware blob into a small inventory of embedded components that can be
used as targets for later Ghidra/angr/radare2 passes.
"""

from __future__ import annotations

import hashlib
import math
import re
import shutil
import struct
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_MIB = 1024 * 1024
_MAX_SIGNAL_STRINGS = 20
_MAX_TOP_STRING_SIGNALS = 36
_MAX_ENTROPY_WINDOWS = 512
_ENTROPY_WINDOW_SIZE = 64 * 1024
_HIGH_ENTROPY_THRESHOLD = 7.2


@dataclass(frozen=True, slots=True)
class _StringRule:
    category: str
    label: str
    pattern: re.Pattern[str]
    confidence: float


@dataclass(frozen=True, slots=True)
class _Signature:
    name: str
    kind: str
    pattern: bytes
    description: str
    confidence: float = 0.75
    recommended: bool = False


_SIGNATURES: tuple[_Signature, ...] = (
    _Signature("ELF", "elf_binary", b"\x7fELF", "Embedded ELF executable/shared object", 0.95, True),
    _Signature("FIT/DTB", "device_tree", b"\xd0\r\xfe\xed", "Flattened device tree or FIT image", 0.9, True),
    _Signature("uImage", "uimage", b"\x27\x05\x19\x56", "U-Boot legacy uImage", 0.9, True),
    _Signature("SquashFS LE", "squashfs_filesystem", b"hsqs", "SquashFS filesystem", 0.9, True),
    _Signature("SquashFS BE", "squashfs_filesystem", b"sqsh", "SquashFS filesystem", 0.85, True),
    _Signature("CramFS", "cramfs_filesystem", b"\x45\x3d\xcd\x28", "CramFS filesystem", 0.85, True),
    _Signature("UBI", "ubi_volume", b"UBI#", "UBI flash volume", 0.85, True),
    _Signature("JFFS2 LE", "jffs2_marker", b"\x85\x19", "JFFS2 erase block marker", 0.65, True),
    _Signature("JFFS2 BE", "jffs2_marker", b"\x19\x85", "JFFS2 erase block marker", 0.65, True),
    _Signature("gzip", "compressed_stream", b"\x1f\x8b\x08", "gzip compressed stream", 0.8, True),
    _Signature("xz", "compressed_stream", b"\xfd7zXZ\x00", "xz compressed stream", 0.85, True),
    _Signature("zstd", "compressed_stream", b"\x28\xb5\x2f\xfd", "Zstandard compressed stream", 0.85, True),
    _Signature("lz4", "compressed_stream", b"\x04\x22\x4d\x18", "LZ4 compressed stream", 0.75, True),
    _Signature("ZIP", "archive", b"PK\x03\x04", "ZIP archive", 0.8, True),
    _Signature("PEM certificate", "credential_material", b"-----BEGIN CERTIFICATE-----", "PEM certificate", 0.9),
    _Signature("PEM private key", "credential_material", b"-----BEGIN", "PEM key/certificate material", 0.7),
    _Signature("OpenWrt", "firmware_marker", b"OpenWrt", "OpenWrt marker string", 0.8),
    _Signature("TP-Link", "vendor_marker", b"TP-LINK", "TP-Link vendor marker", 0.8),
)


_STRING_RULES: tuple[_StringRule, ...] = (
    _StringRule(
        "credential",
        "Credential or default-login material",
        re.compile(r"password|passwd|pwd=|credential|secret|token|admin|root|login|auth"),
        0.82,
    ),
    _StringRule(
        "credential",
        "Private key material",
        re.compile(r"-----begin [a-z0-9 ]*private key-----|/etc/shadow|/etc/passwd"),
        0.95,
    ),
    _StringRule(
        "network",
        "Network endpoint or protocol",
        re.compile(r"https?://|ftp://|tftp|telnet|dropbear|ssh|upnp|dnsmasq|socket|connect"),
        0.78,
    ),
    _StringRule(
        "network",
        "IPv4 address",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        0.72,
    ),
    _StringRule(
        "service",
        "Exposed service daemon",
        re.compile(r"telnetd|sshd|httpd|uhttpd|lighttpd|boa|busybox|smbd|ftpd|dropbear"),
        0.8,
    ),
    _StringRule(
        "crypto",
        "Crypto or certificate handling",
        re.compile(r"openssl|mbedtls|wolfssl|ssl|tls|x509|certificate|cert|aes|rsa|sha\d*|md5"),
        0.72,
    ),
    _StringRule(
        "filesystem",
        "Firmware filesystem path",
        re.compile(r"/etc/|/bin/|/sbin/|/usr/|/var/|/tmp/|init\.d|rc\.d|mtd|nvram|uci"),
        0.76,
    ),
    _StringRule(
        "update",
        "Firmware update or boot path",
        re.compile(r"firmware|upgrade|update|flash|bootloader|u-boot|kernel|squashfs|ubi|mtdblock"),
        0.74,
    ),
    _StringRule(
        "dangerous_api",
        "Dangerous API or command primitive",
        re.compile(r"\bsystem\b|\bexec\b|popen|strcpy|sprintf|memcpy|wget|curl|chmod|chown"),
        0.76,
    ),
)


@dataclass(slots=True)
class FirmwareAdapter:
    """Detect embedded firmware components without requiring extraction tools."""

    name: str = "firmware"
    artifacts_dir: Path | None = None
    max_scan_bytes: int = 256 * _MIB
    max_carve_bytes: int = 64 * _MIB
    max_hits_per_signature: int = 40
    binwalk_timeout: int = 45
    run_binwalk: bool = True

    def is_available(self) -> bool:
        return True

    def quick_scan(self, binary: Path, **kwargs: Any) -> dict[str, Any]:
        if not binary.exists():
            return {"error": f"Binary not found: {binary}"}

        size_bytes = binary.stat().st_size
        data = self._read_prefix(binary)
        artifacts = self._scan_signatures(data)
        string_signals = self._scan_string_signals(data)
        entropy = self._entropy_profile(data)
        binwalk_available = shutil.which("binwalk") is not None
        binwalk_used = False

        if self.run_binwalk and binwalk_available and not artifacts:
            binwalk_used = True
            artifacts.extend(self._scan_binwalk(binary))

        artifacts = self._dedupe_artifacts(artifacts)
        top_level_format = self._classify_top_level(data, artifacts)
        recommended_targets = [
            artifact
            for artifact in artifacts
            if artifact.get("recommended") and int(artifact.get("offset", -1)) > 0
        ][:25]
        for artifact in artifacts:
            artifact.update(self._analysis_routing(artifact))
        carved_targets = self._carve_targets(binary, artifacts, recommended_targets, size_bytes)
        fanout_tasks = self._build_fanout_tasks(carved_targets or recommended_targets)

        return {
            "mode": "firmware_inventory",
            "size_bytes": size_bytes,
            "sha256": self._sha256(binary),
            "is_elf": data.startswith(b"\x7fELF"),
            "top_level_format": top_level_format,
            "container_type": self._classify_container(top_level_format, artifacts),
            "scan": {
                "bytes_scanned": len(data),
                "truncated": size_bytes > len(data),
                "binwalk_available": binwalk_available,
                "binwalk_used": binwalk_used,
                "signature_count": len(artifacts),
            },
            "embedded_artifacts": artifacts[:500],
            "recommended_targets": recommended_targets,
            "carved_targets": carved_targets,
            "fanout_tasks": fanout_tasks,
            "string_signals": string_signals,
            "entropy": entropy,
            "extraction": {
                "enabled": True,
                "output_dir": str(self._output_dir(binary)),
                "carved_count": len(carved_targets),
                "max_carve_bytes": self.max_carve_bytes,
                "strategy": "bounded signature carving; use binwalk/unsquashfs for full filesystem extraction",
            },
            "notes": self._notes(
                size_bytes,
                data,
                artifacts,
                string_signals,
                entropy,
                binwalk_available,
                binwalk_used,
            ),
        }

    def deep_scan(self, binary: Path, *, resource_tree: Any | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.quick_scan(binary, **kwargs)

    def _read_prefix(self, binary: Path) -> bytes:
        with binary.open("rb") as handle:
            return handle.read(self.max_scan_bytes)

    def _scan_signatures(self, data: bytes) -> list[dict[str, Any]]:
        artifacts: list[dict[str, Any]] = []
        for signature in _SIGNATURES:
            start = 0
            hits = 0
            while hits < self.max_hits_per_signature:
                offset = data.find(signature.pattern, start)
                if offset < 0:
                    break
                artifact = {
                    "offset": offset,
                    "offset_hex": f"0x{offset:x}",
                    "kind": signature.kind,
                    "name": signature.name,
                    "description": signature.description,
                    "source": "signature",
                    "confidence": signature.confidence,
                    "recommended": signature.recommended,
                }
                artifact.update(self._parse_signature_metadata(signature, data, offset))
                artifacts.append(artifact)
                hits += 1
                start = offset + max(1, len(signature.pattern))
        return sorted(artifacts, key=lambda item: (int(item["offset"]), str(item["kind"])))

    def _scan_string_signals(self, data: bytes) -> dict[str, Any]:
        categories: dict[str, list[dict[str, Any]]] = {
            rule.category: [] for rule in _STRING_RULES
        }
        category_counts: dict[str, int] = {category: 0 for category in categories}
        seen_values: dict[str, set[str]] = {category: set() for category in categories}
        total_strings = 0

        for offset, value in self._iter_ascii_strings(data):
            total_strings += 1
            lower = value.lower()
            for rule in _STRING_RULES:
                if not rule.pattern.search(lower):
                    continue
                if value in seen_values[rule.category]:
                    continue
                seen_values[rule.category].add(value)
                category_counts[rule.category] += 1
                if len(categories[rule.category]) >= _MAX_SIGNAL_STRINGS:
                    continue
                categories[rule.category].append(
                    {
                        "category": rule.category,
                        "label": rule.label,
                        "value": value[:240],
                        "offset": offset,
                        "offset_hex": f"0x{offset:x}",
                        "confidence": rule.confidence,
                    }
                )

        populated_categories = {
            category: hits for category, hits in categories.items() if hits
        }
        populated_counts = {
            category: count for category, count in category_counts.items() if count
        }
        top_signals = sorted(
            (hit for hits in populated_categories.values() for hit in hits),
            key=lambda item: (
                -float(item.get("confidence", 0.0)),
                int(item.get("offset", 0)),
                str(item.get("value", "")),
            ),
        )[:_MAX_TOP_STRING_SIGNALS]
        return {
            "total_strings": total_strings,
            "matched_count": sum(populated_counts.values()),
            "category_counts": populated_counts,
            "categories": populated_categories,
            "top_signals": top_signals,
            "string_min_length": 4,
        }

    def _iter_ascii_strings(self, data: bytes) -> Iterator[tuple[int, str]]:
        start: int | None = None
        current = bytearray()

        def pop_string() -> tuple[int, str] | None:
            nonlocal start, current
            if start is not None and len(current) >= 4:
                item = (start, current.decode("utf-8", errors="replace"))
            else:
                item = None
            start = None
            current = bytearray()
            return item

        for index, byte in enumerate(data):
            if 32 <= byte <= 126 or byte in {9}:
                if start is None:
                    start = index
                current.append(byte)
                continue
            item = pop_string()
            if item is not None:
                yield item
        item = pop_string()
        if item is not None:
            yield item

    def _entropy_profile(self, data: bytes) -> dict[str, Any]:
        if not data:
            return {
                "window_size": _ENTROPY_WINDOW_SIZE,
                "sampled_windows": 0,
                "average": 0.0,
                "max": 0.0,
                "high_entropy_windows": [],
            }

        step = max(_ENTROPY_WINDOW_SIZE, math.ceil(len(data) / _MAX_ENTROPY_WINDOWS))
        windows: list[dict[str, Any]] = []
        total_entropy = 0.0
        max_entropy = 0.0
        sampled = 0

        for offset in range(0, len(data), step):
            window = data[offset : offset + _ENTROPY_WINDOW_SIZE]
            if not window:
                continue
            entropy = self._shannon_entropy(window)
            sampled += 1
            total_entropy += entropy
            max_entropy = max(max_entropy, entropy)
            if entropy >= _HIGH_ENTROPY_THRESHOLD:
                windows.append(
                    {
                        "offset": offset,
                        "offset_hex": f"0x{offset:x}",
                        "entropy": round(entropy, 3),
                        "size": len(window),
                    }
                )

        high_entropy_windows = sorted(
            windows,
            key=lambda item: (-float(item["entropy"]), int(item["offset"])),
        )[:12]
        return {
            "window_size": _ENTROPY_WINDOW_SIZE,
            "sampled_windows": sampled,
            "average": round(total_entropy / sampled, 3) if sampled else 0.0,
            "max": round(max_entropy, 3),
            "high_entropy_windows": high_entropy_windows,
            "high_entropy_threshold": _HIGH_ENTROPY_THRESHOLD,
        }

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        total = len(data)
        entropy = 0.0
        for count in counts:
            if not count:
                continue
            probability = count / total
            entropy -= probability * math.log2(probability)
        return entropy

    def _parse_signature_metadata(self, signature: _Signature, data: bytes, offset: int) -> dict[str, Any]:
        if signature.kind == "device_tree":
            metadata = self._parse_fdt_header(data, offset)
            window = data[offset : offset + min(4096, len(data) - offset)]
            if b"FIT" in window or b"OpenWrt" in window or b"kernel" in window:
                metadata["kind_hint"] = "fit_image"
                metadata["description_hint"] = "FIT image or OpenWrt device tree container"
            return metadata
        if signature.kind == "uimage":
            return self._parse_uimage_header(data, offset)
        return {}

    def _parse_fdt_header(self, data: bytes, offset: int) -> dict[str, Any]:
        if offset + 40 > len(data):
            return {}
        try:
            (
                magic,
                total_size,
                off_dt_struct,
                off_dt_strings,
                off_mem_rsvmap,
                version,
                last_comp_version,
                boot_cpuid_phys,
                size_dt_strings,
                size_dt_struct,
            ) = struct.unpack_from(">10I", data, offset)
        except struct.error:
            return {}
        if magic != 0xD00DFEED:
            return {}
        return {
            "declared_size": total_size,
            "fdt_version": version,
            "last_compatible_version": last_comp_version,
            "struct_offset": off_dt_struct,
            "strings_offset": off_dt_strings,
            "memory_reserve_offset": off_mem_rsvmap,
            "boot_cpuid_phys": boot_cpuid_phys,
            "strings_size": size_dt_strings,
            "struct_size": size_dt_struct,
        }

    def _parse_uimage_header(self, data: bytes, offset: int) -> dict[str, Any]:
        if offset + 64 > len(data):
            return {}
        try:
            (
                magic,
                _header_crc,
                timestamp,
                payload_size,
                load_address,
                entrypoint,
                _data_crc,
                os_id,
                arch_id,
                image_type_id,
                compression_id,
            ) = struct.unpack_from(">7IBBBB", data, offset)
        except struct.error:
            return {}
        if magic != 0x27051956:
            return {}
        raw_name = data[offset + 32 : offset + 64].split(b"\x00", 1)[0]
        return {
            "timestamp": timestamp,
            "payload_size": payload_size,
            "load_address": f"0x{load_address:x}",
            "entrypoint": f"0x{entrypoint:x}",
            "os_id": os_id,
            "arch_id": arch_id,
            "image_type_id": image_type_id,
            "compression_id": compression_id,
            "image_name": raw_name.decode("utf-8", errors="replace"),
        }

    def _scan_binwalk(self, binary: Path) -> list[dict[str, Any]]:
        try:
            result = subprocess.run(
                ["binwalk", "-B", str(binary)],
                capture_output=True,
                text=True,
                timeout=self.binwalk_timeout,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        if result.returncode != 0:
            return []

        artifacts: list[dict[str, Any]] = []
        for line in result.stdout.splitlines()[3:]:
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            try:
                offset = int(parts[0], 10)
            except ValueError:
                continue
            description = parts[2].strip()
            artifacts.append({
                "offset": offset,
                "offset_hex": f"0x{offset:x}",
                "kind": self._kind_from_description(description),
                "name": description.split(",", 1)[0][:80],
                "description": description,
                "source": "binwalk",
                "confidence": 0.8,
                "recommended": True,
            })
        return artifacts

    def _carve_targets(
        self,
        binary: Path,
        artifacts: list[dict[str, Any]],
        recommended_targets: list[dict[str, Any]],
        size_bytes: int,
    ) -> list[dict[str, Any]]:
        if not recommended_targets:
            return []

        output_dir = self._output_dir(binary)
        output_dir.mkdir(parents=True, exist_ok=True)
        offsets = sorted(
            {
                int(artifact.get("offset", -1))
                for artifact in artifacts
                if isinstance(artifact.get("offset"), int) and int(artifact.get("offset", -1)) >= 0
            }
        )
        carved: list[dict[str, Any]] = []
        with binary.open("rb") as handle:
            for index, target in enumerate(recommended_targets[:25], start=1):
                offset = int(target.get("offset", -1))
                if offset <= 0 or offset >= size_bytes:
                    continue
                carve_size = self._carve_size(target, offset, offsets, size_bytes)
                if carve_size <= 0:
                    continue
                handle.seek(offset)
                data = handle.read(carve_size)
                if not data:
                    continue
                filename = self._carve_filename(index, target, data)
                path = output_dir / filename
                path.write_bytes(data)
                carved_target = dict(target)
                carved_target.update({
                    "carved_path": str(path),
                    "carved_size": len(data),
                    "carved_sha256": hashlib.sha256(data).hexdigest(),
                    "carved_signature": self._classify_bytes(data),
                    "carve_start": offset,
                    "carve_end": offset + len(data),
                })
                carved_target.update(self._analysis_routing(carved_target))
                carved.append(carved_target)
        return carved

    def _carve_size(
        self,
        target: dict[str, Any],
        offset: int,
        offsets: list[int],
        size_bytes: int,
    ) -> int:
        declared_size = target.get("declared_size")
        payload_size = target.get("payload_size")
        if isinstance(declared_size, int) and 0 < declared_size <= self.max_carve_bytes:
            return min(declared_size, size_bytes - offset)
        if isinstance(payload_size, int) and payload_size > 0:
            header_size = 64 if target.get("kind") == "uimage" else 0
            return min(payload_size + header_size, self.max_carve_bytes, size_bytes - offset)

        next_offsets = [candidate for candidate in offsets if candidate > offset]
        next_offset = min(next_offsets) if next_offsets else size_bytes
        return min(max(next_offset - offset, 0), self.max_carve_bytes, size_bytes - offset)

    def _output_dir(self, binary: Path) -> Path:
        if self.artifacts_dir:
            digest = hashlib.sha256(str(binary.resolve()).encode()).hexdigest()[:12]
            return self.artifacts_dir.expanduser() / f"{binary.stem}-{digest}"
        return binary.parent / f"{binary.stem}.r2d2-firmware"

    def _carve_filename(self, index: int, target: dict[str, Any], data: bytes) -> str:
        kind = str(target.get("kind") or "artifact")
        offset = int(target.get("offset", 0))
        suffix = self._extension_for_signature(self._classify_bytes(data), kind)
        safe_kind = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in kind)[:48] or "artifact"
        return f"{index:02d}_{offset:08x}_{safe_kind}{suffix}"

    def _classify_bytes(self, data: bytes) -> str:
        if data.startswith(b"\x7fELF"):
            return "elf"
        if data.startswith(b"\xd0\r\xfe\xed"):
            return "fit_or_dtb"
        if data.startswith(b"\x27\x05\x19\x56"):
            return "uimage"
        if data.startswith((b"hsqs", b"sqsh")):
            return "squashfs"
        if data.startswith(b"UBI#"):
            return "ubi"
        if data.startswith(b"\x1f\x8b\x08"):
            return "gzip"
        if data.startswith(b"\xfd7zXZ\x00"):
            return "xz"
        if data.startswith(b"\x28\xb5\x2f\xfd"):
            return "zstd"
        if data.startswith(b"PK\x03\x04"):
            return "zip"
        return "blob"

    def _extension_for_signature(self, signature: str, kind: str) -> str:
        if signature == "elf":
            return ".elf"
        if signature == "squashfs":
            return ".squashfs"
        if signature == "gzip":
            return ".gz"
        if signature == "xz":
            return ".xz"
        if signature == "zstd":
            return ".zst"
        if signature == "zip":
            return ".zip"
        if signature in {"fit_or_dtb", "uimage"}:
            return ".bin"
        if "filesystem" in kind:
            return ".fs"
        return ".bin"

    def _analysis_routing(self, artifact: dict[str, Any]) -> dict[str, Any]:
        kind = str(artifact.get("kind") or "")
        signature = str(artifact.get("carved_signature") or "")
        if kind == "elf_binary" or signature == "elf":
            return {
                "analysis_role": "code",
                "fanout_tools": ["radare2", "ghidra", "angr", "ghidra_gdb", "angr_mcp"],
            }
        if kind in {"squashfs_filesystem", "ubi_volume", "jffs2_marker", "cramfs_filesystem"} or signature in {"squashfs", "ubi"}:
            return {
                "analysis_role": "filesystem",
                "fanout_tools": ["binwalk", "firmware"],
            }
        if kind in {"compressed_stream", "archive"} or signature in {"gzip", "xz", "zstd", "zip"}:
            return {
                "analysis_role": "compressed",
                "fanout_tools": ["binwalk", "firmware"],
            }
        if kind in {"device_tree", "uimage"} or signature in {"fit_or_dtb", "uimage"}:
            return {
                "analysis_role": "container",
                "fanout_tools": ["firmware", "ghidra_mcp"],
            }
        return {
            "analysis_role": "evidence",
            "fanout_tools": ["firmware"],
        }

    def _build_fanout_tasks(self, targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        tasks: list[dict[str, Any]] = []
        for target in targets[:25]:
            role = target.get("analysis_role") or self._analysis_routing(target)["analysis_role"]
            tools = target.get("fanout_tools") or self._analysis_routing(target)["fanout_tools"]
            tasks.append({
                "target": target.get("carved_path") or target.get("offset_hex"),
                "offset": target.get("offset"),
                "kind": target.get("kind"),
                "role": role,
                "tools": tools,
                "status": "ready" if target.get("carved_path") else "needs_extraction",
                "reason": "ELF/code target" if role == "code" else "container or filesystem target",
            })
        return tasks

    def _dedupe_artifacts(self, artifacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_key: dict[tuple[int, str], dict[str, Any]] = {}
        for artifact in artifacts:
            key = (int(artifact.get("offset", -1)), str(artifact.get("kind", "")))
            if key not in by_key:
                by_key[key] = artifact
                continue
            existing = by_key[key]
            sources = sorted({str(existing.get("source")), str(artifact.get("source"))})
            existing["source"] = "+".join(source for source in sources if source and source != "None")
            existing["confidence"] = max(float(existing.get("confidence", 0.0)), float(artifact.get("confidence", 0.0)))
            existing["recommended"] = bool(existing.get("recommended") or artifact.get("recommended"))
        return sorted(by_key.values(), key=lambda item: (int(item["offset"]), str(item["kind"])))

    def _classify_top_level(self, data: bytes, artifacts: list[dict[str, Any]]) -> str:
        if data.startswith(b"\x7fELF"):
            return "elf"
        if data.startswith(b"\xd0\r\xfe\xed"):
            return "fit_or_dtb"
        if data.startswith(b"\x27\x05\x19\x56"):
            return "uimage"
        if data.startswith((b"hsqs", b"sqsh")):
            return "squashfs"
        if data.startswith(b"UBI#"):
            return "ubi"
        if data.startswith(b"\x1f\x8b\x08"):
            return "gzip"
        if any(artifact.get("kind") in {"device_tree", "uimage", "squashfs_filesystem", "ubi_volume"} for artifact in artifacts):
            return "firmware_container"
        if artifacts:
            return "binary_blob_with_embedded_artifacts"
        return "unknown_blob"

    def _classify_container(self, top_level_format: str, artifacts: list[dict[str, Any]]) -> str:
        kinds = {str(artifact.get("kind")) for artifact in artifacts}
        if top_level_format == "elf":
            return "executable"
        if "squashfs_filesystem" in kinds or "ubi_volume" in kinds or "jffs2_marker" in kinds:
            return "filesystem_image"
        if "device_tree" in kinds or "uimage" in kinds or top_level_format in {"fit_or_dtb", "uimage"}:
            return "boot_firmware"
        if "compressed_stream" in kinds or "archive" in kinds:
            return "compressed_container"
        return "opaque_blob"

    def _kind_from_description(self, description: str) -> str:
        lower = description.lower()
        if "squashfs" in lower:
            return "squashfs_filesystem"
        if "uimage" in lower or "u-boot" in lower:
            return "uimage"
        if "device tree" in lower or "fit image" in lower:
            return "device_tree"
        if "elf" in lower:
            return "elf_binary"
        if any(token in lower for token in ("gzip", "lzma", "xz", "zstd", "compressed")):
            return "compressed_stream"
        if "certificate" in lower or "private key" in lower:
            return "credential_material"
        return "embedded_artifact"

    def _sha256(self, binary: Path) -> str:
        digest = hashlib.sha256()
        with binary.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _notes(
        self,
        size_bytes: int,
        data: bytes,
        artifacts: list[dict[str, Any]],
        string_signals: dict[str, Any],
        entropy: dict[str, Any],
        binwalk_available: bool,
        binwalk_used: bool,
    ) -> list[str]:
        notes: list[str] = []
        if size_bytes > len(data):
            notes.append(f"Scan truncated at {len(data)} bytes.")
        if not data.startswith(b"\x7fELF"):
            notes.append("Top-level subject is not an ELF; use embedded artifacts as code/filesystem targets.")
        if not artifacts:
            notes.append("No common firmware signatures found in the scanned prefix.")
        signal_counts = string_signals.get("category_counts", {})
        if isinstance(signal_counts, dict) and signal_counts:
            categories = ", ".join(
                f"{category}={count}"
                for category, count in sorted(signal_counts.items())
            )
            notes.append(f"Built-in string triage found security-relevant strings: {categories}.")
        high_entropy = entropy.get("high_entropy_windows", [])
        if isinstance(high_entropy, list) and high_entropy:
            notes.append(
                f"High-entropy regions were observed in {len(high_entropy)} sampled window(s)."
            )
        if binwalk_available and not binwalk_used:
            notes.append("binwalk is available but was not needed for the fallback signature scan.")
        if not binwalk_available:
            notes.append("binwalk is not installed; fallback signature scan was used.")
        return notes
