from __future__ import annotations

import struct
from pathlib import Path

from r2d2.adapters.firmware import FirmwareAdapter


def test_firmware_adapter_detects_embedded_components(tmp_path: Path):
    firmware = bytearray(b"\x00" * 0x3000)
    firmware[0:7] = b"TP-LINK"
    firmware[0x40 : 0x40 + 40] = struct.pack(
        ">10I",
        0xD00DFEED,
        0x120,
        0x38,
        0x100,
        0x28,
        17,
        16,
        0,
        0x20,
        0x80,
    )
    firmware[0x100:0x10B] = b"OpenWrt FIT"
    firmware[0x1000:0x1004] = b"hsqs"
    firmware[0x2000:0x2004] = b"\x7fELF"
    path = tmp_path / "router.bin"
    path.write_bytes(firmware)

    result = FirmwareAdapter(run_binwalk=False).quick_scan(path)

    assert result["mode"] == "firmware_inventory"
    assert result["is_elf"] is False
    assert result["top_level_format"] == "firmware_container"
    assert result["container_type"] in {"boot_firmware", "filesystem_image"}

    kinds = {artifact["kind"] for artifact in result["embedded_artifacts"]}
    assert {"device_tree", "squashfs_filesystem", "elf_binary"}.issubset(kinds)
    assert any(target["kind"] == "elf_binary" for target in result["recommended_targets"])
    assert any(target["carved_signature"] == "elf" for target in result["carved_targets"])
    assert any("angr" in task["tools"] and "ghidra" in task["tools"] for task in result["fanout_tasks"])

    elf_target = next(target for target in result["carved_targets"] if target["carved_signature"] == "elf")
    carved_path = Path(elf_target["carved_path"])
    assert carved_path.exists()
    assert carved_path.read_bytes().startswith(b"\x7fELF")


def test_firmware_adapter_classifies_top_level_elf(tmp_path: Path):
    path = tmp_path / "sample.elf"
    path.write_bytes(b"\x7fELF" + b"\x00" * 64)

    result = FirmwareAdapter(run_binwalk=False).quick_scan(path)

    assert result["is_elf"] is True
    assert result["top_level_format"] == "elf"
    assert result["container_type"] == "executable"
