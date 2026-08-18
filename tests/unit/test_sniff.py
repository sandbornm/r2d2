from pathlib import Path

from r2d2.analysis.sniff import render_intake, sniff_binary
from r2d2.storage.models import ChatMessage
from r2d2.web.app import _build_llm_messages


def test_sniff_binary_reads_file_hex_and_strings(tmp_path: Path) -> None:
    blob = tmp_path / "sample.bin"
    blob.write_bytes(
        b"fw-type:Cloud\x00httpd\x00/cgi-bin/login\x00nvram_get\x00"
        + b"\x00" * 64
        + b"upgrade\x00tmpServer\x00"
    )

    payload = sniff_binary(blob)

    assert payload["mode"] == "sniff"
    assert payload["size_bytes"] == blob.stat().st_size
    assert payload["sha256"]
    assert payload["hex_head"].startswith("00000000")
    assert "fw-type" in payload["hex_head"] or "66 77 2d 74" in payload["hex_head"]
    values = {item["value"] for item in payload["strings"]}
    assert "httpd" in values or any("login" in item for item in values)
    assert payload["file"]
    assert payload["readelf"] is None


def test_sniff_readelf_on_elf(tmp_path: Path) -> None:
    elf = tmp_path / "tiny.elf"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 128)
    payload = sniff_binary(elf)
    assert "ELF" in str(payload["file"])
    # readelf may fail on a stub header; sniff should still return a payload
    assert "readelf" in payload


def test_render_intake_includes_file_strings_and_briefing() -> None:
    card = render_intake(
        {
            "quick_scan": {
                "sniff": {
                    "file": "data, TP-Link firmware",
                    "strings": [{"value": "httpd"}, {"value": "nvram_get"}],
                },
                "firmware": {"top_level_format": "ver. 2.0"},
            },
            "briefing": {
                "summary": "wrapper + squashfs @ 0x100200",
                "subject": {"format": "firmware_container", "arch": "", "dangerous_imports": []},
            },
            "issues": ["r2 skipped on container"],
        }
    )
    assert "## Triage intake" in card
    assert "file(1): data, TP-Link firmware" in card
    assert "container: firmware_container" in card
    assert "httpd" in card
    assert "wrapper + squashfs" in card


def test_llm_system_prompt_includes_intake() -> None:
    analysis = {
        "type": "analysis_result",
        "quick_scan": {
            "sniff": {
                "file": "ELF 32-bit LSB executable, MIPS",
                "strings": [{"value": "system"}, {"value": "/cgi-bin/login"}],
            }
        },
        "briefing": {
            "summary": "mips httpd",
            "subject": {"format": "elf", "arch": "mips", "dangerous_imports": ["system"]},
        },
    }
    history = [
        ChatMessage(
            session_id="s1",
            role="system",
            content="User goal: who calls system on login",
            attachments=[{"type": "user_goal", "goal": "who calls system on login"}],
        )
    ]
    messages = _build_llm_messages(history, analysis)
    system = messages[0].content
    assert "User's Goal" in system
    assert "who calls system on login" in system
    assert "Triage intake" in system
    assert "ELF 32-bit LSB executable, MIPS" in system
    assert "system" in system
