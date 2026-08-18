from pathlib import Path

from r2d2.analysis.orchestrator import AnalysisPlan, AnalysisResult
from r2d2.analysis.record import RECORD_SCHEMA_VERSION, AnalysisRecordStore


def _analysis(tmp_path: Path, name: str = "httpd") -> tuple[Path, AnalysisResult]:
    binary = tmp_path / name
    binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
    result = AnalysisResult(
        binary=binary,
        plan=AnalysisPlan(),
        quick_scan={
            "firmware": {
                "top_level_format": "firmware_container",
                "container_type": "tp_link_cloud",
                "carved_targets": [
                    {
                        "kind": "elf_binary",
                        "analysis_role": "code",
                        "carved_path": str(binary),
                        "offset": 4096,
                    }
                ],
            },
            "radare2": {
                "info": {"bin": {"arch": "arm", "bits": 32, "os": "linux"}, "core": {"format": "elf"}},
                "imports": [{"name": "strcpy"}, {"name": "system"}],
            },
            "sniff": {
                "mode": "sniff",
                "file": "ELF 32-bit LSB executable, ARM",
                "sha256": "abc",
                "hex_head": "00000000  7f 45 4c 46",
                "strings": [{"value": "httpd"}],
            },
            "autoprofile": {"profile": {"file_type": "ELF", "is_stripped": True, "risk_level": "high"}},
        },
        deep_scan={
            "radare2": {
                "functions": [{"name": "http_auth", "offset": 0x2000, "size": 128}],
                "function_count": 1,
                "entry_function": {"name": "entry0", "offset": 0x1000},
                "entry_disassembly": "0x1000  push {lr}\n0x1004  pop {pc}\n",
                "function_cfgs": [
                    {
                        "name": "http_auth",
                        "offset": "0x2000",
                        "size": 128,
                        "block_count": 1,
                        "blocks": [
                            {
                                "offset": "0x2000",
                                "size": 8,
                                "jump": None,
                                "fail": None,
                                "disassembly": [{"addr": "0x2000", "opcode": "push {r4, lr}"}],
                            }
                        ],
                    }
                ],
            }
        },
        tool_status={"radare2": {"status": "completed"}},
        notes=["first pass"],
    )
    return binary, result


def test_persist_creates_tagged_record_with_cfg_and_commentary(tmp_path: Path):
    binary, result = _analysis(tmp_path)
    store = AnalysisRecordStore(tmp_path / "artifacts")
    summary = store.persist(result, binary=binary, extra_tags=["lab:wr841", "httpd"])

    assert summary["schema_version"] == RECORD_SCHEMA_VERSION
    assert summary["record_id"]
    assert "elf" in summary["tags"]
    assert "httpd" in summary["tags"]
    assert "lab:wr841" in summary["tags"]
    assert summary["revision"] == 1
    assert summary["cfg_count"] >= 1
    assert summary["region_count"] >= 1

    directory = Path(summary["directory"])
    assert (directory / "record.json").is_file()
    assert (directory / "commentary.md").is_file()
    assert (directory / "briefing.json").is_file()
    assert (directory / "tools" / "radare2.json").is_file()
    assert (directory / "tools" / "sniff.json").is_file()
    sniff = (directory / "tools" / "sniff.json").read_text()
    assert "httpd" in sniff
    assert list((directory / "graphs" / "cfg").glob("*.json"))
    commentary = (directory / "commentary.md").read_text()
    assert "Interesting regions" in commentary
    assert "Analyst notes" in commentary


def test_second_pass_merges_instead_of_replacing(tmp_path: Path):
    binary, first = _analysis(tmp_path)
    store = AnalysisRecordStore(tmp_path / "artifacts")
    first_summary = store.persist(first, binary=binary, extra_tags=["pass-1"])

    notes_path = Path(first_summary["directory"]) / "commentary.md"
    notes_path.write_text(notes_path.read_text() + "\nHuman: check strcpy xref.\n", encoding="utf-8")

    second = AnalysisResult(
        binary=binary,
        plan=AnalysisPlan(),
        quick_scan=first.quick_scan,
        deep_scan={
            "radare2": first.deep_scan["radare2"],
            "ghidra": {
                "mode": "headless",
                "function_count": 1,
                "decompiled": [{"name": "http_auth", "address": "0x2000", "decompiled_c": "int http_auth() { return 0; }"}],
            },
        },
        tool_status={"radare2": {"status": "completed"}, "ghidra": {"status": "completed"}},
    )
    second_summary = store.persist(second, binary=binary, extra_tags=["pass-2"], session_id="sess-9")

    assert second_summary["record_id"] == first_summary["record_id"]
    assert second_summary["revision"] == 2
    assert "pass-1" in second_summary["tags"]
    assert "pass-2" in second_summary["tags"]
    assert "ghidra" in second_summary["tool_names"]
    assert "radare2" in second_summary["tool_names"]
    assert "sess-9" in second_summary["session_ids"]
    loaded = store.load(second_summary["record_id"], include_blobs=True)
    assert loaded is not None
    assert "http_auth" in (loaded.get("commentary_text") or "")
    assert "Human: check strcpy xref." in (loaded.get("commentary_text") or "")
    assert loaded["tool_blobs"]["ghidra"]["decompiled"]


def test_list_records_can_filter_by_tag(tmp_path: Path):
    binary, result = _analysis(tmp_path, name="busybox")
    store = AnalysisRecordStore(tmp_path / "artifacts")
    store.persist(result, binary=binary, extra_tags=["busybox"])
    rows = store.list_records(tag="busybox")
    assert len(rows) == 1
    assert rows[0]["names"] == ["busybox"]
    assert store.list_records(tag="missing") == []
