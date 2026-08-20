from pathlib import Path

from r2d2.analysis.briefing import (
    BRIEFING_SCHEMA_VERSION,
    build_briefing,
    extract_code_snippets,
    render_briefing_markdown,
)
from r2d2.analysis.orchestrator import AnalysisPlan, AnalysisResult
from r2d2.analysis.result_dto import analysis_result_to_public_dict, ensure_analysis_briefing


def _sample_analysis(tmp_path: Path) -> dict:
    return {
        "binary": str(tmp_path / "httpd"),
        "plan": {"quick": True, "deep": True, "run_angr": False, "persist_trajectory": False},
        "quick_scan": {
            "firmware": {
                "top_level_format": "firmware_container",
                "container_type": "tp_link_cloud",
                "wrapper_family": "cloud",
                "embedded_artifacts": [
                    {
                        "kind": "vendor_wrapper",
                        "name": "TP-Link Cloud",
                        "description": "fw-type:Cloud wrapper",
                        "offset": 0,
                        "offset_hex": "0x0",
                        "recommended": True,
                    },
                    {
                        "kind": "elf_binary",
                        "name": "embedded ELF",
                        "offset": 4096,
                        "offset_hex": "0x1000",
                        "analysis_role": "code",
                        "carved_path": str(tmp_path / "httpd"),
                        "recommended": True,
                    },
                ],
                "string_signals": {
                    "top_signals": [
                        {
                            "category": "credential",
                            "label": "default login",
                            "value": "admin_password=root",
                            "offset": 0x1800,
                            "offset_hex": "0x1800",
                        }
                    ]
                },
            },
            "autoprofile": {
                "profile": {
                    "file_type": "ELF",
                    "architecture": "arm",
                    "bits": 32,
                    "is_stripped": True,
                    "risk_level": "high",
                    "risk_factors": ["strcpy", "system"],
                }
            },
            "radare2": {
                "info": {"bin": {"arch": "arm", "bits": 32, "os": "linux"}, "core": {"format": "elf"}},
                "imports": [{"name": "strcpy"}, {"name": "system"}, {"name": "socket"}],
            },
        },
        "deep_scan": {
            "radare2": {
                "functions": [
                    {"name": "entry0", "offset": 0x1000, "size": 48},
                    {"name": "http_auth", "offset": 0x2000, "size": 512},
                ],
                "function_count": 2,
                "entry_function": {"name": "entry0", "offset": 0x1000},
                "entry_disassembly": "0x1000  push {r4, lr}\n0x1004  bl sym.imp.strcpy\n0x1008  pop {r4, pc}\n",
                "snippets": [
                    {
                        "function": "http_auth",
                        "offset": "0x2000",
                        "blocks": [
                            {
                                "offset": "0x2000",
                                "disassembly": [
                                    {"addr": "0x2000", "bytes": "00", "opcode": "push {r4, lr}"},
                                    {"addr": "0x2004", "bytes": "01", "opcode": "bl sym.imp.strcpy"},
                                ],
                            }
                        ],
                    }
                ],
            }
        },
        "issues": [],
        "notes": [],
    }


def test_build_briefing_ranks_wrapper_and_dangerous_imports(tmp_path: Path):
    briefing = build_briefing(_sample_analysis(tmp_path), max_regions=6)

    assert briefing["schema_version"] == BRIEFING_SCHEMA_VERSION
    assert briefing["prompt_id"] == "r2d2.prompt.v1"
    assert briefing["subject"]["wrapper_family"] == "cloud"
    assert briefing["regions"]
    titles = " ".join(region["title"].lower() for region in briefing["regions"])
    assert "cloud" in titles or "firmware" in titles
    assert any("strcpy" in (region.get("ask") or "") or "plt" in region["id"] for region in briefing["regions"])
    assert "4 bullets" in briefing["regions"][0]["ask"]
    assert "non-obvious" in briefing["regions"][0]["ask"]
    assert "6 bullets" in briefing["overall_ask"]
    assert "no exploit" in briefing["overall_ask"].lower() or "exploit" in briefing["overall_ask"].lower()
    assert briefing["next_steps"]
    markdown = render_briefing_markdown(briefing)
    assert "http_auth" in markdown or "Entry" in markdown or "Firmware" in markdown
    assert len(briefing["regions"][0]["ask"]) < 1200


def test_briefing_drops_noisy_firmware_hits(tmp_path: Path):
    analysis = _sample_analysis(tmp_path)
    analysis["quick_scan"]["firmware"]["embedded_artifacts"].extend(
        [
            {
                "kind": "vendor_wrapper",
                "name": "TP-Link Cloud",
                "offset": 4,
                "offset_hex": "0x4",
                "description": "duplicate wrapper",
            },
            {
                "kind": "jffs2_marker",
                "name": "JFFS2 LE",
                "offset": 0x137eb,
                "offset_hex": "0x137eb",
                "description": "false JFFS2",
            },
            {
                "kind": "squashfs_filesystem",
                "name": "SquashFS LE",
                "offset": 0x100200,
                "offset_hex": "0x100200",
                "recommended": True,
                "description": "root filesystem",
            },
        ]
    )
    analysis["quick_scan"]["firmware"]["string_signals"]["top_signals"] = [
        {"category": "credential", "value": "rootpath", "offset": 1},
        {"category": "network", "value": "bootcmd=tftp", "offset": 2},
        {"category": "credential", "value": "admin_password=root", "offset": 3, "label": "login"},
    ]
    briefing = build_briefing(analysis, max_regions=8)
    titles = [region["title"] for region in briefing["regions"]]
    assert sum("Cloud" in title for title in titles) == 1
    assert not any("JFFS2" in title for title in titles)
    assert any("SquashFS" in title for title in titles)
    asks = " ".join(region.get("ask") or "" for region in briefing["regions"])
    assert "rootpath" not in asks
    assert "admin_password=root" in asks


def test_briefing_elf_subject_does_not_ask_to_unpack(tmp_path: Path):
    analysis = {
        "binary": str(tmp_path / "flipper.elf"),
        "quick_scan": {
            "firmware": {
                "is_elf": True,
                "top_level_format": "elf",
                "container_type": "executable",
                "carved_targets": [],
                "embedded_artifacts": [
                    {
                        "kind": "elf_binary",
                        "name": "ELF",
                        "offset": 0,
                        "offset_hex": "0x0",
                        "description": "Embedded ELF executable/shared object",
                    },
                    {
                        "kind": "jffs2_marker",
                        "name": "JFFS2 LE",
                        "offset": 64,
                        "offset_hex": "0x40",
                    },
                ],
                "string_signals": {
                    "top_signals": [
                        {"category": "credential", "value": "AcceptAllPasswords", "offset": 10},
                    ]
                },
            },
            "radare2": {
                "info": {"bin": {"arch": "arm", "bits": 16, "os": "none"}},
                "imports": [],
                "interesting_symbols": [
                    {"name": "subghz_protocol_princeton", "vaddr": 0x080A70F8, "type": "OBJ"},
                    {"name": "subghz_protocol_decoder_princeton_feed", "vaddr": 0x08061200, "type": "FUNC"},
                ],
            },
        },
        "deep_scan": {"radare2": {"functions": [], "function_count": 0}},
        "issues": [],
    }
    briefing = build_briefing(analysis, max_regions=6)
    assert briefing["subject"]["subject_class"] == "baremetal_elf"
    steps = " ".join(briefing["next_steps"]).lower()
    assert "already an elf" in steps
    assert "httpd" not in steps
    titles = " ".join(region["title"].lower() for region in briefing["regions"])
    assert "protocol" in titles or "subghz" in titles
    assert "jffs2" not in titles
    asks = " ".join(region.get("ask") or "" for region in briefing["regions"]).lower()
    assert "acceptallpasswords" not in asks


def test_briefing_quick_elf_uses_entry_listing_not_overview(tmp_path: Path):
    analysis = {
        "binary": str(tmp_path / "hello"),
        "quick_scan": {
            "firmware": {"is_elf": True, "top_level_format": "elf", "container_type": "executable"},
            "radare2": {
                "info": {"bin": {"arch": "arm", "bits": 64, "os": "linux"}, "core": {"format": "elf"}},
                "imports": [{"name": "puts"}],
                "symbols": [
                    {"name": "main", "vaddr": 0x4005A4, "type": "FUNC", "size": 48},
                    {"name": "hello.c", "vaddr": 0xFFFFFFFFFFFFFFFF, "type": "FILE"},
                ],
                "entry_function": {"name": "main", "offset": 0x4005A4},
                "entry_disassembly": "0x4005a4  stp x29, x30, [sp, -16]!\n0x4005a8  mov x29, sp\n0x4005ac  bl sym.imp.puts\n",
            },
        },
        "deep_scan": {},
        "issues": [],
    }
    briefing = build_briefing(analysis, max_regions=4)
    assert briefing["subject"]["subject_class"] == "linux_elf"
    titles = " ".join(region["title"].lower() for region in briefing["regions"])
    assert "characterize" not in titles
    assert "entry" in titles or "main" in titles
    texts = " ".join((region.get("snippet") or {}).get("text") or "" for region in briefing["regions"])
    assert "stp" in texts or "puts" in texts
    assert "hello.c" not in texts


def test_briefing_uimage_does_not_ask_to_unpack_httpd(tmp_path: Path):
    analysis = {
        "binary": str(tmp_path / "kernel.uimage"),
        "quick_scan": {
            "firmware": {
                "is_elf": False,
                "top_level_format": "uimage",
                "container_type": "boot_firmware",
                "carved_targets": [],
                "embedded_artifacts": [
                    {
                        "kind": "uimage",
                        "name": "uImage",
                        "offset": 0,
                        "offset_hex": "0x0",
                        "description": "U-Boot legacy uImage",
                        "recommended": True,
                    }
                ],
            },
            "radare2": {"info": {"bin": {"arch": "mips", "bits": 32}}, "imports": []},
        },
        "deep_scan": {},
        "issues": [],
    }
    briefing = build_briefing(analysis, max_regions=4)
    assert briefing["subject"]["subject_class"] == "uimage"
    steps = " ".join(briefing["next_steps"]).lower()
    assert "uimage payload" in steps
    assert "unpack the vendor wrapper" not in steps
    assert "tdpserver" not in steps


def test_briefing_does_not_dump_full_adapter_bags(tmp_path: Path):
    analysis = _sample_analysis(tmp_path)
    analysis["deep_scan"]["radare2"]["functions"] = [
        {"name": f"fcn_{index}", "offset": 0x3000 + index, "size": 16} for index in range(200)
    ]
    briefing = build_briefing(analysis)
    dumped = render_briefing_markdown(briefing)
    assert "fcn_199" not in dumped
    assert dumped.count("```") <= 20


def test_extract_code_snippets_flattens_r2_blocks():
    snippets = extract_code_snippets(
        {
            "radare2": {
                "snippets": [
                    {
                        "function": "main",
                        "blocks": [
                            {
                                "offset": "0x1000",
                                "disassembly": [{"addr": "0x1000", "opcode": "push {lr}"}],
                            }
                        ],
                    }
                ]
            }
        }
    )
    assert snippets[0]["source"] == "radare2"
    assert snippets[0]["function"] == "main"
    assert snippets[0]["instructions"][0]["opcode"] == "push {lr}"


def test_public_dto_includes_briefing_and_omits_resource_tree(tmp_path: Path):
    result = AnalysisResult(
        binary=tmp_path / "httpd",
        plan=AnalysisPlan(),
        quick_scan=_sample_analysis(tmp_path)["quick_scan"],
        deep_scan=_sample_analysis(tmp_path)["deep_scan"],
    )
    payload = analysis_result_to_public_dict(result, session_id="sess-1")
    assert payload["type"] == "analysis_result"
    assert payload["schema_version"] == "r2d2.analysis_result.v1"
    assert payload["session_id"] == "sess-1"
    assert payload["binary"].endswith("httpd")
    assert "resource_tree" not in payload
    assert payload["briefing"]["regions"]
    assert payload["snippet_count"] == len(payload["snippets"])


def test_ensure_analysis_briefing_recomputes_when_missing(tmp_path: Path):
    analysis = _sample_analysis(tmp_path)
    briefing = ensure_analysis_briefing(analysis)
    assert briefing["regions"]
    analysis["briefing"] = briefing
    assert ensure_analysis_briefing(analysis) is briefing
