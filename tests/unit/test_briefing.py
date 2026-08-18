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


def test_briefing_infers_unpack_goal_for_wrapper(tmp_path: Path):
    briefing = build_briefing(_sample_analysis(tmp_path))
    assert briefing["goal_source"] == "inferred"
    assert briefing["inferred_goal"]
    assert "lens-unpack" in briefing["ranking_tags"]
    assert "wrapper" in briefing["inferred_goal"].lower() or "carve" in briefing["inferred_goal"].lower()
    titles = [region["title"] for region in briefing["regions"]]
    assert any("Cloud" in title or "Squash" in title or "Firmware" in title for title in titles)
    assert not any(title.startswith("Entry") for title in titles)
    assert "Thesis" in briefing["summary"]


def test_briefing_ranks_popen_before_memcpy(tmp_path: Path):
    analysis = _sample_analysis(tmp_path)
    analysis["binary"] = str(tmp_path / "httpd")
    analysis["quick_scan"]["firmware"] = {
        "top_level_format": "elf",
        "container_type": "executable",
        "embedded_artifacts": [],
    }
    analysis["quick_scan"]["radare2"]["imports"] = [
        {"name": "memcpy"},
        {"name": "memmove"},
        {"name": "popen"},
        {"name": "sprintf"},
    ]
    briefing = build_briefing(analysis)
    assert briefing["subject"]["dangerous_imports"][0] == "popen"
    assert "popen" in briefing["next_steps"][0]


def test_briefing_infers_sinks_for_httpd_elf(tmp_path: Path):
    analysis = _sample_analysis(tmp_path)
    analysis["binary"] = str(tmp_path / "httpd")
    analysis["quick_scan"]["firmware"] = {
        "top_level_format": "elf",
        "container_type": "executable",
        "embedded_artifacts": [],
    }
    analysis["quick_scan"]["radare2"]["info"]["core"]["format"] = "elf"
    briefing = build_briefing(analysis)
    assert "lens-sinks" in briefing["ranking_tags"] or "lens-network" in briefing["ranking_tags"]
    assert any("plt" in region["id"] or "import" in region["title"].lower() for region in briefing["regions"])
    assert not any("Firmware region: ELF" in region["title"] and "0x0" in (region.get("snippet") or {}).get("text", "") for region in briefing["regions"])


def test_user_goal_reranks_regions(tmp_path: Path):
    analysis = _sample_analysis(tmp_path)
    unpack = build_briefing(analysis, user_goal="carve squashfs and brief httpd")
    auth = build_briefing(analysis, user_goal="find the login/auth credential path")
    assert unpack["goal_source"] == "user"
    assert auth["goal_source"] == "user"
    assert "lens-unpack" in unpack["ranking_tags"]
    assert "lens-auth" in auth["ranking_tags"]
    auth_titles = " ".join(region["title"].lower() for region in auth["regions"])
    assert "credential" in auth_titles or "auth" in auth_titles
    assert not any("JFFS2" in region["title"] for region in unpack["regions"])


def test_squashfs_survives_jffs2_flood(tmp_path: Path):
    analysis = _sample_analysis(tmp_path)
    flood = [
        {
            "kind": "jffs2_marker",
            "name": f"JFFS2 {index}",
            "offset": 0x1000 + index,
            "offset_hex": hex(0x1000 + index),
        }
        for index in range(40)
    ]
    analysis["quick_scan"]["firmware"]["embedded_artifacts"] = flood + [
        {
            "kind": "squashfs_filesystem",
            "name": "SquashFS LE",
            "offset": 0x100200,
            "offset_hex": "0x100200",
            "recommended": True,
        }
    ]
    analysis["quick_scan"]["firmware"]["recommended_targets"] = flood[:25]
    briefing = build_briefing(analysis)
    titles = [region["title"] for region in briefing["regions"]]
    assert any("SquashFS" in title for title in titles)
    assert not any("JFFS2" in title for title in titles)


def test_wrapper_elf_at_zero_is_not_a_region(tmp_path: Path):
    analysis = _sample_analysis(tmp_path)
    analysis["quick_scan"]["firmware"]["embedded_artifacts"].append(
        {
            "kind": "elf_binary",
            "name": "ELF @ 0x0",
            "offset": 0,
            "offset_hex": "0x0",
            "description": "the wrapper itself",
        }
    )
    briefing = build_briefing(analysis)
    texts = " ".join(
        (region.get("snippet") or {}).get("text", "") + region["title"]
        for region in briefing["regions"]
    )
    assert "ELF @ 0x0" not in texts
