from pathlib import Path

from r2d2.analysis.graph import GRAPH_SCHEMA_VERSION, build_analysis_graph
from r2d2.analysis.investigation_graph import INVESTIGATION_SCHEMA_VERSION, build_investigation_graph
from r2d2.analysis.orchestrator import AnalysisPlan, AnalysisResult
from r2d2.storage.models import ChatMessage, ChatSession


def test_analysis_graph_normalizes_multitool_findings(tmp_path: Path):
    result = AnalysisResult(
        binary=tmp_path / "sample.elf",
        plan=AnalysisPlan(),
        quick_scan={
            "firmware": {
                "mode": "firmware_inventory",
                "size_bytes": 8192,
                "sha256": "abc",
                "is_elf": False,
                "top_level_format": "firmware_container",
                "container_type": "boot_firmware",
                "scan": {"signature_count": 2},
                "embedded_artifacts": [
                    {
                        "offset": 4096,
                        "offset_hex": "0x1000",
                        "kind": "squashfs_filesystem",
                        "name": "SquashFS LE",
                        "description": "SquashFS filesystem",
                        "source": "signature",
                        "confidence": 0.9,
                        "recommended": True,
                        "analysis_role": "filesystem",
                        "fanout_tools": ["firmware", "binwalk"],
                        "carved_path": str(tmp_path / "rootfs.squashfs"),
                        "carved_signature": "squashfs",
                    }
                ],
                "recommended_targets": [
                    {
                        "offset": 4096,
                        "kind": "squashfs_filesystem",
                        "name": "SquashFS LE",
                    }
                ],
                "string_signals": {
                    "matched_count": 2,
                    "category_counts": {"credential": 1, "network": 1},
                    "top_signals": [
                        {
                            "category": "credential",
                            "label": "Credential or default-login material",
                            "value": "admin_password=root",
                            "offset": 6144,
                            "offset_hex": "0x1800",
                            "confidence": 0.82,
                        }
                    ],
                },
                "entropy": {
                    "window_size": 65536,
                    "sampled_windows": 1,
                    "average": 7.98,
                    "max": 7.98,
                    "high_entropy_windows": [{"offset": 0, "offset_hex": "0x0", "entropy": 7.98, "size": 65536}],
                },
            },
            "radare2": {
                "info": {"bin": {"arch": "arm", "bits": 64, "os": "linux"}},
                "imports": [{"name": "printf"}],
                "strings": [{"string": "hello world", "offset": "0x2000"}],
                "sections": [{"name": ".text", "vaddr": "0x1000", "size": 256}],
            }
        },
        deep_scan={
            "radare2": {
                "functions": [{"name": "main", "offset": 0x1000, "size": 64}],
                "function_cfgs": [
                    {
                        "name": "main",
                        "offset": "0x1000",
                        "blocks": [
                            {"offset": "0x1000", "jump": "0x1010", "disassembly": [{"addr": "0x1000", "opcode": "ret"}]},
                            {"offset": "0x1010", "disassembly": [{"addr": "0x1010", "opcode": "nop"}]},
                        ],
                    }
                ],
            },
            "angr": {
                "functions": [{"addr": "0x1000", "name": "main"}],
                "cfg": {"nodes": [{"addr": "0x1000", "function": "0x1000"}], "edges": []},
            },
            "angr_mcp": {
                "mode": "angr_mcp",
                "url": "http://127.0.0.1:8766/mcp",
                "entry": {"entry_point": "0x401000", "main": "0x401050"},
                "cfg": {"node_count": 12, "edge_count": 17},
            },
            "ghidra_gdb": {
                "file_info": {"architecture": "x86_64", "format": "ELF", "sha256": "abc"},
                "sections": [{"name": ".mcp_text", "address": "0000000000401000", "size": "10"}],
                "imports": [{"name": "malloc", "type": "function"}],
                "strings": ["firmware config"],
                "checksec": {"nx": True, "pie": False, "relro": "Partial", "canary": False},
                "entry": {"entry_point": "0x401000", "main": "0x401050"},
                "cfg": {
                    "nodes": [{"addr": "0x401000", "size": 5}],
                    "edges": [{"from": "0x401000", "to": "0x401005"}],
                },
            },
        },
        tool_availability={"radare2": True, "angr": True, "angr_mcp": True, "ghidra_gdb": True},
    )

    graph = build_analysis_graph(result)

    assert graph["schema_version"] == GRAPH_SCHEMA_VERSION
    assert graph["summary"]["node_count"] > 0
    assert any(node["kind"] == "function" and node["address"] == "0x1000" for node in graph["nodes"])
    assert any(edge["kind"] == "control_flow" for edge in graph["edges"])
    assert any(node["kind"] == "import" and node["label"] == "printf" for node in graph["nodes"])
    assert any(node["kind"] == "import" and node["label"] == "malloc" for node in graph["nodes"])
    assert any(node["kind"] == "mitigation_profile" for node in graph["nodes"])
    assert any(node["kind"] == "section" and node["address"] == "0x401000" for node in graph["nodes"])
    assert any(node["kind"] == "cfg_summary" and node["source"] == "angr_mcp" for node in graph["nodes"])
    assert any(edge["kind"] == "has_cfg_summary" and edge["source_tool"] == "angr_mcp" for edge in graph["edges"])
    assert any(node["kind"] == "embedded_artifact" and node["address"] == "0x1000" for node in graph["nodes"])
    assert any(
        node["kind"] == "string"
        and node["source"] == "firmware"
        and node["address"] == "0x1800"
        and node["properties"]["category"] == "credential"
        for node in graph["nodes"]
    )
    assert any(edge["kind"] == "has_string_signal" and edge["source_tool"] == "firmware" for edge in graph["edges"])
    assert any(edge["kind"] == "suggests_target" for edge in graph["edges"])
    assert any(edge["kind"] == "candidate_for" for edge in graph["edges"])


def test_investigation_graph_keeps_journey_separate_from_findings():
    session = ChatSession(binary_path="/tmp/sample.elf", session_id="sess-1", trajectory_id="traj-1")
    messages = [
        ChatMessage(session_id="sess-1", role="user", content="What does main do?", message_id="m1"),
        ChatMessage(
            session_id="sess-1",
            role="assistant",
            content="It returns.",
            attachments=[{"type": "llm_response_meta", "provider": "ollama"}],
            message_id="m2",
        ),
    ]
    activities = [
        {
            "event_id": "a1",
            "event_type": "address_hover",
            "event_data": '{"address": "0x1000"}',
            "created_at": "2026-01-01T00:00:00+00:00",
        }
    ]
    trajectory_actions = [
        {
            "trajectory_id": "traj-1",
            "seq": 1,
            "action": "radare2.deep",
            "payload": '{"functions": 1}',
            "created_at": "2026-01-01T00:00:01+00:00",
        }
    ]

    graph = build_investigation_graph(
        session,
        messages=messages,
        activities=activities,
        trajectory_actions=trajectory_actions,
    )

    assert graph["schema_version"] == INVESTIGATION_SCHEMA_VERSION
    assert graph["summary"]["event_count"] == 4
    assert any(node["kind"] == "human_action" for node in graph["nodes"])
    assert any(node["kind"] == "tool_action" for node in graph["nodes"])
    assert any(edge["kind"] == "then" for edge in graph["edges"])
