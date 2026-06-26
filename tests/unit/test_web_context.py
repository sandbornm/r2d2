"""Tests for web LLM context budgeting helpers."""

from __future__ import annotations

from r2d2.config import AppConfig
from r2d2.storage.models import ChatSession
from r2d2.web.app import _build_budgeted_session_context, _llm_context_cache_key


def test_budgeted_session_context_keeps_within_budget() -> None:
    config = AppConfig()
    config.llm.context_budget_chars = 4200
    analysis = {
        "binary": "/tmp/sample.bin",
        "quick_scan": {
            "radare2": {
                "info": {"bin": {"arch": "arm", "bits": 32, "os": "linux"}, "core": {"format": "elf"}},
            },
        },
        "deep_scan": {
            "radare2": {
                "entry_disassembly": "\n".join(f"0x{i:04x}: mov r0, r0" for i in range(500)),
            },
        },
        "analysis_graph": {
            "nodes": [
                {"kind": "string", "label": f"signal-{i}", "address": f"0x{i:x}", "source": "firmware"}
                for i in range(200)
            ],
            "summary": {"node_count": 200, "edge_count": 0, "tools": ["firmware", "radare2"]},
        },
        "tool_status": {"radare2": {"status": "completed", "functions_count": 2}},
    }
    built = _build_budgeted_session_context(
        analysis,
        {"summary": {"event_count": 3, "node_count": 4, "edge_count": 2}},
        [{"event_type": "tab_switch", "event_data": {"to_tab": "analysis"}, "created_at": "now"}],
        config=config,
    )

    assert len(built["context"]) <= config.llm.context_budget_chars
    assert built["meta"]["budget_chars"] == config.llm.context_budget_chars
    assert any(section["name"] == "analysis" for section in built["meta"]["sections"])


def test_llm_context_cache_key_changes_with_activity() -> None:
    config = AppConfig()
    session = ChatSession(binary_path="/tmp/sample.bin", session_id="session-test")
    analysis = {
        "binary": "/tmp/sample.bin",
        "trajectory_id": "traj",
        "plan": {"profile": "standard"},
        "analysis_graph": {"summary": {"node_count": 1}},
        "tool_status": {"firmware": {"status": "completed"}},
    }

    first = _llm_context_cache_key(
        session,
        analysis_attachment=analysis,
        activity_context=[],
        investigation_graph={"summary": {"node_count": 1}},
        config=config,
    )
    second = _llm_context_cache_key(
        session,
        analysis_attachment=analysis,
        activity_context=[{"event_type": "tab_switch", "created_at": "2026-01-01T00:00:00Z"}],
        investigation_graph={"summary": {"node_count": 1}},
        config=config,
    )

    assert first != second
