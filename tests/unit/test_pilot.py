"""Unit tests for the goal-driven pilot (no LLM, no subprocess execution)."""

import json
from pathlib import Path

import pytest

from r2d2.pilot import PilotEngine, build_cmd, corpus_context, extract_json, pilot_dir_for, validate_plan

HEX = "a" * 64


@pytest.fixture()
def lab_root(tmp_path):
    sample = tmp_path / "samples" / "Archer_C7_US_V5_220715"
    sample.mkdir(parents=True)
    (sample / "meta.json").write_text(json.dumps(
        {"id": "Archer_C7_US_V5_220715", "product": "Archer C7", "family": "cloud-safeloader"}))
    sbin = tmp_path / "work" / "c7" / "rootfs" / "usr" / "sbin"
    sbin.mkdir(parents=True)
    (sbin / "httpd").write_bytes(b"\x7fELF fake")
    (tmp_path / "outside.bin").write_bytes(b"not in lab")
    return tmp_path


# ---------------------------------------------------------------- validate_plan

def test_validate_plan_accepts_corpus_targets(lab_root):
    plan = {
        "goal": "audit httpd",
        "steps": [
            {"verb": "analyze", "target": "work/c7/rootfs/usr/sbin/httpd", "quick": True, "why": "first pass"},
            {"verb": "brief",
             "target": str(lab_root / "work" / "c7" / "rootfs" / "usr" / "sbin" / "httpd"),
             "ask_regions": 2, "why": "region asks"},
            {"verb": "records", "target": "list", "why": "enumerate"},
            {"verb": "records", "target": HEX, "why": "reopen"},
            {"verb": "insights", "target": "httpd", "why": "distill"},
        ],
    }
    assert validate_plan(plan, lab_root) == []


def test_validate_plan_rejects_target_escape(lab_root):
    plan = {"goal": "g", "steps": [
        {"verb": "analyze", "target": "../outside.bin", "why": "escape"},
    ]}
    errs = validate_plan(plan, lab_root)
    assert any("escapes lab root" in e for e in errs)


def test_validate_plan_rejects_absolute_target_outside_root(lab_root):
    plan = {"goal": "g", "steps": [
        {"verb": "brief", "target": "/etc/hostname", "why": "escape"},
    ]}
    errs = validate_plan(plan, lab_root)
    assert any("escapes lab root" in e for e in errs)


def test_validate_plan_rejects_missing_file_bad_verb_and_ranges(lab_root):
    plan = {
        "goal": "g",
        "steps": [
            {"verb": "analyze", "target": "work/c7/rootfs/usr/sbin/nope", "why": "missing"},
            {"verb": "delete", "target": "x", "why": "unknown verb"},
            {"verb": "records", "target": "not-hex", "why": "bad id"},
            {"verb": "insights", "target": "bad tag!", "why": "bad tag"},
            {"verb": "mcp-start", "target": "straced", "why": "unknown service"},
            {"verb": "brief", "target": "work/c7/rootfs/usr/sbin/httpd", "ask_regions": 4, "why": "range"},
        ],
    }
    errs = validate_plan(plan, lab_root)
    assert any("not an existing file" in e for e in errs)
    assert any("verb" in e for e in errs)
    assert any("64-hex" in e for e in errs)
    assert any("short tag" in e for e in errs)
    assert any("mcp-start" in e for e in errs)
    assert any("ask_regions" in e for e in errs)


def test_validate_plan_rejects_wrong_shape():
    tmp_root = Path("/tmp")
    assert validate_plan({"nope": 1}, tmp_root)
    assert validate_plan({"goal": "g", "steps": []}, tmp_root)
    assert validate_plan(
        {"goal": "g", "steps": [{"verb": "records", "target": "list", "why": "x"}] * 9}, tmp_root)


# ---------------------------------------------------------------- extract_json

def test_extract_json_plain_fenced_and_prose():
    assert extract_json('{"a": 1}') == {"a": 1}
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Sure! Here it is: {"a": {"b": 2}} hope that helps') == {"a": {"b": 2}}


def test_extract_json_rejects_text_without_object():
    with pytest.raises(ValueError):
        extract_json("no json here at all")


# ---------------------------------------------------------------- context

def test_corpus_context_lists_samples_and_carved_binaries(lab_root):
    ctx = corpus_context(lab_root)
    assert "Archer_C7_US_V5_220715 | Archer C7 | cloud-safeloader" in ctx
    assert "work/c7/rootfs/usr/sbin/httpd | c7" in ctx
    assert "records list" in ctx


def test_corpus_context_ignores_uninteresting_files(lab_root):
    ctx = corpus_context(lab_root)
    assert "meta.json" not in ctx


# ---------------------------------------------------------------- build_cmd

def test_build_cmd_analyze_and_brief(lab_root, monkeypatch):
    monkeypatch.setenv("R2D2_PILOT_BIN", "r2d2")
    cfg = lab_root / "config.toml"
    analyze = build_cmd(
        {"verb": "analyze", "target": "work/c7/rootfs/usr/sbin/httpd", "quick": True,
         "tag": "sample:c7", "ask": "auth surface?"},
        root=lab_root, config_path=cfg)
    assert analyze == [
        "r2d2", "analyze", str(lab_root / "work/c7/rootfs/usr/sbin/httpd"),
        "--config", str(cfg), "--json", "--quick", "--tag", "sample:c7", "--ask", "auth surface?",
    ]
    brief = build_cmd(
        {"verb": "brief", "target": "work/c7/rootfs/usr/sbin/httpd", "quick": False, "ask_regions": 2},
        root=lab_root)
    assert brief == [
        "r2d2", "brief", str(lab_root / "work/c7/rootfs/usr/sbin/httpd"),
        "--json", "--ask-regions", "2",
    ]


def test_build_cmd_records_insights_mcp(monkeypatch):
    monkeypatch.setenv("R2D2_PILOT_BIN", "r2d2")
    assert build_cmd({"verb": "records", "target": "list"}, root="/lab") == [
        "r2d2", "records", "list"]
    assert build_cmd({"verb": "records", "target": HEX}, root="/lab") == [
        "r2d2", "records", "show", HEX]
    assert build_cmd({"verb": "insights", "target": "httpd"}, root="/lab") == [
        "r2d2", "insights", "--tag", "httpd"]
    assert build_cmd({"verb": "mcp-start", "target": "angr_mcp"}, root="/lab") == [
        "r2d2", "mcp-start", "--service", "angr_mcp"]


# ---------------------------------------------------------------- reporting

def test_grounded_and_mechanical_report():
    digests = ["record_id=abc123defghij tag=httpd binary=httpd arch=mips"]
    assert PilotEngine.grounded(
        "Found record_id abc123defghij for httpd arch mips.", digests)
    assert not PilotEngine.grounded(
        "The router runs a vulnerable service on port 9999.", digests)
    assert PilotEngine.grounded("anything", [])

    report = PilotEngine.mechanical_report(
        "audit httpd",
        [{"step": "00-analyze", "verb": "analyze", "target": "httpd", "rc": 0}],
        ["record_id=abc123defghij"],
    )
    assert "00-analyze" in report and "record_id=abc123defghij" in report
    assert "mechanical fallback" in report


# ---------------------------------------------------------------- engine paths

def test_pilot_dir_and_queue_under_root(lab_root):
    class _NoLLM:  # PilotEngine never touches the LLM for path logic
        pass

    engine = PilotEngine(llm=_NoLLM(), root=lab_root)
    assert engine.pilot_dir == lab_root / "work" / "pilot"
    assert engine.queue_dir == lab_root / "work" / "pilot" / "queue"
    assert pilot_dir_for(lab_root) == engine.pilot_dir
