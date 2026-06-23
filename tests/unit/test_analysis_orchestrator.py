from pathlib import Path

import pytest

from r2d2.analysis.orchestrator import AnalysisOrchestrator, AnalysisPlan, AnalysisResult
from r2d2.config import AppConfig
from r2d2.environment.detectors import EnvironmentReport, ToolCheck


def build_env_report(tmp_path: Path) -> EnvironmentReport:
    return EnvironmentReport(
        python_version='3.11',
        uv_available=True,
        openai_key_present=False,
        tools=[
            ToolCheck(name='radare2', command='radare2', available=False),
        ],
        ghidra=None,
    )


def test_ensure_elf_validation(tmp_path: Path):
    config = AppConfig()
    config.analysis.enable_angr = False
    config.analysis.enable_ghidra = False
    config.analysis.require_elf = True

    env = build_env_report(tmp_path)

    orchestrator = AnalysisOrchestrator(config, env, trajectory_dao=None)

    non_elf = tmp_path / 'not_elf.bin'
    non_elf.write_bytes(b'\x00\x00\x00\x00')

    with pytest.raises(ValueError):
        orchestrator._ensure_elf(non_elf)

    elf = tmp_path / 'sample.elf'
    elf.write_bytes(b'\x7fELF' + b'\x00' * 8)
    orchestrator._ensure_elf(elf)  # should not raise


class _FakeChildAnalyzer:
    name = "angr_mcp"

    def is_available(self) -> bool:
        return True

    def quick_scan(self, binary: Path, **kwargs):
        return {"entry": "0x1000"}

    def deep_scan(self, binary: Path, **kwargs):
        return {"functions": [{"addr": "0x1000", "name": "entry"}], "cfg": {"nodes": [], "edges": []}}


def test_firmware_child_fanout_runs_available_code_analyzers(tmp_path: Path):
    config = AppConfig()
    config.analysis.enable_angr = False
    config.analysis.enable_ghidra = False
    env = build_env_report(tmp_path)
    orchestrator = AnalysisOrchestrator(config, env, trajectory_dao=None)

    child = tmp_path / "child.elf"
    child.write_bytes(b"\x7fELF" + b"\x00" * 32)
    result = AnalysisResult(
        binary=tmp_path / "firmware.bin",
        plan=AnalysisPlan(),
        quick_scan={
            "firmware": {
                "carved_targets": [
                    {
                        "offset": 4096,
                        "kind": "elf_binary",
                        "analysis_role": "code",
                        "fanout_tools": ["angr_mcp"],
                        "carved_path": str(child),
                    }
                ],
                "fanout_tasks": [
                    {
                        "target": str(child),
                        "offset": 4096,
                        "kind": "elf_binary",
                        "role": "code",
                        "tools": ["angr_mcp"],
                        "status": "ready",
                    }
                ],
            }
        },
    )

    orchestrator._run_firmware_child_fanout(result, None, None, {"angr_mcp": _FakeChildAnalyzer()})

    children = result.deep_scan["firmware_children"]
    assert children["mode"] == "firmware_child_fanout"
    assert children["analyses"][0]["tool"] == "angr_mcp"
    assert children["analyses"][0]["status"] == "completed"
