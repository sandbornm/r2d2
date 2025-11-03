import io
from pathlib import Path

import pytest

from r2d2.analysis.orchestrator import AnalysisOrchestrator
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
