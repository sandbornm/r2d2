from pathlib import Path

from r2d2.analysis.insights import extract_insights, save_lab_note
from r2d2.analysis.orchestrator import AnalysisPlan, AnalysisResult
from r2d2.analysis.record import AnalysisRecordStore


def _binary(tmp_path: Path, name: str, payload: bytes = b"\x7fELF") -> Path:
    path = tmp_path / name
    path.write_bytes(payload + name.encode() + b"\x00" * 32)
    return path


def _result(binary: Path) -> AnalysisResult:
    return AnalysisResult(
        binary=binary,
        plan=AnalysisPlan(),
        quick_scan={
            "firmware": {"top_level_format": "firmware_container", "container_type": "tp_link_cloud"},
            "radare2": {
                "info": {"bin": {"arch": "arm", "bits": 32}, "core": {"format": "elf"}},
                "imports": [{"name": "strcpy"}, {"name": "system"}],
            },
            "autoprofile": {"profile": {"file_type": "ELF"}},
        },
        deep_scan={
            "radare2": {
                "functions": [{"name": "http_auth", "offset": 0x2000, "size": 64}],
                "entry_function": {"name": "entry0", "offset": 0x1000},
                "entry_disassembly": "0x1000  push {lr}\n",
            }
        },
    )


def test_insights_wait_for_siblings(tmp_path: Path):
    store = AnalysisRecordStore(tmp_path / "artifacts")
    one = _binary(tmp_path, "httpd")
    store.persist(_result(one), binary=one, extra_tags=["httpd"])
    payload = extract_insights(store, tag="httpd")
    assert payload["ready"] is False
    assert payload["patterns"] == []
    assert "two" in (payload["reason"] or "").lower() or "2" in (payload["reason"] or "")


def test_insights_distill_shared_imports_but_not_a_skill(tmp_path: Path):
    store = AnalysisRecordStore(tmp_path / "artifacts")
    first = store.persist(_result(_binary(tmp_path, "httpd-a")), extra_tags=["httpd"])
    store.persist(_result(_binary(tmp_path, "httpd-b")), extra_tags=["httpd"])
    payload = extract_insights(store, focus_id=first["record_id"])
    assert payload["ready"] is True
    assert payload["skill_ready"] is False
    titles = " ".join(pattern["title"] for pattern in payload["patterns"])
    assert "strcpy" in titles or "system" in titles
    assert payload["lab_note"].startswith("# Lab note")
    path = save_lab_note(store, payload)
    assert path.is_file()
    assert "not a skill" in path.read_text().lower()
