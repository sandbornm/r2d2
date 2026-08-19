from pathlib import Path

from r2d2.analysis.insights import extract_insights, save_lab_note
from r2d2.analysis.orchestrator import AnalysisPlan, AnalysisResult
from r2d2.analysis.record import AnalysisRecordStore


def _binary(tmp_path: Path, name: str, payload: bytes = b"\x7fELF") -> Path:
    path = tmp_path / name
    path.write_bytes(payload + name.encode() + b"\x00" * 32)
    return path


def _elf_result(binary: Path) -> AnalysisResult:
    return AnalysisResult(
        binary=binary,
        plan=AnalysisPlan(),
        quick_scan={
            "firmware": {
                "is_elf": True,
                "top_level_format": "elf",
                "container_type": "executable",
            },
            "radare2": {
                "info": {"bin": {"arch": "arm", "bits": 32, "os": "linux"}, "core": {"format": "elf"}},
                "imports": [{"name": "strcpy"}, {"name": "system"}],
            },
            "autoprofile": {"profile": {"file_type": "ELF", "architecture": "arm", "bits": 32}},
        },
        deep_scan={
            "radare2": {
                "functions": [{"name": "http_auth", "offset": 0x2000, "size": 64}],
                "entry_function": {"name": "entry0", "offset": 0x1000},
                "entry_disassembly": "0x1000  push {lr}\n",
            }
        },
    )


def _container_result(binary: Path, *, wrapper: str) -> AnalysisResult:
    names = {
        "safeloader": "TP-Link fwup-ptn",
        "img0": "TP-Link IMG0",
        "cloud": "TP-Link Cloud",
        "ver20": "TP-Link ver. 2.0",
    }
    name = names[wrapper]
    return AnalysisResult(
        binary=binary,
        plan=AnalysisPlan(),
        quick_scan={
            "firmware": {
                "is_elf": False,
                "top_level_format": "firmware_container",
                "container_type": "filesystem_image",
                "wrapper_family": wrapper,
                "embedded_artifacts": [
                    {
                        "kind": "vendor_wrapper",
                        "name": name,
                        "offset": 0x1014,
                        "offset_hex": "0x1014",
                        "recommended": True,
                    },
                    {
                        "kind": "jffs2_marker",
                        "name": "JFFS2 LE",
                        "offset": 0x2000,
                        "offset_hex": "0x2000",
                    },
                ],
                "carved_targets": [],
            },
            "radare2": {"info": {"bin": {}}, "imports": []},
            "autoprofile": {"profile": {"file_type": "data"}},
        },
        deep_scan={},
    )


def _result(binary: Path) -> AnalysisResult:
    return _elf_result(binary)


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
    assert payload["family"]["subject_class"] == "linux_elf"
    assert "unsquash" not in titles.lower()
    actions = " ".join(pattern.get("next_action") or "" for pattern in payload["patterns"]).lower()
    assert "unsquash" not in actions
    assert "wrapper" not in actions


def test_insights_do_not_mix_wrapper_and_elf_under_firmware_tag(tmp_path: Path):
    store = AnalysisRecordStore(tmp_path / "artifacts")
    store.persist(_elf_result(_binary(tmp_path, "flipper.elf")), extra_tags=["firmware", "flipper"])
    a7 = store.persist(
        _container_result(_binary(tmp_path, "a7.bin", payload=b"FW"), wrapper="safeloader"),
        extra_tags=["firmware", "a7"],
    )
    store.persist(
        _container_result(_binary(tmp_path, "eap.bin", payload=b"FW2"), wrapper="safeloader"),
        extra_tags=["firmware", "eap225"],
    )
    payload = extract_insights(store, tag="firmware")
    assert payload["ready"] is True
    assert payload["family"]["subject_class"] == "firmware_container"
    assert payload["family"]["id"] == "safeloader"
    assert payload["sibling_count"] == 2
    classes = {item["subject_class"] for item in payload["families"]}
    assert "linux_elf" in classes or "baremetal_elf" in classes
    actions = " ".join(pattern.get("next_action") or "" for pattern in payload["patterns"]).lower()
    assert "strcpy" not in actions
    assert "brief" in actions or "unpack" in actions or "carve" in actions
    ids = {item["record_id"] for item in payload["siblings"]}
    assert a7["record_id"] in ids


def test_insights_img0_and_safeloader_are_different_families(tmp_path: Path):
    store = AnalysisRecordStore(tmp_path / "artifacts")
    store.persist(_container_result(_binary(tmp_path, "a7.bin", payload=b"A7"), wrapper="safeloader"))
    store.persist(_container_result(_binary(tmp_path, "eap.bin", payload=b"EAP"), wrapper="safeloader"))
    store.persist(_container_result(_binary(tmp_path, "re.bin", payload=b"RE"), wrapper="img0"))
    store.persist(_container_result(_binary(tmp_path, "wa.bin", payload=b"WA"), wrapper="img0"))
    payload = extract_insights(store)
    assert payload["ready"] is True
    family_ids = {item["id"] for item in payload["families"] if item["subject_class"] == "firmware_container"}
    assert family_ids == {"safeloader", "img0"}
    assert payload["sibling_count"] == 2
