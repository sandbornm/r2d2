"""Unit tests for Ghidra setup helpers."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from r2d2.environment.ghidra_setup import (
    GhidraSetupError,
    archive_name_from_url,
    resolve_ghidra_release_url,
    setup_ghidra,
)


def _write_ghidra_zip(path: Path, root: str = "ghidra_11.4.2_PUBLIC") -> None:
    with zipfile.ZipFile(path, "w") as zip_file:
        zip_file.writestr(f"{root}/support/analyzeHeadless", "#!/bin/sh\n")
        zip_file.writestr(f"{root}/ghidraRun", "#!/bin/sh\n")


def test_setup_ghidra_installs_local_archive(tmp_path):
    archive = tmp_path / "ghidra.zip"
    _write_ghidra_zip(archive)

    result = setup_ghidra(archive=archive, install_root=tmp_path / "tools")

    assert result.ready is True
    assert result.install_dir == tmp_path / "tools" / "ghidra_11.4.2_PUBLIC"
    assert result.headless_path == result.install_dir / "support" / "analyzeHeadless"
    assert result.env_line == f"export GHIDRA_INSTALL_DIR={result.install_dir}"


def test_setup_ghidra_dry_run_uses_archive_root(tmp_path):
    archive = tmp_path / "ghidra.zip"
    _write_ghidra_zip(archive, root="ghidra_custom_PUBLIC")

    result = setup_ghidra(archive=archive, install_root=tmp_path / "tools", dry_run=True)

    assert result.dry_run is True
    assert result.install_dir == tmp_path / "tools" / "ghidra_custom_PUBLIC"
    assert result.ready is False


def test_setup_ghidra_rejects_multiple_sources(tmp_path):
    archive = tmp_path / "ghidra.zip"
    _write_ghidra_zip(archive)

    with pytest.raises(GhidraSetupError, match="exactly one"):
        setup_ghidra(version="11.4.2", archive=archive, install_root=tmp_path / "tools")


def test_setup_ghidra_rejects_unsafe_archive_path(tmp_path):
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as zip_file:
        zip_file.writestr("../escape", "bad")

    with pytest.raises(GhidraSetupError, match="Unsafe archive path"):
        setup_ghidra(archive=archive, install_root=tmp_path / "tools")


def test_archive_name_from_url():
    assert archive_name_from_url("https://example.test/releases/ghidra_11.4.2_PUBLIC_20260101.zip") == (
        "ghidra_11.4.2_PUBLIC_20260101.zip"
    )
    assert archive_name_from_url("https://example.test/releases/") == "ghidra.zip"


def test_resolve_ghidra_release_url_from_mocked_metadata(monkeypatch):
    payload = {
        "assets": [
            {
                "name": "ghidra_11.4.2_PUBLIC_20260101.zip",
                "browser_download_url": "https://downloads.example/ghidra.zip",
            }
        ]
    }

    class FakeResponse:
        def __enter__(self):
            return io.BytesIO(json.dumps(payload).encode("utf-8"))

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(request, timeout):  # noqa: ANN001
        assert "Ghidra_11.4.2_build" in request.full_url
        assert timeout == 15
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    assert resolve_ghidra_release_url("11.4.2") == "https://downloads.example/ghidra.zip"
