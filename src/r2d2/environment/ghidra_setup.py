"""Ghidra setup helpers for reproducible local installations."""

from __future__ import annotations

import json
import shutil
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError


GHIDRA_RELEASE_API = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/{tag}"
GHIDRA_TAG_TEMPLATES = ("Ghidra_{version}_build", "Ghidra_{version}")
DEFAULT_GHIDRA_INSTALL_ROOT = Path("~/.local/share/r2d2/tools").expanduser()


class GhidraSetupError(RuntimeError):
    """Raised when a Ghidra setup action cannot be completed."""


@dataclass(slots=True)
class GhidraSetupResult:
    """Result from preparing or installing a Ghidra distribution."""

    archive_url: str | None
    archive_path: Path | None
    install_dir: Path
    headless_path: Path | None
    version: str | None = None
    dry_run: bool = False

    @property
    def env_line(self) -> str:
        return f"export GHIDRA_INSTALL_DIR={self.install_dir}"

    @property
    def ready(self) -> bool:
        return self.headless_path is not None and self.headless_path.exists()


def resolve_ghidra_release_url(version: str) -> str:
    """Resolve a Ghidra version to the official release archive URL.

    Ghidra release asset names include a build date, so constructing a URL from
    the version alone is fragile. Use release metadata instead and ask the user
    for an explicit URL when a tag cannot be resolved.
    """

    errors: list[str] = []
    for tag_template in GHIDRA_TAG_TEMPLATES:
        tag = tag_template.format(version=version)
        request = urllib.request.Request(
            GHIDRA_RELEASE_API.format(tag=tag),
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "r2d2-ghidra-setup",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            errors.append(f"{tag}: {type(exc).__name__}: {exc}")
            continue

        for asset in payload.get("assets", []):
            name = str(asset.get("name", ""))
            url = str(asset.get("browser_download_url", ""))
            if name.startswith(f"ghidra_{version}_PUBLIC") and name.endswith(".zip") and url:
                return url
            if name.startswith("ghidra_") and "_PUBLIC" in name and name.endswith(".zip") and url:
                return url

    detail = "; ".join(errors) if errors else "no matching .zip release asset"
    raise GhidraSetupError(
        f"Could not resolve Ghidra version {version!r} from official releases ({detail}). "
        "Pass --url with an explicit Ghidra archive URL."
    )


def setup_ghidra(
    *,
    version: str | None = None,
    url: str | None = None,
    archive: Path | None = None,
    install_root: Path = DEFAULT_GHIDRA_INSTALL_ROOT,
    force: bool = False,
    dry_run: bool = False,
) -> GhidraSetupResult:
    """Download/extract Ghidra and validate the resulting installation."""

    choices = [value is not None for value in (version, url, archive)]
    if sum(choices) != 1:
        raise GhidraSetupError("Specify exactly one of version, url, or archive.")

    install_root = install_root.expanduser()
    archive_url: str | None = url
    archive_path: Path | None = archive.expanduser() if archive else None
    source_archive_path = archive_path

    if version and not archive_url:
        archive_url = resolve_ghidra_release_url(version)

    if dry_run:
        planned_dir = install_root / _planned_install_name(version=version, url=archive_url, archive=archive_path)
        return GhidraSetupResult(
            archive_url=archive_url,
            archive_path=archive_path,
            install_dir=planned_dir,
            headless_path=planned_dir / "support" / "analyzeHeadless",
            version=version,
            dry_run=True,
        )

    install_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="r2d2-ghidra-") as tmp:
        tmp_path = Path(tmp)
        if archive_path is None:
            assert archive_url is not None
            archive_path = tmp_path / archive_name_from_url(archive_url)
            download_archive(archive_url, archive_path)
        if not archive_path.exists():
            raise GhidraSetupError(f"Archive does not exist: {archive_path}")

        install_dir = extract_ghidra_archive(archive_path, install_root, force=force)
        headless_path = install_dir / "support" / "analyzeHeadless"
        if not headless_path.exists():
            raise GhidraSetupError(f"Installed archive does not contain support/analyzeHeadless: {install_dir}")

        return GhidraSetupResult(
            archive_url=archive_url,
            archive_path=source_archive_path,
            install_dir=install_dir,
            headless_path=headless_path,
            version=version,
        )


def download_archive(url: str, destination: Path) -> None:
    """Download a Ghidra archive to destination."""

    request = urllib.request.Request(url, headers={"User-Agent": "r2d2-ghidra-setup"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            with destination.open("wb") as out:
                shutil.copyfileobj(response, out)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise GhidraSetupError(f"Failed to download {url}: {type(exc).__name__}: {exc}") from exc


def extract_ghidra_archive(archive: Path, install_root: Path, *, force: bool = False) -> Path:
    """Extract a Ghidra zip archive and return its installation directory."""

    if archive.suffix.lower() != ".zip":
        raise GhidraSetupError("Ghidra setup currently supports .zip archives only.")

    with zipfile.ZipFile(archive) as zip_file:
        root_name = _archive_root(zip_file)
        install_dir = install_root / root_name
        if install_dir.exists():
            if not force:
                raise GhidraSetupError(f"Install directory already exists: {install_dir}. Use --force to replace it.")
            shutil.rmtree(install_dir)
        _safe_extract_zip(zip_file, install_root)
    return install_dir


def archive_name_from_url(url: str) -> str:
    name = url.rstrip("/").rsplit("/", 1)[-1]
    if not name or "." not in name:
        return "ghidra.zip"
    return name


def _planned_install_name(*, version: str | None, url: str | None, archive: Path | None) -> str:
    if archive:
        try:
            with zipfile.ZipFile(archive) as zip_file:
                return _archive_root(zip_file)
        except (FileNotFoundError, zipfile.BadZipFile):
            return archive.stem
    if version:
        return f"ghidra_{version}_PUBLIC"
    if url:
        return Path(archive_name_from_url(url)).stem
    return "ghidra"


def _archive_root(zip_file: zipfile.ZipFile) -> str:
    roots: set[str] = set()
    for info in zip_file.infolist():
        path = PurePosixPath(info.filename)
        if path.is_absolute() or ".." in path.parts:
            raise GhidraSetupError(f"Unsafe archive path: {info.filename}")
        if not path.parts:
            continue
        roots.add(path.parts[0])
    if len(roots) != 1:
        raise GhidraSetupError(f"Expected a single top-level directory in archive, found: {sorted(roots)}")
    return next(iter(roots))


def _safe_extract_zip(zip_file: zipfile.ZipFile, destination: Path) -> None:
    destination = destination.resolve()
    for info in zip_file.infolist():
        target = (destination / info.filename).resolve()
        if destination != target and destination not in target.parents:
            raise GhidraSetupError(f"Unsafe archive path: {info.filename}")
    zip_file.extractall(destination)
