"""r2d2 - Binary analysis copilot."""

from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]

try:  # pragma: no cover - metadata probe
    __version__ = version("r2d2")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.1.0"
