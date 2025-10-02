"""Logging helpers for r2d2."""

from __future__ import annotations

import logging
from typing import Literal

Verbosity = Literal["quiet", "normal", "verbose"]

_LEVEL_BY_VERBOSITY: dict[Verbosity, int] = {
    "quiet": logging.WARNING,
    "normal": logging.INFO,
    "verbose": logging.DEBUG,
}


def configure_logging(verbosity: Verbosity = "normal") -> None:
    """Configure root logging for the CLI session."""

    level = _LEVEL_BY_VERBOSITY.get(verbosity, logging.INFO)
    logging.basicConfig(
        level=level,
        format="[%(levelname).1s] %(message)s",
    )
    logging.debug("Logging configured with level %s", logging.getLevelName(level))
