"""WSGI/CLI helpers to run the r2d2 web app."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from werkzeug.serving import run_simple

from .app import create_app


def run(config_path: Optional[str] = None) -> None:
    """Start the development web server."""

    resolved_config = Path(config_path).expanduser() if config_path else None
    app = create_app(resolved_config)

    host = os.getenv("R2D2_WEB_HOST", "127.0.0.1")
    port = int(os.getenv("R2D2_WEB_PORT", "5050"))
    debug = os.getenv("R2D2_WEB_DEBUG", "true").lower() == "true"

    run_simple(hostname=host, port=port, application=app, use_debugger=debug, use_reloader=debug)


__all__ = ["run"]
