"""Debug logging module for r2d2 backend.

Provides structured logging for user activity tracking and debugging.
Enabled by default, can be toggled via environment variable or config.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, TypeVar

from flask import Flask, Request, Response, g, request

# Check if debug mode is enabled (default: true)
DEBUG_ENABLED = os.environ.get("R2D2_DEBUG", "true").lower() in ("true", "1", "yes")

# Configure logging
logger = logging.getLogger("r2d2.debug")

# Color codes for terminal output
COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "green": "\033[32m",
    "blue": "\033[34m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "gray": "\033[90m",
}


def colored(text: str, color: str) -> str:
    """Apply color to text if terminal supports it."""
    if not os.isatty(1):  # Check if stdout is a terminal
        return text
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def format_request(req: Request) -> str:
    """Format request info for logging."""
    return f"{req.method} {req.path}"


def format_response_status(status: int) -> str:
    """Format and color response status."""
    if status < 300:
        return colored(str(status), "green")
    elif status < 400:
        return colored(str(status), "yellow")
    else:
        return colored(str(status), "red")


def log_request(category: str, message: str, data: dict[str, Any] | None = None) -> None:
    """Log a debug message with category."""
    if not DEBUG_ENABLED:
        return

    timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    prefix = colored(f"[{timestamp}]", "gray")
    cat = colored(f"[{category.upper()}]", "cyan")

    if data:
        # Format data as compact JSON
        data_str = json.dumps(data, default=str, separators=(",", ":"))
        if len(data_str) > 200:
            data_str = data_str[:200] + "..."
        logger.debug(f"{prefix} {cat} {message} {colored(data_str, 'dim')}")
    else:
        logger.debug(f"{prefix} {cat} {message}")


class DebugLogger:
    """Debug logger for r2d2 backend."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def enable(self) -> None:
        """Enable debug logging."""
        global DEBUG_ENABLED
        DEBUG_ENABLED = True
        self.enabled = True
        logger.info(colored("[r2d2] Debug mode ENABLED", "green"))

    def disable(self) -> None:
        """Disable debug logging."""
        global DEBUG_ENABLED
        DEBUG_ENABLED = False
        self.enabled = False
        logger.info(colored("[r2d2] Debug mode DISABLED", "red"))

    def is_enabled(self) -> bool:
        """Check if debug logging is enabled."""
        return DEBUG_ENABLED and self.enabled

    # API logging
    def api_request(self, method: str, path: str, body: dict[str, Any] | None = None) -> None:
        """Log an API request."""
        log_request("api", f"{colored(method, 'bold')} {path}", body)

    def api_response(self, path: str, status: int, duration_ms: float | None = None) -> None:
        """Log an API response."""
        status_str = format_response_status(status)
        duration_str = f" ({duration_ms:.0f}ms)" if duration_ms else ""
        log_request("api", f"Response {status_str} {path}{duration_str}")

    def api_error(self, path: str, error: str) -> None:
        """Log an API error."""
        log_request("error", f"{colored('ERROR', 'red')} {path}: {error}")

    # Analysis logging
    def analysis_start(self, binary: str, options: dict[str, Any] | None = None) -> None:
        """Log analysis start."""
        log_request("analysis", f"Starting analysis: {binary}", options)

    def analysis_complete(self, binary: str, duration_ms: float | None = None) -> None:
        """Log analysis completion."""
        duration_str = f" ({duration_ms:.0f}ms)" if duration_ms else ""
        log_request("analysis", f"{colored('Complete', 'green')}: {binary}{duration_str}")

    def analysis_error(self, binary: str, error: str) -> None:
        """Log analysis error."""
        log_request("analysis", f"{colored('Failed', 'red')}: {binary} - {error}")

    # Chat logging
    def chat_message(self, session_id: str, role: str, content_preview: str) -> None:
        """Log a chat message."""
        preview = content_preview[:50] + "..." if len(content_preview) > 50 else content_preview
        log_request("chat", f"[{session_id[:8]}] {role}: {preview}")

    def chat_response(self, session_id: str, provider: str | None = None) -> None:
        """Log chat response."""
        provider_str = f" (via {provider})" if provider else ""
        log_request("chat", f"[{session_id[:8]}] Assistant response{provider_str}")

    # Session logging
    def session_create(self, session_id: str, binary_path: str) -> None:
        """Log session creation."""
        log_request("session", f"Created: {session_id[:8]} for {binary_path}")

    def session_load(self, session_id: str) -> None:
        """Log session load."""
        log_request("session", f"Loaded: {session_id[:8]}")

    def session_delete(self, session_id: str) -> None:
        """Log session deletion."""
        log_request("session", f"Deleted: {session_id[:8]}")

    # Function naming logging
    def function_name_suggest(self, session_id: str, count: int) -> None:
        """Log function naming request."""
        log_request("naming", f"[{session_id[:8]}] Suggesting names for {count} functions")

    def function_name_save(self, session_id: str, address: str, name: str) -> None:
        """Log function name save."""
        log_request("naming", f"[{session_id[:8]}] Saved: {address} -> {name}")

    # LLM logging
    def llm_request(self, provider: str, model: str, prompt_preview: str) -> None:
        """Log LLM request."""
        preview = prompt_preview[:50] + "..." if len(prompt_preview) > 50 else prompt_preview
        log_request("llm", f"{provider}/{model}: {preview}")

    def llm_response(self, provider: str, duration_ms: float | None = None) -> None:
        """Log LLM response."""
        duration_str = f" ({duration_ms:.0f}ms)" if duration_ms else ""
        log_request("llm", f"{provider} response{duration_str}")

    # Activity tracking
    def activity_event(self, session_id: str, event_type: str, data: dict[str, Any] | None = None) -> None:
        """Log activity event."""
        log_request("activity", f"[{session_id[:8]}] {event_type}", data)


# Global debug logger instance
debug = DebugLogger()


def setup_flask_debug(app: Flask) -> None:
    """Set up Flask request/response logging."""
    if not DEBUG_ENABLED:
        return

    # Configure logging level
    logging.basicConfig(
        level=logging.DEBUG if DEBUG_ENABLED else logging.INFO,
        format="%(message)s",
    )

    @app.before_request
    def log_request_start() -> None:
        """Log request start and store timing."""
        g.request_start_time = time.time()
        if DEBUG_ENABLED:
            body = None
            if request.content_type == "application/json" and request.data:
                try:
                    body = request.get_json(silent=True)
                except Exception:
                    pass
            debug.api_request(request.method, request.path, body)

    @app.after_request
    def log_request_end(response: Response) -> Response:
        """Log request completion with timing."""
        if DEBUG_ENABLED:
            duration_ms = None
            if hasattr(g, "request_start_time"):
                duration_ms = (time.time() - g.request_start_time) * 1000
            debug.api_response(request.path, response.status_code, duration_ms)
        return response


F = TypeVar("F", bound=Callable[..., Any])


def log_endpoint(category: str = "api") -> Callable[[F], F]:
    """Decorator to log endpoint calls with timing."""

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                log_request(category, f"{func.__name__} completed ({duration_ms:.0f}ms)")
                return result
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                log_request(
                    "error",
                    f"{colored('ERROR', 'red')} {func.__name__} ({duration_ms:.0f}ms): {e}",
                )
                raise

        return wrapper  # type: ignore

    return decorator
