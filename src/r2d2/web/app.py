"""Flask web frontend for r2d2 with progress streaming."""

from __future__ import annotations

import copy
import hashlib
import json
import queue
import threading
import time
import uuid
import zipfile
from dataclasses import asdict
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Optional

from flask import Flask, Response, jsonify, request, send_from_directory
from flask_cors import CORS  # type: ignore[import-untyped]
from werkzeug.exceptions import RequestEntityTooLarge

from ..analysis import AnalysisOrchestrator, AnalysisResult
from ..analysis.investigation_graph import build_investigation_graph
from ..config import AppConfig
from ..environment.detectors import detect_mcp_connections
from ..environment.mcp_launcher import MCPLaunchError, launch_mcp_services
from ..llm import ChatMessage as LLMChatMessage, LLMBridge, LLMError
from ..state import AppState, build_state
from ..storage.chat import ChatDAO
from ..storage.models import AnalysisTrajectory, ChatMessage as StoredChatMessage, ChatSession, TrajectoryAction
from ..tools import (
    GhidraExecutor,
    Radare2Executor,
    ScriptLanguage,
    ScriptValidator,
    ToolName,
)
from ..utils.serialization import to_json
from .debug import debug, setup_flask_debug


class Job:
    def __init__(self, job_id: str) -> None:
        self.id = job_id
        self.queue: "queue.Queue[dict[str, Any]]" = queue.Queue()
        self.status = "queued"
        self.result: AnalysisResult | None = None
        self.error: str | None = None
        self.session_id: str | None = None
        self.binary_path: str | None = None

    def put(self, event: str, data: dict[str, Any] | None = None) -> None:
        payload = {"event": event, "data": data or {}}
        self.queue.put(payload)


class JobRegistry:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def create(self) -> Job:
        job_id = uuid.uuid4().hex
        job = Job(job_id)
        with self._lock:
            self._jobs[job_id] = job
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def remove(self, job_id: str) -> None:
        with self._lock:
            self._jobs.pop(job_id, None)


def _serialize(obj: Any) -> Any:
    try:
        return json.loads(to_json(obj, indent=0))
    except TypeError:
        return obj


def _parse_size_bytes(value: str) -> int:
    text = value.strip().upper()
    multipliers = {
        "B": 1,
        "KB": 1024,
        "KIB": 1024,
        "MB": 1024 * 1024,
        "MIB": 1024 * 1024,
        "GB": 1024 * 1024 * 1024,
        "GIB": 1024 * 1024 * 1024,
    }
    for suffix, multiplier in sorted(multipliers.items(), key=lambda item: len(item[0]), reverse=True):
        if text.endswith(suffix):
            number = text[: -len(suffix)].strip()
            return int(float(number) * multiplier)
    return int(float(text))


def _format_size(size_bytes: int) -> str:
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.0f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.0f} KB"
    return f"{size_bytes} B"


def _analysis_result_cache_key(binary: Path, plan: Any, config: AppConfig) -> str:
    stat = binary.stat()
    fingerprint = {
        "binary": {
            "path": str(binary.resolve()),
            "size": stat.st_size,
            "sha256": _sha256_file(binary),
        },
        "plan": asdict(plan),
        "analysis": {
            "enable_angr": config.analysis.enable_angr,
            "enable_ghidra": config.analysis.enable_ghidra,
            "enable_gef": config.analysis.enable_gef,
            "enable_frida": config.analysis.enable_frida,
            "default_radare_profile": config.analysis.default_radare_profile,
            "timeout_quick": config.analysis.timeout_quick,
            "timeout_deep": config.analysis.timeout_deep,
        },
        "mcp": {
            name: server.enabled
            for name, server in config.mcp.configured_servers().items()
        },
    }
    encoded = json.dumps(fingerprint, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def create_app(config_path: Optional[Path] = None) -> Flask:
    state: AppState = build_state(config_path)
    if state.chat_dao is None:
        raise RuntimeError(
            "Chat storage is not configured; ensure storage.auto_migrate is enabled in config."
        )

    project_root = Path(__file__).resolve().parents[3]
    dist_dir = project_root / "web" / "frontend" / "dist"

    if dist_dir.exists():
        app = Flask(
            __name__,
            static_folder=str(dist_dir),
            template_folder=str(dist_dir),
            static_url_path="",
        )
    else:
        app = Flask(__name__)
    max_upload_bytes = _parse_size_bytes(state.config.analysis.max_binary_size)
    app.config["MAX_CONTENT_LENGTH"] = max_upload_bytes

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error: RequestEntityTooLarge) -> Any:
        return jsonify({"error": f"File exceeds {_format_size(max_upload_bytes)} hard limit"}), 413

    CORS(app)

    # Set up debug logging for Flask
    setup_flask_debug(app)

    def _record_trajectory_action(session_id: str, action: str, payload: dict[str, Any]) -> None:
        if not state.dao:
            return
        session = chat_dao.get_session(session_id)
        if not session or not session.trajectory_id:
            return
        trajectory = AnalysisTrajectory(
            binary_path=session.binary_path,
            trajectory_id=session.trajectory_id,
        )
        state.dao.append_action(trajectory, TrajectoryAction(action=action, payload=payload))

    jobs = JobRegistry()
    chat_dao: ChatDAO = state.chat_dao
    llm_bridge = LLMBridge(state.config)
    tools_status_cache: dict[str, Any] = {
        "payload": None,
        "generated_at": None,
        "expires_at": 0.0,
        "live": False,
    }
    tools_status_lock = threading.Lock()
    compiler_status_cache: dict[str, Any] = {
        "payload": None,
        "generated_at": None,
        "expires_at": 0.0,
        "probing": False,
    }
    compiler_status_lock = threading.Lock()
    analysis_result_cache: dict[str, AnalysisResult] = {}
    analysis_cache_lock = threading.Lock()
    llm_context_cache: dict[str, dict[str, Any]] = {}
    llm_context_cache_lock = threading.Lock()

    def _live_status_requested() -> bool:
        value = (request.args.get("live") or request.args.get("refresh") or "").strip().lower()
        return value in {"1", "true", "yes", "on"}

    def _get_tools_status_cached(state: AppState, *, live: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
        now = time.monotonic()
        with tools_status_lock:
            cached_payload = tools_status_cache.get("payload")
            cached_live = bool(tools_status_cache.get("live"))
            expires_at = float(tools_status_cache.get("expires_at") or 0.0)
            if cached_payload is not None and now < expires_at and (not live or cached_live):
                return cached_payload, {
                    "cached": True,
                    "live": cached_live,
                    "generated_at": tools_status_cache.get("generated_at"),
                }

        tools_status = _attach_live_tool_scorecards(_get_tools_status(state, live=live))
        generated_at = datetime.now(timezone.utc).isoformat()
        ttl_seconds = 3.0 if live else 15.0
        with tools_status_lock:
            tools_status_cache.update({
                "payload": tools_status,
                "generated_at": generated_at,
                "expires_at": time.monotonic() + ttl_seconds,
                "live": live,
            })
        return tools_status, {
            "cached": False,
            "live": live,
            "generated_at": generated_at,
        }

    def _compiler_probing_snapshot() -> dict[str, Any]:
        return {
            "state": "probing",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "compilers": {"arm32": [], "arm64": [], "x86": [], "x86_64": []},
            "available_architectures": [],
            "docker_available": False,
            "docker_image_exists": False,
            "docker": {
                "available": False,
                "image": "r2d2-compiler:latest",
                "image_exists": False,
                "action": "Checking compiler and Docker availability",
            },
            "helpers": {},
            "architectures": {},
            "install_hints": ["Checking compiler support in the background"],
            "errors": [],
        }

    def _refresh_compiler_status() -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            from ..compilation import sniff_compiler_capabilities

            payload = sniff_compiler_capabilities()
        except Exception as exc:  # pragma: no cover - defensive UI fallback
            payload = _compiler_probing_snapshot()
            payload.update({
                "state": "error",
                "errors": [str(exc)],
                "install_hints": ["Compiler support probe failed; check server logs"],
            })

        generated_at = str(payload.get("generated_at") or datetime.now(timezone.utc).isoformat())
        with compiler_status_lock:
            compiler_status_cache.update({
                "payload": payload,
                "generated_at": generated_at,
                "expires_at": time.monotonic() + 30.0,
                "probing": False,
            })
        return payload, {"cached": False, "live": True, "generated_at": generated_at, "probing": False}

    def _start_compiler_status_refresh() -> None:
        with compiler_status_lock:
            if compiler_status_cache.get("probing"):
                return
            compiler_status_cache["probing"] = True

        def _worker() -> None:
            _refresh_compiler_status()

        thread = threading.Thread(target=_worker, name="r2d2-compiler-sniffer", daemon=True)
        thread.start()

    def _get_compiler_status_cached(*, live: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
        if live:
            return _refresh_compiler_status()

        now = time.monotonic()
        with compiler_status_lock:
            cached_payload = compiler_status_cache.get("payload")
            expires_at = float(compiler_status_cache.get("expires_at") or 0.0)
            probing = bool(compiler_status_cache.get("probing"))
            if cached_payload is not None and now < expires_at:
                return cached_payload, {
                    "cached": True,
                    "live": False,
                    "generated_at": compiler_status_cache.get("generated_at"),
                    "probing": probing,
                }

        _start_compiler_status_refresh()
        if cached_payload is not None:
            return cached_payload, {
                "cached": True,
                "live": False,
                "generated_at": compiler_status_cache.get("generated_at"),
                "probing": True,
            }
        return _compiler_probing_snapshot(), {
            "cached": False,
            "live": False,
            "generated_at": None,
            "probing": True,
        }

    def _get_llm_context_cached(
        session: ChatSession,
        *,
        history: list[StoredChatMessage],
        analysis_attachment: dict[str, Any] | None,
        activity_context: list[dict[str, Any]] | None,
        investigation_graph: dict[str, Any] | None,
    ) -> tuple[str | None, dict[str, Any]]:
        if not analysis_attachment:
            return None, {"cached": False, "reason": "no_analysis_attachment"}
        key = _llm_context_cache_key(
            session,
            analysis_attachment=analysis_attachment,
            activity_context=activity_context,
            investigation_graph=investigation_graph,
            config=state.config,
        )
        with llm_context_cache_lock:
            cached = llm_context_cache.get(key)
            if cached:
                return str(cached["context"]), {**cached["meta"], "cached": True}

        built = _build_budgeted_session_context(
            analysis_attachment,
            investigation_graph,
            activity_context,
            config=state.config,
        )
        with llm_context_cache_lock:
            if len(llm_context_cache) >= 32:
                llm_context_cache.pop(next(iter(llm_context_cache)))
            llm_context_cache[key] = built
        return str(built["context"]), {**built["meta"], "cached": False}

    if dist_dir.exists():

        @app.get("/")
        def index() -> Any:  # pragma: no cover - runtime integration
            return send_from_directory(dist_dir, "index.html")

        @app.get("/<path:path>")
        def static_proxy(path: str) -> Any:  # pragma: no cover - runtime integration
            try:
                return send_from_directory(dist_dir, path)
            except FileNotFoundError:
                return send_from_directory(dist_dir, "index.html")

    @app.get("/api/health")
    def health() -> Any:
        tools_status, tools_meta = _get_tools_status_cached(state, live=_live_status_requested())
        
        return jsonify(_serialize({
            "status": "ok",
            "model": llm_bridge.model,
            "provider": llm_bridge.providers[0] if llm_bridge.providers else "anthropic",
            "available_models": llm_bridge.available_models,
            "model_names": llm_bridge.model_display_names,
            "ghidra_ready": bool(state.env.ghidra and state.env.ghidra.is_ready),
            "features": {
                "show_compiler": state.config.ui.show_compiler,
            },
            "tools": tools_status,
            "tools_meta": tools_meta,
        }))

    def _get_tools_status(state: AppState, *, live: bool = False) -> dict[str, Any]:
        """Get detailed status of all analysis tools."""
        import shutil
        import subprocess

        mocked_state = type(state.config).__module__.startswith("unittest.mock")
        config = AppConfig() if mocked_state else state.config
        tools: dict[str, Any] = {}
        
        # Check Python packages
        def check_import(module: str) -> bool:
            try:
                __import__(module)
                return True
            except ImportError:
                return False

        def which_any(*commands: str) -> str | None:
            for command in commands:
                path = shutil.which(command)
                if path:
                    return path
            return None
        
        # Firmware inventory is always available and gives generic firmware
        # blobs a useful graph even when heavyweight analyzers are absent.
        binwalk_path = which_any("binwalk")
        tools["firmware"] = {
            "available": True,
            "binwalk_available": binwalk_path is not None,
            "path": binwalk_path,
            "install_hint": "Optional: brew install binwalk or install sasquatch/unsquashfs for deeper extraction",
            "description": "Firmware signature inventory, carving targets, and fanout planning",
            "details": "Fallback signature scanning is built in; binwalk enables richer extraction hints.",
        }
        tools["binwalk"] = {
            "available": binwalk_path is not None,
            "path": binwalk_path,
            "install_hint": "Optional: brew install binwalk",
            "description": "Firmware analysis and extraction signatures",
        }

        file_path = which_any("file")
        tools["autoprofile"] = {
            "available": file_path is not None,
            "command_available": file_path is not None,
            "path": file_path,
            "install_hint": "Install the file command",
            "description": "Security profile, strings analysis",
        }

        # radare2/r2pipe
        r2_path = which_any("radare2", "r2")
        r2pipe_available = check_import("r2pipe")
        tools["radare2"] = {
            "available": r2_path is not None and r2pipe_available,
            "command_available": r2_path is not None,
            "python_package_available": r2pipe_available,
            "path": r2_path,
            "install_hint": "uv sync --extra analyzers",
            "description": "Disassembly, functions, imports, strings",
            "details": f"command={'yes' if r2_path else 'no'}; r2pipe={'yes' if r2pipe_available else 'no'}",
        }

        rizin_path = which_any("rizin", "rz-bin")
        tools["rizin"] = {
            "available": rizin_path is not None,
            "command_available": rizin_path is not None,
            "path": rizin_path,
            "install_hint": "Optional: brew install rizin",
            "description": "radare-family disassembly alternative",
        }

        # Ollama local model runtime
        ollama_cli_available = shutil.which("ollama") is not None
        ollama_service_available = False
        ollama_models: list[str] = []
        if not mocked_state:
            try:
                response = __import__("httpx").get(
                    f"{config.llm.base_url.rstrip('/')}/api/tags",
                    timeout=1.5 if live else 0.35,
                )
                ollama_service_available = response.status_code == 200
                if ollama_service_available:
                    payload = response.json()
                    models = payload.get("models")
                    if isinstance(models, list):
                        ollama_models = [
                            str(model.get("name") or model.get("model"))
                            for model in models
                            if isinstance(model, dict) and (model.get("name") or model.get("model"))
                        ]
            except Exception:
                ollama_service_available = False
        tools["ollama"] = {
            "available": ollama_cli_available and ollama_service_available and config.llm.model in ollama_models,
            "cli_available": ollama_cli_available,
            "service_available": ollama_service_available,
            "installed_models": ollama_models,
            "selected_model": config.llm.model,
            "selected_model_available": config.llm.model in ollama_models,
            "install_hint": f"Install/start Ollama, then run: ollama pull {config.llm.model}",
            "description": "Local Gemma chat model runtime",
        }
        
        # angr
        angr_available = check_import("angr")
        tools["angr"] = {
            "available": angr_available,
            "python_package_available": angr_available,
            "install_hint": "uv sync --extra analyzers",
            "description": "CFG analysis, symbolic execution",
        }
        
        # Capstone
        capstone_available = check_import("capstone")
        tools["capstone"] = {
            "available": capstone_available,
            "python_package_available": capstone_available,
            "install_hint": "uv sync --extra analyzers",
            "description": "Instruction-level disassembly",
        }

        unicorn_available = check_import("unicorn")
        tools["unicorn"] = {
            "available": unicorn_available,
            "python_package_available": unicorn_available,
            "install_hint": "uv sync --extra analyzers",
            "description": "CPU emulation for isolated dynamic snippets",
        }

        keystone_available = check_import("keystone")
        tools["keystone"] = {
            "available": keystone_available,
            "python_package_available": keystone_available,
            "install_hint": "uv add keystone-engine",
            "description": "Assembler engine for patches and shellcode prototypes",
        }
        
        # python-magic
        magic_available = check_import("magic")
        tools["libmagic"] = {
            "available": magic_available,
            "python_package_available": magic_available,
            "install_hint": "uv sync --extra analyzers; brew install libmagic (macOS)",
            "description": "File type identification",
        }
        
        # Frida
        frida_available = check_import("frida")
        tools["frida"] = {
            "available": frida_available,
            "python_package_available": frida_available,
            "install_hint": "uv sync --extra analyzers",
            "description": "Dynamic instrumentation",
        }
        
        # pyelftools (for DWARF)
        dwarf_available = check_import("elftools")
        tools["pyelftools"] = {
            "available": dwarf_available,
            "python_package_available": dwarf_available,
            "install_hint": "uv sync",
            "description": "ELF and DWARF metadata parsing",
        }
        tools["dwarf"] = {
            "available": dwarf_available,
            "python_package_available": dwarf_available,
            "install_hint": "uv sync --extra analyzers",
            "description": "Debug symbol parsing",
        }

        pefile_available = check_import("pefile")
        tools["pefile"] = {
            "available": pefile_available,
            "python_package_available": pefile_available,
            "install_hint": "uv sync",
            "description": "Windows PE metadata, imports, resources, and sections",
        }

        lief_available = check_import("lief")
        tools["lief"] = {
            "available": lief_available,
            "python_package_available": lief_available,
            "install_hint": "uv add lief",
            "description": "ELF/PE/Mach-O parser and patching library",
        }

        pwntools_available = check_import("pwn")
        tools["pwntools"] = {
            "available": pwntools_available,
            "python_package_available": pwntools_available,
            "install_hint": "uv add pwntools",
            "description": "Exploit development helpers for ELF, ROP, packing, and process I/O",
        }
        
        # GEF/GDB (requires Docker image)
        docker_available = shutil.which("docker") is not None
        gef_image_available = False
        if docker_available and not mocked_state and live:
            try:
                result = subprocess.run(
                    ["docker", "image", "inspect", "r2d2-gef"],
                    capture_output=True,
                    timeout=5,
                )
                gef_image_available = result.returncode == 0
            except Exception:
                pass
        
        tools["gef"] = {
            "available": docker_available and gef_image_available,
            "docker_available": docker_available,
            "image_built": gef_image_available,
            "install_hint": "docker build -t r2d2-gef -f Dockerfile.gef .",
            "description": "Dynamic execution tracing with GDB",
        }

        gdb_path = which_any("gdb")
        tools["gdb"] = {
            "available": gdb_path is not None,
            "path": gdb_path,
            "install_hint": "Install gdb or use the GhidraMCP GDB Docker service on port 5051",
            "description": "GNU debugger for dynamic analysis",
        }
        
        # Ghidra
        ghidra_env = state.env.ghidra
        ghidra_headless_ready = False if mocked_state else (ghidra_env.is_ready if ghidra_env else False)
        ghidra_bridge_ready = False if mocked_state else (ghidra_env.bridge_ready if ghidra_env else False)
        tools["ghidra"] = {
            "available": ghidra_headless_ready or ghidra_bridge_ready,
            "headless_ready": ghidra_headless_ready,
            "headless_available": ghidra_headless_ready,
            "bridge_available": False if mocked_state else (ghidra_env.bridge_available if ghidra_env else False),
            "bridge_connected": False if mocked_state else (ghidra_env.bridge_connected if ghidra_env else False),
            "bridge_program_loaded": None if mocked_state else (ghidra_env.bridge_program_loaded if ghidra_env else None),
            "install_hint": "Set GHIDRA_INSTALL_DIR or start Ghidra Bridge server",
            "description": "Decompilation, type recovery",
        }

        # MCP checks can be slow when services are down. Default calls reuse the
        # startup snapshot; live refreshes update it explicitly.
        if not mocked_state and live:
            state.env.mcp_connections = detect_mcp_connections(config)
        if not mocked_state:
            for name, check in state.env.mcp_connections.items():
                tools[name] = {
                    "available": check.available,
                    "enabled": check.enabled,
                    "transport": check.transport,
                    "url": check.url,
                    "active_url": check.active_url,
                    "command": check.command,
                    "args": check.args,
                    "command_available": check.command_available,
                    "start_command": check.start_command,
                    "working_dir": check.working_dir,
                    "status_code": check.status_code,
                    "capabilities_count": check.capabilities_count,
                    "latency_ms": check.latency_ms,
                    "install_hint": check.install_hint,
                    "description": check.description,
                    "details": check.details,
                }
        return tools

    @app.get("/api/models")
    def list_models() -> Any:
        """List available Claude models."""
        return jsonify({
            "models": llm_bridge.available_models,
            "current": llm_bridge.model,
        })

    @app.post("/api/models")
    def set_model() -> Any:
        """Set the active Claude model."""
        body = request.get_json(silent=True) or {}
        model = body.get("model", "").strip()
        
        if not model:
            return jsonify({"error": "model is required"}), 400
        
        if model not in llm_bridge.available_models:
            return jsonify({
                "error": f"Unknown model: {model}",
                "available": llm_bridge.available_models,
            }), 400
        
        llm_bridge.set_model(model)
        return jsonify({
            "model": llm_bridge.model,
            "available": llm_bridge.available_models,
        })

    @app.get("/api/environment")
    def environment() -> Any:
        return jsonify(_serialize(state.env))

    @app.get("/api/chats")
    def list_chats() -> Any:
        limit_param = request.args.get("limit")
        binary_param = request.args.get("binary")
        try:
            limit = int(limit_param) if limit_param else 20
        except ValueError:
            limit = 20

        if binary_param:
            sessions = chat_dao.list_sessions_for_binary(binary_param)
        else:
            sessions = chat_dao.list_sessions(limit=limit)
        return jsonify([_session_to_dict(session) for session in sessions])

    @app.delete("/api/chats/<session_id>")
    def delete_chat(session_id: str) -> Any:
        session = chat_dao.get_session(session_id)
        if not session:
            return jsonify({"error": "session not found"}), 404
        
        chat_dao.delete_session(session_id)
        return jsonify({"success": True, "session_id": session_id})

    @app.get("/api/chats/<session_id>")
    def chat_detail(session_id: str) -> Any:
        session = chat_dao.get_session(session_id)
        if not session:
            return jsonify({"error": "chat session not found"}), 404
        limit_param = request.args.get("limit")
        try:
            limit = int(limit_param) if limit_param else 250
        except ValueError:
            limit = 250
        messages = chat_dao.list_messages(session.session_id, limit=limit)
        return jsonify({
            "session": _session_to_dict(session),
            "messages": [_message_to_dict(message) for message in messages],
        })

    @app.get("/api/chats/<session_id>/analysis")
    def chat_analysis(session_id: str) -> Any:
        session = chat_dao.get_session(session_id)
        if not session:
            return jsonify({"error": "chat session not found"}), 404
        messages = chat_dao.list_messages(session.session_id, limit=500)
        analysis_attachment = _extract_latest_analysis(messages)
        if not analysis_attachment:
            return jsonify({"error": "analysis result not found for session"}), 404
        return jsonify({
            "session": _session_to_dict(session),
            "analysis": _serialize(analysis_attachment),
        })

    @app.get("/api/chats/<session_id>/graphs")
    def chat_graphs(session_id: str) -> Any:
        session = chat_dao.get_session(session_id)
        if not session:
            return jsonify({"error": "chat session not found"}), 404
        messages = chat_dao.list_messages(session.session_id, limit=500)
        analysis_attachment = _extract_latest_analysis(messages) or {}
        return jsonify(
            {
                "analysis_graph": analysis_attachment.get("analysis_graph"),
                "investigation_graph": _build_investigation_graph_for_session(
                    session,
                    messages=messages,
                    state=state,
                ),
            }
        )

    @app.get("/api/chats/<session_id>/bundle")
    def chat_bundle(session_id: str) -> Any:
        session = chat_dao.get_session(session_id)
        if not session:
            return jsonify({"error": "chat session not found"}), 404

        include_raw = str(request.args.get("include_raw", "")).lower() in {"1", "true", "yes", "on"}
        messages = chat_dao.list_messages(session.session_id, limit=500)
        bundle = _build_analysis_bundle(
            session,
            messages=messages,
            state=state,
            include_raw=include_raw,
        )
        if not bundle:
            return jsonify({"error": "analysis result not found for session"}), 404

        output_format = str(request.args.get("format", "json")).lower()
        if output_format in {"md", "markdown"}:
            filename = f"{Path(session.binary_path).stem or session.session_id}-r2d2-report.md"
            return Response(
                bundle["report_markdown"],
                mimetype="text/markdown",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        if output_format in {"manifest", "artifacts"}:
            return jsonify(bundle["manifest"])
        if output_format in {"zip", "archive"}:
            include_binary = str(request.args.get("include_binary", "")).lower() in {"1", "true", "yes", "on"}
            archive = _render_analysis_bundle_zip(bundle, state=state, include_binary=include_binary)
            filename = f"{Path(session.binary_path).stem or session.session_id}-r2d2-session.zip"
            return Response(
                archive.getvalue(),
                mimetype="application/zip",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )

        return jsonify(bundle)

    @app.post("/api/chats/<session_id>/messages")
    def post_chat_message(session_id: str) -> Any:
        session = chat_dao.get_session(session_id)
        if not session:
            return jsonify({"error": "chat session not found"}), 404

        body = request.get_json(silent=True) or {}
        content = (body.get("content") or "").strip()
        attachments = body.get("attachments") or []
        call_llm = bool(body.get("call_llm"))

        debug.chat_message(session_id, "user", content)

        if not content and not attachments:
            return jsonify({"error": "Message content or attachments required"}), 400

        if not isinstance(attachments, list):
            return jsonify({"error": "attachments must be a list"}), 400

        user_message = chat_dao.append_message(session.session_id, "user", content, attachments=attachments)

        response_payload: dict[str, Any] = {
            "session": _session_to_dict(chat_dao.get_session(session.session_id) or session),
            "messages": [_message_to_dict(message) for message in chat_dao.list_messages(session.session_id)],
        }

        if call_llm:
            history = chat_dao.list_messages(session.session_id)
            analysis_attachment = _extract_latest_analysis(history)
            
            # Fetch recent activity context
            activity_context = _get_activity_context(state.db, session.session_id) if state.db else None
            
            investigation_graph = _build_investigation_graph_for_session(
                session,
                messages=history,
                state=state,
            )
            session_context, context_meta = _get_llm_context_cached(
                session,
                history=history,
                analysis_attachment=analysis_attachment,
                activity_context=activity_context,
                investigation_graph=investigation_graph,
            )
            llm_messages = _build_llm_messages(
                history,
                analysis_attachment,
                activity_context,
                config=state.config,
                investigation_graph=investigation_graph,
                prebuilt_context=session_context,
            )
            try:
                assistant_response = llm_bridge.chat(llm_messages)
            except LLMError as exc:
                response_payload["error"] = str(exc)
                response_payload["messages"] = [
                    _message_to_dict(message) for message in chat_dao.list_messages(session.session_id)
                ]
                return jsonify(response_payload), 503

            metadata_attachment = [{
                "type": "llm_response_meta",
                "provider": llm_bridge.last_provider,
                "context": context_meta,
            }]

            assistant_message = chat_dao.append_message(
                session.session_id,
                "assistant",
                assistant_response,
                attachments=metadata_attachment,
            )
            debug.chat_response(session_id, llm_bridge.last_provider)
            response_payload["provider"] = llm_bridge.last_provider
            response_payload["assistant"] = _message_to_dict(assistant_message)
            response_payload["messages"] = [
                _message_to_dict(message) for message in chat_dao.list_messages(session.session_id)
            ]

        response_payload["messages"] = [
            _message_to_dict(message) for message in chat_dao.list_messages(session.session_id)
        ]
        response_payload["message"] = _message_to_dict(user_message)
        return jsonify(response_payload)

    # ──────────────────────────────────────────────────────────────────────────
    # Annotation endpoints
    # ──────────────────────────────────────────────────────────────────────────
    
    @app.get("/api/chats/<session_id>/annotations")
    def list_annotations(session_id: str) -> Any:
        """List all annotations for a session."""
        if not state.db:
            return jsonify({"annotations": []})  # No database configured
            
        session = chat_dao.get_session(session_id)
        if not session:
            return jsonify({"error": "session not found"}), 404
        
        with state.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT annotation_id, address, note, created_at, updated_at
                FROM annotations
                WHERE session_id = ?
                ORDER BY address
                """,
                (session_id,),
            ).fetchall()
        
        annotations = [
            {
                "id": row["annotation_id"],
                "address": row["address"],
                "note": row["note"],
                "createdAt": row["created_at"],
                "updatedAt": row["updated_at"],
            }
            for row in rows
        ]
        return jsonify({"annotations": annotations})

    @app.post("/api/chats/<session_id>/annotations")
    def upsert_annotation(session_id: str) -> Any:
        """Create or update an annotation for a session."""
        if not state.db:
            return jsonify({"error": "database not configured"}), 503
            
        session = chat_dao.get_session(session_id)
        if not session:
            return jsonify({"error": "session not found"}), 404
        
        body = request.get_json(silent=True) or {}
        address = body.get("address", "").strip()
        note = body.get("note", "").strip()
        
        if not address:
            return jsonify({"error": "address is required"}), 400
        
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        
        with state.db.connect() as conn:
            if note:
                # Upsert annotation
                annotation_id = f"{session_id}-{address}"
                conn.execute(
                    """
                    INSERT INTO annotations (annotation_id, session_id, binary_path, address, note, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (session_id, address) DO UPDATE SET
                        note = excluded.note,
                        updated_at = excluded.updated_at
                    """,
                    (annotation_id, session_id, session.binary_path, address, note, now, now),
                )
                return jsonify({
                    "id": annotation_id,
                    "address": address,
                    "note": note,
                    "createdAt": now,
                    "updatedAt": now,
                })
            else:
                # Delete annotation if note is empty
                conn.execute(
                    "DELETE FROM annotations WHERE session_id = ? AND address = ?",
                    (session_id, address),
                )
                return jsonify({"deleted": True, "address": address})

    @app.delete("/api/chats/<session_id>/annotations/<address>")
    def delete_annotation(session_id: str, address: str) -> Any:
        """Delete an annotation."""
        if not state.db:
            return jsonify({"error": "database not configured"}), 503
            
        session = chat_dao.get_session(session_id)
        if not session:
            return jsonify({"error": "session not found"}), 404
        
        with state.db.connect() as conn:
            conn.execute(
                "DELETE FROM annotations WHERE session_id = ? AND address = ?",
                (session_id, address),
            )
        
        return jsonify({"deleted": True, "address": address})

    # ──────────────────────────────────────────────────────────────────────────
    # Activity tracking endpoints for context engineering
    # ──────────────────────────────────────────────────────────────────────────
    
    @app.post("/api/chats/<session_id>/activities")
    def track_activities(session_id: str) -> Any:
        """Record user activity events for session trajectory and LLM context."""
        if not state.db:
            return jsonify({"error": "database not configured"}), 503
            
        session = chat_dao.get_session(session_id)
        if not session:
            return jsonify({"error": "session not found"}), 404
        
        body = request.get_json(silent=True) or {}
        events = body.get("events", [])
        
        if not isinstance(events, list):
            return jsonify({"error": "events must be a list"}), 400
        
        with state.db.connect() as conn:
            for event in events:
                if not isinstance(event, dict):
                    continue
                event_type = event.get("event_type", "unknown")
                event_data = event.get("event_data", {})
                created_at = event.get("created_at") or datetime.now(timezone.utc).isoformat()
                event_id = f"{session_id}-{uuid.uuid4().hex[:8]}"
                
                conn.execute(
                    """
                    INSERT INTO activity_events (event_id, session_id, event_type, event_data, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (event_id, session_id, event_type, json.dumps(event_data), created_at),
                )
        
        return jsonify({"recorded": len(events)})

    @app.get("/api/chats/<session_id>/activities")
    def list_activities(session_id: str) -> Any:
        """Get recent activity events for a session."""
        if not state.db:
            return jsonify({"activities": []})
            
        session = chat_dao.get_session(session_id)
        if not session:
            return jsonify({"error": "session not found"}), 404
        
        limit_param = request.args.get("limit")
        try:
            limit = int(limit_param) if limit_param else 50
        except ValueError:
            limit = 50
        
        with state.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT event_id, event_type, event_data, created_at
                FROM activity_events
                WHERE session_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
        
        activities = []
        for row in rows:
            try:
                event_data = json.loads(row["event_data"]) if row["event_data"] else {}
            except json.JSONDecodeError:
                event_data = {}
            activities.append({
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "event_data": event_data,
                "created_at": row["created_at"],
            })
        
        return jsonify({"activities": activities})

    # ──────────────────────────────────────────────────────────────────────────
    # Function naming endpoints
    # ──────────────────────────────────────────────────────────────────────────

    @app.get("/api/chats/<session_id>/function-names")
    def list_function_names(session_id: str) -> Any:
        """List all custom function names for a session."""
        if not state.db:
            return jsonify({"function_names": []})

        session = chat_dao.get_session(session_id)
        if not session:
            return jsonify({"error": "session not found"}), 404

        with state.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, address, original_name, display_name, reasoning, confidence, source, created_at, updated_at
                FROM function_names
                WHERE session_id = ?
                ORDER BY address
                """,
                (session_id,),
            ).fetchall()

        function_names = [
            {
                "id": row["id"],
                "address": row["address"],
                "originalName": row["original_name"],
                "displayName": row["display_name"],
                "reasoning": row["reasoning"],
                "confidence": row["confidence"],
                "source": row["source"],
                "createdAt": row["created_at"],
                "updatedAt": row["updated_at"],
            }
            for row in rows
        ]
        return jsonify({"function_names": function_names})

    @app.post("/api/chats/<session_id>/function-names")
    def upsert_function_name(session_id: str) -> Any:
        """Create or update a function name for a session."""
        if not state.db:
            return jsonify({"error": "database not configured"}), 503

        session = chat_dao.get_session(session_id)
        if not session:
            return jsonify({"error": "session not found"}), 404

        body = request.get_json(silent=True) or {}
        address = body.get("address", "").strip()
        original_name = body.get("originalName", "").strip()
        display_name = body.get("displayName", "").strip()
        reasoning = body.get("reasoning", "")
        confidence = body.get("confidence")
        source = body.get("source", "user")  # "user" or "llm"

        if not address:
            return jsonify({"error": "address is required"}), 400
        if not display_name:
            return jsonify({"error": "displayName is required"}), 400

        now = datetime.now(timezone.utc).isoformat()
        fn_id = f"{session_id}-{address}"

        with state.db.connect() as conn:
            conn.execute(
                """
                INSERT INTO function_names (id, session_id, address, original_name, display_name, reasoning, confidence, source, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (session_id, address) DO UPDATE SET
                    display_name = excluded.display_name,
                    reasoning = excluded.reasoning,
                    confidence = excluded.confidence,
                    source = excluded.source,
                    updated_at = excluded.updated_at
                """,
                (fn_id, session_id, address, original_name, display_name, reasoning, confidence, source, now, now),
            )

        return jsonify({
            "id": fn_id,
            "address": address,
            "originalName": original_name,
            "displayName": display_name,
            "reasoning": reasoning,
            "confidence": confidence,
            "source": source,
            "createdAt": now,
            "updatedAt": now,
        })

    @app.delete("/api/chats/<session_id>/function-names/<address>")
    def delete_function_name(session_id: str, address: str) -> Any:
        """Delete a function name."""
        if not state.db:
            return jsonify({"error": "database not configured"}), 503

        session = chat_dao.get_session(session_id)
        if not session:
            return jsonify({"error": "session not found"}), 404

        with state.db.connect() as conn:
            conn.execute(
                "DELETE FROM function_names WHERE session_id = ? AND address = ?",
                (session_id, address),
            )

        return jsonify({"deleted": True, "address": address})

    @app.post("/api/functions/suggest-names")
    def suggest_function_names() -> Any:
        """Use LLM to suggest names for functions with generic names."""
        body = request.get_json(silent=True) or {}
        session_id = body.get("session_id")
        functions = body.get("functions", [])  # List of function dicts with address, name, blocks

        debug.function_name_suggest(session_id or "unknown", len(functions))

        if not session_id:
            return jsonify({"error": "session_id is required"}), 400

        session = chat_dao.get_session(session_id)
        if not session:
            return jsonify({"error": "session not found"}), 404

        if not functions:
            return jsonify({"error": "functions list is required"}), 400

        # Filter to only functions with generic names
        import re
        generic_pattern = re.compile(r"^(sub_|fcn\.|func_|FUN_)[0-9a-fA-F]+$", re.IGNORECASE)
        generic_functions = [
            f for f in functions
            if isinstance(f, dict) and generic_pattern.match(f.get("name", ""))
        ]

        if not generic_functions:
            return jsonify({"suggestions": [], "message": "No generic function names found"})

        # Limit to first 10 functions to avoid too large LLM request
        generic_functions = generic_functions[:10]

        # Build LLM prompt
        prompt_parts = [
            "Analyze these assembly functions and suggest meaningful names based on their behavior.",
            "For each function, provide:",
            "1. A concise, descriptive name (snake_case, no prefix)",
            "2. A confidence level (high/medium/low)",
            "3. Brief reasoning (1 sentence)",
            "",
            "Respond in JSON format:",
            '{"suggestions": [{"address": "0x...", "name": "suggested_name", "confidence": "high|medium|low", "reasoning": "why"}]}',
            "",
            "Functions to analyze:",
        ]

        for func in generic_functions:
            prompt_parts.append(f"\n## Function: {func.get('name', '?')} at {func.get('address', '?')}")
            blocks = func.get("blocks", [])
            if blocks:
                for i, block in enumerate(blocks[:3]):  # First 3 blocks
                    prompt_parts.append(f"### Block {i + 1} at {block.get('offset', '?')}:")
                    disasm = block.get("disassembly", [])
                    for instr in disasm[:10]:  # First 10 instructions per block
                        addr = instr.get("addr", "")
                        opcode = instr.get("opcode", "")
                        prompt_parts.append(f"  {addr}  {opcode}")
            else:
                prompt_parts.append("  (no block disassembly available)")

        prompt = "\n".join(prompt_parts)

        # Call LLM
        try:
            llm_messages = [
                LLMChatMessage(role="system", content="You are an expert reverse engineer. Analyze assembly code and suggest meaningful function names. Always respond with valid JSON."),
                LLMChatMessage(role="user", content=prompt),
            ]
            response = llm_bridge.chat(llm_messages)

            # Parse JSON response
            # Try to extract JSON from the response (it might have markdown code blocks)
            json_match = re.search(r"\{[\s\S]*\}", response)
            if json_match:
                result = json.loads(json_match.group())
                suggestions = result.get("suggestions", [])

                # Map confidence strings to floats
                confidence_map = {"high": 0.9, "medium": 0.7, "low": 0.5}
                for s in suggestions:
                    conf = s.get("confidence", "medium")
                    if isinstance(conf, str):
                        s["confidence"] = confidence_map.get(conf.lower(), 0.7)

                return jsonify({"suggestions": suggestions, "provider": llm_bridge.last_provider})
            else:
                return jsonify({"error": "Could not parse LLM response", "raw_response": response}), 500

        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    # Ensure uploads directory exists
    uploads_dir = Path(state.config.output.artifacts_dir).expanduser() / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)

    @app.post("/api/upload")
    def upload_binary() -> Any:
        """Handle binary file uploads and return the server path."""
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]
        if not file.filename:
            return jsonify({"error": "No filename provided"}), 400

        # Sanitize filename and save
        from werkzeug.utils import secure_filename
        filename = secure_filename(file.filename)
        if not filename:
            filename = f"binary_{uuid.uuid4().hex[:8]}"

        save_path = uploads_dir / filename
        # Add suffix if file exists
        counter = 1
        original_stem = save_path.stem
        while save_path.exists():
            save_path = uploads_dir / f"{original_stem}_{counter}{save_path.suffix}"
            counter += 1

        file.save(str(save_path))
        size_bytes = save_path.stat().st_size
        if size_bytes > max_upload_bytes:
            save_path.unlink(missing_ok=True)
            return jsonify({"error": f"File exceeds {_format_size(max_upload_bytes)} hard limit"}), 413
        return jsonify({
            "path": str(save_path),
            "filename": save_path.name,
            "size_bytes": size_bytes,
            "max_size_bytes": max_upload_bytes,
        })

    @app.post("/api/analyze")
    def analyze() -> Any:
        body = request.get_json(silent=True) or {}
        binary_path = body.get("binary")
        user_goal = body.get("user_goal", "").strip()
        quick_only = bool(body.get("quick_only", False))
        analysis_profile = str(body.get("analysis_profile") or ("triage" if quick_only else "standard")).strip().lower()
        if analysis_profile not in {"triage", "standard", "exhaustive"}:
            analysis_profile = "standard"
        if analysis_profile == "triage":
            quick_only = True
        elif analysis_profile == "exhaustive":
            quick_only = False

        enable_angr = bool(body.get("enable_angr", True))
        enable_ghidra = bool(body.get("enable_ghidra", True))
        enable_gef = bool(body.get("enable_gef", True))
        enable_frida = bool(body.get("enable_frida", True))
        if analysis_profile == "exhaustive":
            enable_angr = True
            enable_ghidra = True
            enable_gef = True
            enable_frida = True

        debug.analysis_start(binary_path or "unknown", {
            "analysis_profile": analysis_profile,
            "quick_only": quick_only,
            "enable_angr": enable_angr,
            "enable_ghidra": enable_ghidra,
            "enable_gef": enable_gef,
            "enable_frida": enable_frida,
            "user_goal": user_goal[:50] if user_goal else None,
        })

        if not binary_path:
            return jsonify({"error": "Missing 'binary' in request body"}), 400

        path = Path(binary_path)
        if not path.exists():
            return jsonify({"error": f"Binary path does not exist: {binary_path}"}), 404

        session = chat_dao.get_or_create_session(str(path), title=path.name)
        debug.session_create(session.session_id, str(path))
        
        # Store user goal in session metadata
        if user_goal:
            chat_dao.append_message(
                session.session_id,
                "system",
                f"User goal: {user_goal}",
                attachments=[{"type": "user_goal", "goal": user_goal}],
            )

        job = jobs.create()
        job.status = "running"
        job.session_id = session.session_id
        job.binary_path = str(path)

        def _progress(event: str, payload: dict[str, Any] | None) -> None:
            data = dict(payload or {})
            if job.session_id:
                data.setdefault("session_id", job.session_id)
            job.put(event, data)

        def _worker() -> None:
            job.put("job_started", {"binary": str(path), "session_id": job.session_id})
            try:
                # Override config settings based on frontend request
                request_config = state.config.model_copy(deep=True)
                request_config.analysis.enable_angr = enable_angr
                request_config.analysis.enable_ghidra = enable_ghidra
                request_config.analysis.enable_gef = enable_gef
                request_config.analysis.enable_frida = enable_frida
                
                orchestrator = AnalysisOrchestrator(request_config, state.env, trajectory_dao=state.dao)
                # Create custom analysis plan respecting frontend settings
                plan = orchestrator.create_plan(quick_only=quick_only, profile=analysis_profile)
                plan.run_angr = enable_angr and plan.deep
                cache_key = _analysis_result_cache_key(path, plan, request_config)
                result: AnalysisResult | None = None
                if request_config.performance.cache_results:
                    with analysis_cache_lock:
                        cached_result = analysis_result_cache.get(cache_key)
                    if cached_result:
                        result = copy.deepcopy(cached_result)
                        result.notes.append("analysis result restored from in-process cache")
                        job.put(
                            "analysis_cache_hit",
                            {"binary": str(path), "session_id": job.session_id, "profile": plan.profile},
                        )
                if result is None:
                    result = orchestrator.analyze(path, plan=plan, progress_callback=_progress)
                    if request_config.performance.cache_results:
                        with analysis_cache_lock:
                            if len(analysis_result_cache) >= 12:
                                analysis_result_cache.pop(next(iter(analysis_result_cache)))
                            analysis_result_cache[cache_key] = copy.deepcopy(result)
                job.result = result
                job.status = "completed"

                updated_session = chat_dao.get_or_create_session(
                    str(path),
                    trajectory_id=result.trajectory_id,
                    title=path.name,
                )
                job.session_id = updated_session.session_id

                # Extract snippets from analysis results for session persistence
                snippets = _extract_snippets(result.deep_scan)
                tool_scorecard = _build_analysis_tool_scorecard(
                    result.tool_status,
                    result.tool_availability,
                    result.evidence_coverage,
                )
                
                analysis_attachment = {
                    "type": "analysis_result",
                    "binary": str(result.binary),
                    "plan": asdict(result.plan),
                    "quick_scan": result.quick_scan,
                    "deep_scan": result.deep_scan,
                    "notes": result.notes,
                    "issues": result.issues,
                    "trajectory_id": result.trajectory_id,
                    "snippets": snippets,
                    "snippet_count": len(snippets),
                    "tool_availability": result.tool_availability,
                    "tool_status": result.tool_status,
                    "tool_scorecard": tool_scorecard,
                    "evidence_coverage": result.evidence_coverage,
                    "analysis_graph": result.analysis_graph,
                }
                chat_dao.append_message(
                    updated_session.session_id,
                    "system",
                    f"Analysis completed for {path.name}",
                    attachments=[analysis_attachment],
                )

                payload = _serialize(result)
                if isinstance(payload, dict):
                    payload["session_id"] = updated_session.session_id
                else:
                    payload = {"result": payload, "session_id": updated_session.session_id}
                payload["trajectory_id"] = result.trajectory_id
                payload["analysis_graph"] = result.analysis_graph
                payload["tool_scorecard"] = tool_scorecard
                job.put("analysis_result", payload)
                job.put(
                    "job_completed",
                    {
                        "issues": result.issues,
                        "notes": result.notes,
                        "session_id": updated_session.session_id,
                        "trajectory_id": result.trajectory_id,
                    },
                )
            except Exception as exc:  # pragma: no cover - defensive
                job.error = str(exc)
                job.status = "failed"
                error_payload = {"error": str(exc)}
                if job.session_id:
                    error_payload["session_id"] = job.session_id
                job.put("job_failed", error_payload)
            finally:
                job.put("__close__")

        thread = threading.Thread(target=_worker, name=f"job-{job.id}", daemon=True)
        thread.start()

        return jsonify({"job_id": job.id, "session_id": session.session_id})

    @app.get("/api/jobs/<job_id>/stream")
    def stream(job_id: str) -> Response | tuple[Response, int]:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"error": "job not found"}), 404

        def _event_stream() -> Any:
            while True:
                item = job.queue.get()
                event = item.get("event")
                if event == "__close__":
                    jobs.remove(job.id)
                    break
                data = item.get("data", {})
                if job.session_id and isinstance(data, dict):
                    data.setdefault("session_id", job.session_id)
                yield f"event: {event}\n"
                yield f"data: {json.dumps(data)}\n\n"

        return Response(_event_stream(), mimetype="text/event-stream")

    # ──────────────────────────────────────────────────────────────────────────
    # Compilation endpoints
    # ──────────────────────────────────────────────────────────────────────────

    @app.get("/api/compilers")
    def list_compilers() -> Any:
        """List compiler capabilities and background probe status."""
        snapshot, meta = _get_compiler_status_cached(live=_live_status_requested())
        return jsonify(_serialize({**snapshot, "meta": meta}))

    @app.post("/api/compilers/preview")
    def preview_compile_command() -> Any:
        """Preview the compilation command that would run."""
        try:
            from ..compilation import preview_compile_with_capabilities

            body = request.get_json(silent=True) or {}
            
            architecture = body.get("architecture", "arm64")
            optimization = body.get("optimization", "-O0")
            freestanding = body.get("freestanding", False)
            output_name = body.get("output_name", "output")
            
            preview = preview_compile_with_capabilities(
                architecture=architecture,
                optimization=optimization,
                freestanding=freestanding,
                output_name=output_name or "output",
            )
            return jsonify(preview)
        except ImportError:
            return jsonify({
                "command": "",
                "uses_docker": False,
                "compiler": "none",
                "available": False,
                "error": "Compilation module not available",
            })

    @app.post("/api/compile")
    def compile_source() -> Any:
        """Compile C source or assemble ASM source."""
        body = request.get_json(silent=True) or {}
        source_code = body.get("source", "").strip()
        source_path = body.get("source_path", "").strip()
        architecture = body.get("architecture", "arm64")
        source_type = body.get("type", "c")  # "c" or "asm"
        optimization = body.get("optimization", "-O0")
        output_name = body.get("output_name", "")
        freestanding = body.get("freestanding", False)  # No libc mode
        emit_asm = body.get("emit_asm", True)  # Also generate .s file

        if not source_code and not source_path:
            return jsonify({"error": "Either 'source' or 'source_path' required"}), 400

        try:
            from ..compilation import compile_c_source, assemble_source, compile_to_asm

            # Determine source
            if source_path:
                source = Path(source_path)
                if not source.exists():
                    return jsonify({"error": f"Source file not found: {source_path}"}), 404
            else:
                source = source_code

            # Determine output path
            output = None
            if output_name:
                # Strip extension if provided, we'll add the right one
                base_name = output_name.rsplit('.', 1)[0] if '.' in output_name else output_name
                output = uploads_dir / base_name

            # Build extra flags for freestanding mode
            # Use -nostartfiles to avoid crt1.o conflict when code defines _start
            extra_flags = []
            if freestanding:
                extra_flags = ["-ffreestanding", "-nostartfiles", "-nodefaultlibs", "-static"]

            # First, generate assembly if requested
            asm_output = None
            asm_path = None
            if emit_asm and source_type == "c":
                asm_result = compile_to_asm(source, architecture, optimization, extra_flags)
                if asm_result.success and asm_result.assembly:
                    asm_output = asm_result.assembly
                    # Save .s file
                    asm_filename = (output.stem if output else "output") + ".s"
                    asm_path = uploads_dir / asm_filename
                    asm_path.write_text(asm_output)

            # Compile or assemble
            if source_type == "asm":
                result = assemble_source(source, architecture, output)
            else:
                result = compile_c_source(source, architecture, output, optimization, extra_flags)

            response = {
                "success": result.success,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": result.command,
                "return_code": result.return_code,
                "architecture": result.architecture,
                "compiler": result.compiler_used,
            }

            if result.success and result.output_path:
                response["output_path"] = str(result.output_path)
                response["output_name"] = result.output_path.name

            # Include assembly output
            if asm_output:
                response["assembly"] = asm_output
                if asm_path:
                    response["asm_path"] = str(asm_path)
                    response["asm_name"] = asm_path.name

            return jsonify(response), 200 if result.success else 400

        except ImportError:
            return jsonify({"error": "Compilation module not available"}), 503

    @app.post("/api/compile/modified-asm")
    def compile_modified_asm() -> Any:
        """Compile modified assembly back to binary.

        This endpoint allows re-assembling modified disassembly output.
        """
        body = request.get_json(silent=True) or {}
        asm_source = body.get("asm", "").strip()
        body.get("original_binary", "").strip()
        architecture = body.get("architecture", "arm64")

        if not asm_source:
            return jsonify({"error": "Assembly source required"}), 400

        try:
            from ..compilation import assemble_source

            # Create output in uploads directory
            import hashlib
            hash_suffix = hashlib.md5(asm_source.encode()).hexdigest()[:8]
            output_name = f"modified_{hash_suffix}.o"
            output = uploads_dir / output_name

            result = assemble_source(asm_source, architecture, output)

            response = {
                "success": result.success,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "command": result.command,
                "return_code": result.return_code,
                "architecture": result.architecture,
            }

            if result.success and result.output_path:
                response["output_path"] = str(result.output_path)

            return jsonify(response), 200 if result.success else 400

        except ImportError:
            return jsonify({"error": "Compilation module not available"}), 503

    @app.get("/api/compile/download/<path:filename>")
    def download_compiled(filename: str) -> Any:
        """Download a compiled binary file."""
        from werkzeug.utils import secure_filename
        
        # Security: ensure filename is safe
        safe_name = secure_filename(filename)
        if not safe_name:
            return jsonify({"error": "Invalid filename"}), 400
        
        file_path = uploads_dir / safe_name
        if not file_path.exists():
            return jsonify({"error": "File not found"}), 404
        
        # Serve the file for download
        return send_from_directory(
            uploads_dir,
            safe_name,
            as_attachment=True,
            download_name=safe_name,
        )

    @app.get("/api/compile/listing/<path:filename>")
    def get_binary_listing(filename: str) -> Any:
        """Get objdump-style disassembly listing for a compiled binary.
        
        Returns structured listing with address, bytes, and instruction for each line.
        This is the typical binary view in tools like Ghidra, OFRAK, and angr.
        """
        import subprocess
        from werkzeug.utils import secure_filename
        
        safe_name = secure_filename(filename)
        if not safe_name:
            return jsonify({"error": "Invalid filename"}), 400
        
        file_path = uploads_dir / safe_name
        if not file_path.exists():
            return jsonify({"error": "File not found"}), 404
        
        # Determine architecture and pick appropriate objdump
        # Try to detect from filename or use default
        arch = "aarch64" if "arm64" in filename.lower() or "aarch64" in filename.lower() else "arm"
        
        # Try Docker objdump first (for cross-arch), then native
        listing_lines: list[dict[str, Any]] = []
        raw_output = ""
        
        try:
            # Use Docker container for cross-arch objdump
            objdump_cmd = "aarch64-linux-gnu-objdump" if arch == "aarch64" else "arm-linux-gnueabihf-objdump"
            docker_cmd = [
                "docker", "run", "--rm",
                "-v", f"{file_path.parent}:/data:ro",
                "-w", "/data",
                "r2d2-compiler:latest",
                "-c", f"{objdump_cmd} -d -w /data/{safe_name}"
            ]
            
            result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=30)
            raw_output = result.stdout
            
            if result.returncode != 0:
                # Fallback to native objdump
                native_result = subprocess.run(
                    ["objdump", "-d", "-w", str(file_path)],
                    capture_output=True, text=True, timeout=30
                )
                raw_output = native_result.stdout
        except Exception:
            # Try native objdump as last resort
            try:
                native_result = subprocess.run(
                    ["objdump", "-d", "-w", str(file_path)],
                    capture_output=True, text=True, timeout=30
                )
                raw_output = native_result.stdout
            except Exception as e:
                return jsonify({"error": f"Failed to disassemble: {e}"}), 500
        
        # Parse objdump output into structured format
        current_section = ""
        current_function = ""
        
        for line in raw_output.split("\n"):
            line = line.rstrip()
            
            # Section header (e.g., "Disassembly of section .text:")
            if line.startswith("Disassembly of section"):
                current_section = line.split()[-1].rstrip(":")
                listing_lines.append({
                    "type": "section",
                    "name": current_section,
                })
                continue
            
            # Function header (e.g., "0000000000400078 <_start>:")
            if "<" in line and ">:" in line and not line.startswith(" "):
                parts = line.split()
                if parts:
                    addr = parts[0]
                    func_name = line.split("<")[1].split(">")[0] if "<" in line else ""
                    current_function = func_name
                    listing_lines.append({
                        "type": "function",
                        "address": addr,
                        "name": func_name,
                    })
                continue
            
            # Instruction line (e.g., "  400078:	d2800020 	mov	x0, #0x1")
            if ":" in line and line.strip() and line[0] in " \t":
                parts = line.split(":", 1)
                if len(parts) == 2:
                    addr = parts[0].strip()
                    rest = parts[1].strip()
                    
                    # Split bytes from instruction
                    # Format: "d2800020 	mov	x0, #0x1"
                    tokens = rest.split(None, 1)
                    if tokens:
                        # First token(s) are hex bytes, rest is instruction
                        bytes_part = ""
                        instr_part = ""
                        
                        # Collect hex bytes until we hit a non-hex token
                        words = rest.split()
                        i = 0
                        for i, word in enumerate(words):
                            # Check if word is hex (bytes)
                            if all(c in "0123456789abcdef" for c in word.lower()) and len(word) in [2, 4, 8]:
                                bytes_part += word + " "
                            else:
                                break
                        
                        instr_part = " ".join(words[i:]) if i < len(words) else ""
                        
                        listing_lines.append({
                            "type": "instruction",
                            "address": addr,
                            "bytes": bytes_part.strip(),
                            "instruction": instr_part,
                            "function": current_function,
                        })
        
        return jsonify({
            "filename": safe_name,
            "listing": listing_lines,
            "raw": raw_output[:50000] if len(raw_output) > 50000 else raw_output,  # Limit raw output
        })

    # ──────────────────────────────────────────────────────────────────────────
    # Ghidra Scripting endpoints
    # ──────────────────────────────────────────────────────────────────────────

    @app.post("/api/ghidra/generate-script")
    def generate_ghidra_script() -> Any:
        """Generate a Ghidra script based on task description using LLM."""
        data = request.get_json() or {}
        session_id = data.get("session_id")
        task_description = data.get("task_description", "")
        language = data.get("language", "python")  # python or java
        data.get("binary_path")

        if not session_id:
            return jsonify({"error": "session_id is required"}), 400
        if not task_description.strip():
            return jsonify({"error": "task_description is required"}), 400
        if language not in ("python", "java"):
            return jsonify({"error": "language must be 'python' or 'java'"}), 400

        # Build context for script generation
        history = chat_dao.list_messages(session_id, limit=10)
        analysis = _extract_latest_analysis(history)

        # Build prompt for LLM
        script_template = _get_ghidra_script_template(language)
        binary_info = ""
        if analysis:
            quick = analysis.get("quick_scan", {})
            r2_info = quick.get("radare2", {}).get("info", {})
            binary_info = f"""
Binary Information:
- File: {analysis.get('binary', 'unknown')}
- Architecture: {r2_info.get('arch', 'unknown')}
- Bits: {r2_info.get('bits', 'unknown')}
- Format: {r2_info.get('bintype', 'unknown')}
"""

        prompt = f"""Generate a Ghidra {language.capitalize()} script to accomplish the following task:

Task: {task_description}
{binary_info}
Requirements:
1. The script must be complete and runnable in Ghidra
2. Use proper Ghidra API calls
3. Include helpful comments explaining what the code does
4. Handle errors gracefully
5. Print results in a readable format

{script_template}

Generate ONLY the script code, no explanations before or after. The script should start immediately with the code."""

        try:
            # Use LLM to generate script
            llm_messages = [
                LLMChatMessage(role="system", content="You are a Ghidra scripting expert. Generate clean, well-documented scripts."),
                LLMChatMessage(role="user", content=prompt),
            ]

            response = llm_bridge.chat(llm_messages)
            script = response.strip()

            # Clean up script (remove markdown code blocks if present)
            if script.startswith("```"):
                lines = script.split("\n")
                # Remove first and last line if they're code block markers
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                script = "\n".join(lines)

            # Record this task in trajectory
            _record_trajectory_action(
                session_id,
                "ghidra_scripting.script_generation",
                {
                    "task": task_description,
                    "language": language,
                    "script_length": len(script),
                },
            )

            debug.log("ghidra_script", f"Generated {language} script for: {task_description[:50]}...")

            return jsonify({
                "script": script,
                "language": language,
                "task": task_description,
            })

        except Exception as exc:
            debug.log("ghidra_script_error", str(exc))
            return jsonify({"error": str(exc)}), 500

    @app.post("/api/ghidra/execute-script")
    def execute_ghidra_script() -> Any:
        """Execute a Ghidra script via bridge or headless mode."""
        data = request.get_json() or {}
        session_id = data.get("session_id")
        script = data.get("script", "")
        language = data.get("language", "python")
        binary_path = data.get("binary_path")
        task_description = data.get("task_description", "")

        if not session_id:
            return jsonify({"error": "session_id is required"}), 400
        if not script.strip():
            return jsonify({"error": "script is required"}), 400

        try:
            # Try to execute via bridge if available
            if state.config.ghidra.use_bridge and state.env.ghidra.bridge_connected:
                output = _execute_script_via_bridge(script, language, state)
            else:
                # Fall back to headless execution
                output = _execute_script_headless(script, language, binary_path, state)

            # Record execution in trajectory
            _record_trajectory_action(
                session_id,
                "ghidra_scripting.script_execution",
                {
                    "task": task_description,
                    "language": language,
                    "script_length": len(script),
                    "output_length": len(output),
                    "success": True,
                },
            )

            # Store in chat for history
            chat_dao.append_message(
                session_id,
                "system",
                f"Ghidra script executed: {task_description[:100]}",
                attachments=[{
                    "type": "ghidra_script_result",
                    "task": task_description,
                    "language": language,
                    "output": output[:5000],  # Limit stored output
                }],
            )

            debug.log("ghidra_execute", f"Executed {language} script successfully")

            return jsonify({
                "output": output,
                "language": language,
                "success": True,
            })

        except Exception as exc:
            debug.log("ghidra_execute_error", str(exc))

            # Record failure
            _record_trajectory_action(
                session_id,
                "ghidra_scripting.script_execution",
                {
                    "task": task_description,
                    "language": language,
                    "error": str(exc),
                    "success": False,
                },
            )

            return jsonify({"error": str(exc)}), 500

    @app.get("/api/ghidra/status")
    def ghidra_status() -> Any:
        """Get Ghidra integration status."""
        ghidra_env = state.env.ghidra
        return jsonify({
            "available": ghidra_env.is_ready or ghidra_env.bridge_available,
            "bridge_available": ghidra_env.bridge_available,
            "bridge_connected": ghidra_env.bridge_connected,
            "bridge_program": ghidra_env.bridge_program_loaded,
            "headless_available": ghidra_env.is_ready,
            "install_dir": str(ghidra_env.install_dir) if ghidra_env.install_dir else None,
            "issues": ghidra_env.issues,
            "notes": ghidra_env.notes,
        })

    # ──────────────────────────────────────────────────────────────────────────
    # Unified Tool Execution endpoints
    # ──────────────────────────────────────────────────────────────────────────

    @app.post("/api/tools/execute")
    def execute_tool_script() -> Any:
        """Execute a script using the unified tool execution system.

        Request JSON:
            tool: Tool name (ghidra, radare2, angr, binwalk, gdb)
            script: Script content to execute
            language: Script language (python, r2, shell)
            session_id: Optional session for trajectory tracking
            timeout_ms: Optional execution timeout in milliseconds

        Returns:
            validation: Validation result with errors/warnings
            execution: Execution result with status, stdout, stderr
            result: Parsed output data
        """
        data = request.get_json() or {}

        # Validate required fields
        tool_name = data.get("tool")
        script = data.get("script", "")
        language = data.get("language", "python")
        session_id = data.get("session_id")
        timeout_ms = data.get("timeout_ms", 30000)

        if not tool_name:
            return jsonify({"error": "tool is required"}), 400
        if not script.strip():
            return jsonify({"error": "script is required"}), 400

        # Validate tool name
        try:
            tool = ToolName(tool_name)
        except ValueError:
            valid_tools = [t.value for t in ToolName]
            return jsonify({
                "error": f"Invalid tool: {tool_name}. Valid tools: {valid_tools}"
            }), 400

        # Validate language
        try:
            lang = ScriptLanguage(language)
        except ValueError:
            valid_langs = [lang_val.value for lang_val in ScriptLanguage]
            return jsonify({
                "error": f"Invalid language: {language}. Valid languages: {valid_langs}"
            }), 400

        # First, validate the script (always do this, even if tool unavailable)
        validation = ScriptValidator.validate(script, lang, tool)

        if not validation.valid:
            return jsonify({
                "validation": validation.model_dump(),
                "execution": None,
                "result": {},
                "error": validation.error_summary,
            })

        # Get the appropriate executor
        executor = None
        if tool == ToolName.GHIDRA:
            if state.config.ghidra.use_bridge and hasattr(state, 'ghidra_client') and state.ghidra_client:
                executor = GhidraExecutor(client=state.ghidra_client)
            else:
                return jsonify({
                    "validation": validation.model_dump(),
                    "execution": None,
                    "result": {},
                    "error": "Ghidra bridge not configured or not connected",
                })
        elif tool == ToolName.RADARE2:
            # Radare2 executor needs an r2pipe instance
            executor = Radare2Executor(r2pipe=None)
        else:
            return jsonify({
                "validation": validation.model_dump(),
                "execution": None,
                "result": {},
                "error": f"Executor not yet implemented for {tool.value}",
            })

        # Execute the script
        try:
            output = executor.execute(
                script=script,
                language=lang,
                tool=tool,
                timeout_ms=timeout_ms,
            )

            # Record in trajectory if session provided
            if session_id and state.dao:
                state.dao.record_action(
                    trajectory_id=session_id,
                    adapter=f"tools_{tool.value}",
                    stage="script_execution",
                    payload={
                        "language": lang.value,
                        "script_length": len(script),
                        "success": output.execution.status.value == "success" if output.execution else False,
                    },
                )

            return jsonify({
                "validation": output.validation.model_dump() if output.validation else None,
                "execution": output.execution.model_dump() if output.execution else None,
                "result": output.result,
            })

        except Exception as exc:
            debug.log("tools_execute_error", str(exc))
            return jsonify({
                "validation": validation.model_dump(),
                "execution": None,
                "result": {},
                "error": str(exc),
            }), 500

    @app.get("/api/tools/status")
    def get_tools_status() -> Any:
        """Get availability status for all supported analysis tools.

        Returns:
            tools: Dict of tool name -> status (available, description, etc.)
            available_count: Number of available tools
            total_count: Total number of supported tools
        """
        tools, tools_meta = _get_tools_status_cached(state, live=_live_status_requested())

        # Calculate summary
        available_count = sum(1 for t in tools.values() if t["available"])
        total_count = len(tools)
        scorecard = {
            name: tool.get("scorecard", {})
            for name, tool in tools.items()
            if isinstance(tool, dict)
        }

        return jsonify(_serialize({
            "tools": tools,
            "scorecard": scorecard,
            "score_summary": _summarize_scorecard(scorecard),
            "available_count": available_count,
            "total_count": total_count,
            "meta": tools_meta,
        }))

    @app.post("/api/tools/start")
    def start_tools() -> Any:
        """Start configured MCP-backed analysis services."""

        body = request.get_json(silent=True) or {}
        services_raw = body.get("services") or body.get("service")
        if isinstance(services_raw, str):
            services = [services_raw]
        elif isinstance(services_raw, list):
            services = [str(service) for service in services_raw if str(service).strip()]
        elif services_raw is None:
            services = None
        else:
            return jsonify({"error": "services must be a string or list of strings"}), 400

        dry_run = bool(body.get("dry_run", False))
        foreground = bool(body.get("foreground", False))
        log_dir_raw = body.get("log_dir")
        log_dir = Path(str(log_dir_raw)).expanduser() if log_dir_raw else None

        try:
            launch_results = launch_mcp_services(
                state.config,
                selected=services,
                dry_run=dry_run,
                foreground=foreground,
                log_dir=log_dir,
            )
        except MCPLaunchError as exc:
            return jsonify({"error": str(exc)}), 400

        # Force a live refresh after launch attempts so the UI immediately sees
        # reachable services once they bind their ports.
        with tools_status_lock:
            tools_status_cache["payload"] = None
            tools_status_cache["expires_at"] = 0.0
        tools, tools_meta = _get_tools_status_cached(state, live=True)
        available_count = sum(1 for t in tools.values() if t["available"])
        scorecard = {
            name: tool.get("scorecard", {})
            for name, tool in tools.items()
            if isinstance(tool, dict)
        }

        return jsonify(_serialize({
            "launch": {name: asdict(result) for name, result in launch_results.items()},
            "tools": tools,
            "scorecard": scorecard,
            "score_summary": _summarize_scorecard(scorecard),
            "available_count": available_count,
            "total_count": len(tools),
            "meta": tools_meta,
        }))

    return app


def _get_ghidra_script_template(language: str) -> str:
    """Get a template/guidelines for Ghidra script generation."""
    if language == "python":
        return """
Python Script Guidelines:
- Use `currentProgram` to access the loaded program
- Use `getMonitor()` for progress tracking
- Use `FlatProgramAPI` for common operations
- Import from `ghidra.program.model.*` for data types
- Use `println()` or `print()` for output

Example structure:
```python
# Ghidra Python Script
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *

def run():
    program = currentProgram
    listing = program.getListing()
    # Your analysis code here
    pass

run()
```
"""
    else:
        return """
Java Script Guidelines:
- Extend `GhidraScript` class
- Override `run()` method
- Use `currentProgram` to access the loaded program
- Use `monitor` for progress tracking
- Use `println()` for output

Example structure:
```java
// Ghidra Java Script
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;

public class AnalysisScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Your analysis code here
    }
}
```
"""


def _execute_script_via_bridge(script: str, language: str, state: AppState) -> str:
    """Execute script via Ghidra bridge connection."""
    try:
        from ..adapters.ghidra_bridge_client import GhidraBridgeClient

        client = GhidraBridgeClient(
            host=state.config.ghidra.bridge_host,
            port=state.config.ghidra.bridge_port,
            timeout=state.config.ghidra.bridge_timeout,
        )

        if not client.connect():
            raise RuntimeError("Failed to connect to Ghidra bridge")

        # For Python scripts, we can execute directly via the bridge
        if language == "python":
            # Execute via bridge's remote execution
            bridge = client._bridge
            if bridge is None:
                raise RuntimeError("Bridge not initialized")

            # Execute the script remotely
            try:
                # Escape single quotes in the script
                escaped_script = script.replace("'", "\\'")
                # Use bridge to run script with output capture
                remote_code = f"""
import io
import sys
_output = io.StringIO()
_old_stdout = sys.stdout
sys.stdout = _output
try:
    exec('''{escaped_script}''')
finally:
    sys.stdout = _old_stdout
_output.getvalue()
"""
                result = bridge.remote_eval(remote_code)
                return str(result) if result else "Script executed successfully (no output)"
            except Exception as e:
                return f"Script execution error: {str(e)}"
        else:
            # For Java, we'd need to compile and run via Ghidra's script manager
            raise NotImplementedError("Java script execution via bridge not yet supported")

    except ImportError:
        raise RuntimeError("ghidra_bridge module not available")
    finally:
        if 'client' in locals():
            client.disconnect()


def _execute_script_headless(script: str, language: str, binary_path: str | None, state: AppState) -> str:
    """Execute script via Ghidra headless analyzer."""
    import subprocess
    import tempfile

    if not state.env.ghidra.is_ready:
        raise RuntimeError("Ghidra headless not available")

    if not binary_path:
        raise RuntimeError("binary_path required for headless execution")

    # Write script to temp file
    ext = ".py" if language == "python" else ".java"
    with tempfile.NamedTemporaryFile(mode='w', suffix=ext, delete=False) as f:
        f.write(script)
        script_path = f.name

    try:
        # Build headless command
        headless_path = state.env.ghidra.headless_path
        project_dir = Path(state.config.ghidra.project_dir).expanduser()
        project_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(headless_path),
            str(project_dir),
            "r2d2_scripting",
            "-import", binary_path,
            "-postScript", script_path,
            "-deleteProject",  # Clean up after
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

        output = result.stdout
        if result.stderr:
            output += "\n\nStderr:\n" + result.stderr

        return output

    finally:
        # Clean up temp script
        import os
        try:
            os.unlink(script_path)
        except Exception:
            pass


def _session_to_dict(session: ChatSession) -> dict[str, Any]:
    return {
        "session_id": session.session_id,
        "binary_path": session.binary_path,
        "trajectory_id": session.trajectory_id,
        "title": session.title or Path(session.binary_path).name,
        "created_at": session.created_at.isoformat(),
        "updated_at": session.updated_at.isoformat(),
        "message_count": session.message_count,
    }


def _message_to_dict(message: StoredChatMessage) -> dict[str, Any]:
    return {
        "message_id": message.message_id,
        "session_id": message.session_id,
        "role": message.role,
        "content": message.content,
        "attachments": list(message.attachments),
        "created_at": message.created_at.isoformat(),
    }


def _extract_latest_analysis(messages: list[StoredChatMessage]) -> dict[str, Any] | None:
    for message in reversed(messages):
        for attachment in message.attachments or []:
            if isinstance(attachment, dict) and attachment.get("type") == "analysis_result":
                return attachment
    return None


def _extract_user_goal(history: list[StoredChatMessage]) -> str | None:
    """Extract user's stated goal from session history."""
    for message in history:
        for attachment in message.attachments or []:
            if isinstance(attachment, dict) and attachment.get("type") == "user_goal":
                return attachment.get("goal")
    return None


def _build_investigation_graph_for_session(
    session: ChatSession,
    *,
    messages: list[StoredChatMessage],
    state: AppState,
) -> dict[str, Any]:
    activities = _get_activity_events(state.db, session.session_id, limit=500) if state.db else []
    trajectory_actions = []
    if state.dao and session.trajectory_id:
        trajectory_actions = state.dao.list_actions(session.trajectory_id)
    return build_investigation_graph(
        session,
        messages=messages,
        activities=activities or [],
        trajectory_actions=trajectory_actions,
    )


def _build_analysis_bundle(
    session: ChatSession,
    *,
    messages: list[StoredChatMessage],
    state: AppState,
    include_raw: bool = False,
) -> dict[str, Any] | None:
    analysis = _extract_latest_analysis(messages)
    if not analysis:
        return None

    investigation_graph = _build_investigation_graph_for_session(
        session,
        messages=messages,
        state=state,
    )
    trajectory_actions = _list_trajectory_actions(session, state)
    annotations = _list_annotations(session, state)
    function_names = _list_function_names(session, state)
    analysis_graph = analysis.get("analysis_graph") if isinstance(analysis.get("analysis_graph"), dict) else {}
    evidence = analysis.get("evidence_coverage") if isinstance(analysis.get("evidence_coverage"), dict) else {}
    tool_scorecard = _build_analysis_tool_scorecard(
        analysis.get("tool_status") if isinstance(analysis.get("tool_status"), dict) else {},
        analysis.get("tool_availability") if isinstance(analysis.get("tool_availability"), dict) else {},
        evidence,
    )

    bundle: dict[str, Any] = {
        "schema_version": "r2d2.analysis_bundle.v1",
        "schema_url": "schemas/analysis_bundle.schema.json",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "session": _session_to_dict(session),
        "subject": _summarize_subject(analysis),
        "findings": {
            "issues": list(analysis.get("issues") or []),
            "notes": list(analysis.get("notes") or []),
            "important_nodes": _select_graph_nodes(analysis_graph)[:48],
            "evidence_gaps": _summarize_evidence_gaps(evidence),
        },
        "tooling": {
            "tool_availability": analysis.get("tool_availability") or {},
            "tool_status": analysis.get("tool_status") or {},
            "tool_scorecard": tool_scorecard,
            "evidence_coverage": evidence,
        },
        "graphs": {
            "analysis_graph": analysis_graph,
            "investigation_graph": investigation_graph,
        },
        "journey": {
            "message_count": len(messages),
            "messages": _summarize_messages(messages),
            "trajectory_actions": _summarize_trajectory_actions(trajectory_actions),
            "annotations": annotations,
            "function_names": function_names,
            "investigation_summary": investigation_graph.get("summary", {}) if isinstance(investigation_graph, dict) else {},
        },
        "context": {
            "compact_markdown": _build_compact_analysis_context(analysis, investigation_graph),
        },
    }
    if include_raw:
        bundle["raw"] = {
            "analysis_attachment": analysis,
            "messages": [_message_to_dict(message) for message in messages],
            "trajectory_actions": trajectory_actions,
        }

    bundle["report_markdown"] = _render_analysis_bundle_markdown(bundle)
    bundle["manifest"] = _build_session_artifact_manifest(bundle, analysis, state=state)
    return bundle


def _list_trajectory_actions(session: ChatSession, state: AppState) -> list[dict[str, Any]]:
    if not state.dao or not session.trajectory_id:
        return []
    return state.dao.list_actions(session.trajectory_id)


def _list_annotations(session: ChatSession, state: AppState) -> list[dict[str, Any]]:
    if not state.db:
        return []
    try:
        with state.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT address, note, created_at, updated_at
                FROM annotations
                WHERE session_id = ?
                ORDER BY address
                """,
                (session.session_id,),
            ).fetchall()
        return [
            {
                "address": row["address"],
                "note": row["note"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]
    except Exception:
        return []


def _list_function_names(session: ChatSession, state: AppState) -> list[dict[str, Any]]:
    if not state.db:
        return []
    try:
        with state.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT address, original_name, display_name, reasoning, confidence, source, created_at, updated_at
                FROM function_names
                WHERE session_id = ?
                ORDER BY address
                """,
                (session.session_id,),
            ).fetchall()
        return [
            {
                "address": row["address"],
                "original_name": row["original_name"],
                "display_name": row["display_name"],
                "reasoning": row["reasoning"],
                "confidence": row["confidence"],
                "source": row["source"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]
    except Exception:
        return []


def _attach_live_tool_scorecards(tools: dict[str, Any]) -> dict[str, Any]:
    augmented: dict[str, Any] = {}
    for name, status in tools.items():
        if not isinstance(status, dict):
            augmented[name] = status
            continue
        entry = dict(status)
        entry["scorecard"] = _score_live_tool(name, status)
        augmented[name] = entry
    return augmented


def _score_live_tool(name: str, status: dict[str, Any]) -> dict[str, Any]:
    available = bool(status.get("available"))
    enabled = status.get("enabled", True)
    partial = any(
        bool(status.get(key))
        for key in (
            "binwalk_available",
            "python_package_available",
            "command_available",
            "cli_available",
            "service_available",
            "bridge_available",
            "bridge_connected",
            "docker_available",
            "image_built",
        )
    )
    if enabled is False:
        state = "disabled"
        quality = "unavailable"
        score = 0
    elif available:
        state = "ready"
        quality = "good"
        score = 90
        if name == "firmware" and not status.get("binwalk_available"):
            quality = "usable"
            score = 78
        if status.get("latency_ms") and float(status.get("latency_ms") or 0) > 1500:
            quality = "usable"
            score = min(score, 72)
    elif partial:
        state = "degraded"
        quality = "limited"
        score = 35
    else:
        state = "missing"
        quality = "unavailable"
        score = 0

    limits: list[str] = []
    if status.get("error"):
        limits.append(str(status["error"]))
    if not available and status.get("install_hint"):
        limits.append(str(status["install_hint"]))
    if name == "firmware" and not status.get("binwalk_available"):
        limits.append("built-in signature inventory works; binwalk improves extraction hints")
    if name.endswith("_mcp") and not status.get("capabilities_count"):
        limits.append("MCP capabilities not visible until the service is reachable")

    return {
        "state": state,
        "quality": quality,
        "score": score,
        "speed": _tool_speed_tier(name),
        "confidence": "high" if available else ("medium" if partial else "low"),
        "best_for": _tool_best_for(name),
        "limits": limits[:4],
        "action": status.get("start_command") or status.get("install_hint"),
    }


def _build_analysis_tool_scorecard(
    tool_status: dict[str, Any],
    tool_availability: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    names = sorted(set(tool_status) | set(tool_availability))
    matrix = evidence.get("matrix") if isinstance(evidence, dict) else {}
    scorecard: dict[str, Any] = {}
    for name in names:
        status = tool_status.get(name) if isinstance(tool_status.get(name), dict) else {}
        available = bool(tool_availability.get(name))
        run_state = str(status.get("status") or ("ready" if available else "missing"))
        if run_state == "completed":
            score = 88
            quality = "good"
        elif run_state == "partial":
            score = 68
            quality = "usable"
        elif run_state == "skipped":
            score = 48 if available else 20
            quality = "limited"
        elif run_state == "failed":
            score = 15
            quality = "unavailable"
        elif available:
            score = 55
            quality = "limited"
        else:
            score = 0
            quality = "unavailable"

        coverage = matrix.get(name) if isinstance(matrix, dict) and isinstance(matrix.get(name), dict) else {}
        present = sum(1 for value in coverage.values() if value == "present")
        partial = sum(1 for value in coverage.values() if value == "partial")
        missing = sum(1 for value in coverage.values() if value == "missing")
        if present:
            score = min(100, score + min(10, present * 2))
        if missing and run_state not in {"skipped", "failed"}:
            score = max(0, score - min(20, missing * 2))

        scorecard[name] = {
            "state": run_state,
            "quality": quality,
            "score": score,
            "speed": _tool_speed_tier(name),
            "confidence": "high" if run_state == "completed" else ("medium" if available else "low"),
            "best_for": _tool_best_for(name),
            "duration_ms": status.get("duration_ms"),
            "coverage": {
                "present": present,
                "partial": partial,
                "missing": missing,
            },
            "error": status.get("error"),
            "warnings": status.get("warnings") or [],
        }
    return scorecard


def _summarize_scorecard(scorecard: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "good": 0,
        "usable": 0,
        "limited": 0,
        "unavailable": 0,
        "ready": 0,
        "degraded": 0,
        "missing": 0,
        "disabled": 0,
    }
    for entry in scorecard.values():
        if not isinstance(entry, dict):
            continue
        quality = str(entry.get("quality") or "unavailable")
        state = str(entry.get("state") or "missing")
        if quality in summary:
            summary[quality] += 1
        if state in summary:
            summary[state] += 1
    return summary


def _tool_speed_tier(name: str) -> str:
    if name in {
        "firmware",
        "binwalk",
        "autoprofile",
        "libmagic",
        "capstone",
        "dwarf",
        "pyelftools",
        "pefile",
        "lief",
        "keystone",
        "rizin",
    }:
        return "fast"
    if name in {"radare2", "angr_mcp", "ghidra_mcp", "unicorn", "pwntools"}:
        return "medium"
    if name in {"angr", "ghidra", "ghidra_gdb", "gef", "frida", "gdb"}:
        return "slow"
    if name == "ollama":
        return "interactive"
    return "unknown"


def _tool_best_for(name: str) -> list[str]:
    return {
        "firmware": ["firmware inventory", "embedded artifacts", "triage routing"],
        "binwalk": ["firmware signatures", "filesystem extraction hints"],
        "autoprofile": ["security profile", "interesting strings", "risk hints"],
        "libmagic": ["file identification"],
        "radare2": ["disassembly", "functions", "imports", "strings"],
        "rizin": ["disassembly", "metadata", "strings"],
        "capstone": ["instruction decoding"],
        "pyelftools": ["ELF metadata", "DWARF parsing"],
        "dwarf": ["debug symbols", "source mappings"],
        "pefile": ["PE imports", "resources", "headers"],
        "lief": ["ELF/PE/Mach-O parsing", "binary patching"],
        "unicorn": ["emulation", "instruction experiments"],
        "keystone": ["assembly", "patch prototyping"],
        "pwntools": ["ELF helpers", "ROP", "exploit prototyping"],
        "angr": ["CFG", "symbolic execution"],
        "angr_mcp": ["CFG service", "symbolic execution service"],
        "ghidra": ["decompilation", "types", "cross references"],
        "ghidra_mcp": ["Ghidra static service"],
        "ghidra_gdb": ["GDB-backed dynamic service"],
        "gef": ["runtime traces", "register snapshots"],
        "gdb": ["debug execution"],
        "frida": ["runtime instrumentation"],
        "ollama": ["local chat"],
    }.get(name, ["analysis support"])


def _build_session_artifact_manifest(
    bundle: dict[str, Any],
    analysis: dict[str, Any],
    *,
    state: AppState,
) -> dict[str, Any]:
    exports = [
        _manifest_export("bundle.json", "application/json", "Machine-readable session bundle"),
        _manifest_export("manifest.json", "application/json", "Deterministic artifact manifest"),
        _manifest_export("report.md", "text/markdown", "Human-readable report"),
        _manifest_export("context/compact.md", "text/markdown", "Compact model context"),
        _manifest_export("graphs/analysis_graph.json", "application/json", "Analysis graph"),
        _manifest_export("graphs/investigation_graph.json", "application/json", "Investigation graph"),
        _manifest_export("tooling/tool_status.json", "application/json", "Per-session tool status"),
        _manifest_export("tooling/tool_scorecard.json", "application/json", "Per-session tool scorecard"),
        _manifest_export("tooling/evidence_coverage.json", "application/json", "Evidence coverage matrix"),
        _manifest_export("journey/messages.json", "application/json", "Message summaries"),
        _manifest_export("journey/trajectory_actions.json", "application/json", "Trajectory action summaries"),
        _manifest_export("journey/annotations.json", "application/json", "Session annotations"),
        _manifest_export("journey/function_names.json", "application/json", "Function name overrides"),
        _manifest_export("subject.json", "application/json", "Subject summary"),
    ]
    files = _collect_session_artifact_files(analysis, state)
    return {
        "schema_version": "r2d2.session_artifact_manifest.v1",
        "generated_at": bundle.get("generated_at"),
        "session_id": (bundle.get("session") or {}).get("session_id") if isinstance(bundle.get("session"), dict) else None,
        "exports": exports,
        "files": files,
        "summary": {
            "export_count": len(exports),
            "file_count": len(files),
            "included_file_count": sum(1 for item in files if item.get("included")),
        },
    }


def _manifest_export(path: str, media_type: str, description: str) -> dict[str, Any]:
    return {
        "path": path,
        "media_type": media_type,
        "description": description,
    }


def _collect_session_artifact_files(analysis: dict[str, Any], state: AppState) -> list[dict[str, Any]]:
    quick = analysis.get("quick_scan") if isinstance(analysis.get("quick_scan"), dict) else {}
    firmware = quick.get("firmware") if isinstance(quick.get("firmware"), dict) else {}
    carved_targets = firmware.get("carved_targets") if isinstance(firmware.get("carved_targets"), list) else []
    files: list[dict[str, Any]] = []
    for index, target in enumerate(carved_targets):
        if not isinstance(target, dict):
            continue
        raw_path = target.get("carved_path") or target.get("path")
        entry = _artifact_file_entry(
            raw_path,
            state,
            archive_prefix="artifacts/firmware",
            index=index,
            kind=str(target.get("kind") or "carved_target"),
            role=str(target.get("analysis_role") or "artifact"),
        )
        entry["offset"] = target.get("offset")
        entry["source"] = "firmware.carved_targets"
        files.append(entry)
    return files


def _artifact_file_entry(
    raw_path: Any,
    state: AppState,
    *,
    archive_prefix: str,
    index: int,
    kind: str,
    role: str,
) -> dict[str, Any]:
    source_path = str(raw_path or "")
    entry: dict[str, Any] = {
        "kind": kind,
        "role": role,
        "source_path": source_path,
        "archive_path": None,
        "included": False,
    }
    if not source_path:
        entry["reason"] = "no source path recorded"
        return entry

    try:
        path = Path(source_path).expanduser()
        resolved = path.resolve()
        artifacts_root = Path(state.config.output.artifacts_dir).expanduser().resolve()
    except Exception as exc:
        entry["reason"] = f"path resolution failed: {exc}"
        return entry

    if not _path_within(resolved, artifacts_root):
        entry["reason"] = f"outside artifact allowlist: {artifacts_root}"
        return entry
    if not resolved.exists():
        entry["reason"] = "file is missing"
        return entry
    if not resolved.is_file():
        entry["reason"] = "not a regular file"
        return entry

    archive_name = _sanitize_archive_name(resolved.name)
    entry.update({
        "source_path": str(resolved),
        "archive_path": f"{archive_prefix}/{index:03d}-{archive_name}",
        "included": True,
        "size_bytes": resolved.stat().st_size,
    })
    return entry


def _path_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _sanitize_archive_name(name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {".", "_", "-"} else "_" for ch in name)
    return cleaned or "artifact.bin"


def _render_analysis_bundle_zip(
    bundle: dict[str, Any],
    *,
    state: AppState,
    include_binary: bool = False,
) -> BytesIO:
    manifest = dict(bundle.get("manifest") or {})
    files = list(manifest.get("files") or [])
    if include_binary:
        binary_entry = _artifact_file_entry(
            (bundle.get("session") or {}).get("binary_path") if isinstance(bundle.get("session"), dict) else None,
            state,
            archive_prefix="artifacts/original",
            index=0,
            kind="original_binary",
            role="subject",
        )
        binary_entry["source"] = "session.binary_path"
        files.append(binary_entry)
    manifest["files"] = files
    manifest["summary"] = {
        **(manifest.get("summary") if isinstance(manifest.get("summary"), dict) else {}),
        "file_count": len(files),
        "included_file_count": sum(1 for item in files if isinstance(item, dict) and item.get("included")),
        "includes_original_binary": include_binary,
    }

    archive_bundle = dict(bundle)
    archive_bundle["manifest"] = manifest

    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        _zip_writestr_json(zf, "bundle.json", archive_bundle)
        _zip_writestr_json(zf, "manifest.json", manifest)
        zf.writestr("report.md", str(bundle.get("report_markdown") or ""))
        context = bundle.get("context") if isinstance(bundle.get("context"), dict) else {}
        zf.writestr("context/compact.md", str(context.get("compact_markdown") or ""))
        graphs = bundle.get("graphs") if isinstance(bundle.get("graphs"), dict) else {}
        tooling = bundle.get("tooling") if isinstance(bundle.get("tooling"), dict) else {}
        journey = bundle.get("journey") if isinstance(bundle.get("journey"), dict) else {}
        _zip_writestr_json(zf, "graphs/analysis_graph.json", graphs.get("analysis_graph") or {})
        _zip_writestr_json(zf, "graphs/investigation_graph.json", graphs.get("investigation_graph") or {})
        _zip_writestr_json(zf, "tooling/tool_status.json", tooling.get("tool_status") or {})
        _zip_writestr_json(zf, "tooling/tool_scorecard.json", tooling.get("tool_scorecard") or {})
        _zip_writestr_json(zf, "tooling/evidence_coverage.json", tooling.get("evidence_coverage") or {})
        _zip_writestr_json(zf, "journey/messages.json", journey.get("messages") or [])
        _zip_writestr_json(zf, "journey/trajectory_actions.json", journey.get("trajectory_actions") or [])
        _zip_writestr_json(zf, "journey/annotations.json", journey.get("annotations") or [])
        _zip_writestr_json(zf, "journey/function_names.json", journey.get("function_names") or [])
        _zip_writestr_json(zf, "subject.json", bundle.get("subject") or {})

        for item in files:
            if not isinstance(item, dict) or not item.get("included") or not item.get("archive_path"):
                continue
            try:
                zf.write(str(item["source_path"]), str(item["archive_path"]))
            except Exception:
                continue
    buffer.seek(0)
    return buffer


def _zip_writestr_json(zf: zipfile.ZipFile, path: str, payload: Any) -> None:
    zf.writestr(
        path,
        json.dumps(_serialize(payload), indent=2, sort_keys=True, default=str),
    )


def _summarize_subject(analysis: dict[str, Any]) -> dict[str, Any]:
    quick = analysis.get("quick_scan") if isinstance(analysis.get("quick_scan"), dict) else {}
    deep = analysis.get("deep_scan") if isinstance(analysis.get("deep_scan"), dict) else {}
    firmware = quick.get("firmware") if isinstance(quick.get("firmware"), dict) else {}
    r2_quick = quick.get("radare2") if isinstance(quick.get("radare2"), dict) else {}
    r2_info = r2_quick.get("info") if isinstance(r2_quick.get("info"), dict) else {}
    bin_meta = r2_info.get("bin") if isinstance(r2_info.get("bin"), dict) else {}
    core = r2_info.get("core") if isinstance(r2_info.get("core"), dict) else {}
    ghidra_gdb = deep.get("ghidra_gdb") if isinstance(deep.get("ghidra_gdb"), dict) else {}
    file_info = ghidra_gdb.get("file_info") if isinstance(ghidra_gdb.get("file_info"), dict) else {}

    artifacts = firmware.get("embedded_artifacts") if isinstance(firmware.get("embedded_artifacts"), list) else []
    targets = firmware.get("recommended_targets") if isinstance(firmware.get("recommended_targets"), list) else []
    carves = firmware.get("carved_targets") if isinstance(firmware.get("carved_targets"), list) else []
    scan = firmware.get("scan") if isinstance(firmware.get("scan"), dict) else {}

    return {
        "binary": analysis.get("binary"),
        "trajectory_id": analysis.get("trajectory_id"),
        "format": core.get("format") or firmware.get("top_level_format") or file_info.get("format"),
        "architecture": bin_meta.get("arch") or file_info.get("architecture"),
        "bits": bin_meta.get("bits"),
        "os": bin_meta.get("os") or firmware.get("container_type"),
        "sha256": firmware.get("sha256") or file_info.get("sha256"),
        "size_bytes": firmware.get("size_bytes") or file_info.get("size_bytes"),
        "firmware": {
            "top_level_format": firmware.get("top_level_format"),
            "container_type": firmware.get("container_type"),
            "signature_count": scan.get("signature_count"),
            "artifact_count": len(artifacts),
            "recommended_target_count": len(targets),
            "carved_target_count": len(carves),
        },
    }


def _summarize_messages(messages: list[StoredChatMessage], limit: int = 24) -> list[dict[str, Any]]:
    summarized: list[dict[str, Any]] = []
    for message in messages[-limit:]:
        summarized.append(
            {
                "message_id": message.message_id,
                "role": message.role,
                "created_at": message.created_at.isoformat(),
                "content_preview": _clamp_text(message.content.replace("\n", " "), 240),
                "attachments": [
                    attachment.get("type", "attachment")
                    for attachment in (message.attachments or [])
                    if isinstance(attachment, dict)
                ],
            }
        )
    return summarized


def _summarize_trajectory_actions(actions: list[dict[str, Any]], limit: int = 80) -> list[dict[str, Any]]:
    summarized: list[dict[str, Any]] = []
    for row in actions[-limit:]:
        payload = row.get("payload")
        parsed_payload: Any = payload
        if isinstance(payload, str):
            try:
                parsed_payload = json.loads(payload)
            except json.JSONDecodeError:
                parsed_payload = payload[:500]
        summarized.append(
            {
                "seq": row.get("seq"),
                "action": row.get("action"),
                "created_at": row.get("created_at"),
                "payload": parsed_payload,
            }
        )
    return summarized


def _render_analysis_bundle_markdown(bundle: dict[str, Any]) -> str:
    subject = bundle.get("subject", {}) if isinstance(bundle.get("subject"), dict) else {}
    findings = bundle.get("findings", {}) if isinstance(bundle.get("findings"), dict) else {}
    tooling = bundle.get("tooling", {}) if isinstance(bundle.get("tooling"), dict) else {}
    graphs = bundle.get("graphs", {}) if isinstance(bundle.get("graphs"), dict) else {}
    journey = bundle.get("journey", {}) if isinstance(bundle.get("journey"), dict) else {}
    analysis_graph = graphs.get("analysis_graph", {}) if isinstance(graphs.get("analysis_graph"), dict) else {}
    graph_summary = analysis_graph.get("summary", {}) if isinstance(analysis_graph.get("summary"), dict) else {}
    investigation_summary = journey.get("investigation_summary", {}) if isinstance(journey.get("investigation_summary"), dict) else {}

    binary_name = Path(str(subject.get("binary") or "unknown")).name
    lines = [
        f"# r2d2 Analysis Report: {binary_name}",
        "",
        f"Generated: {bundle.get('generated_at', 'unknown')}",
        f"Session: `{bundle.get('session', {}).get('session_id', 'unknown') if isinstance(bundle.get('session'), dict) else 'unknown'}`",
        "",
        "## Subject",
        "",
        f"- Binary: `{subject.get('binary', 'unknown')}`",
        f"- Format: {subject.get('format') or 'unknown'}",
        f"- Architecture: {subject.get('architecture') or 'unknown'}"
        + (f" / {subject.get('bits')}-bit" if subject.get("bits") else ""),
        f"- OS/container: {subject.get('os') or 'unknown'}",
    ]
    if subject.get("sha256"):
        lines.append(f"- SHA-256: `{subject.get('sha256')}`")

    firmware = subject.get("firmware") if isinstance(subject.get("firmware"), dict) else {}
    if firmware and any(value for value in firmware.values()):
        lines.extend(
            [
                "",
                "## Firmware Inventory",
                "",
                f"- Top-level format: {firmware.get('top_level_format') or 'unknown'}",
                f"- Container type: {firmware.get('container_type') or 'unknown'}",
                f"- Signatures: {firmware.get('signature_count') or 0}",
                f"- Embedded artifacts: {firmware.get('artifact_count') or 0}",
                f"- Recommended targets: {firmware.get('recommended_target_count') or 0}",
                f"- Carved targets: {firmware.get('carved_target_count') or 0}",
            ]
        )

    lines.extend(
        [
            "",
            "## Findings Graph",
            "",
            f"- Nodes: {graph_summary.get('node_count', 0)}",
            f"- Edges: {graph_summary.get('edge_count', 0)}",
            f"- Tools: {', '.join(str(tool) for tool in graph_summary.get('tools', [])[:12]) if graph_summary.get('tools') else 'unknown'}",
        ]
    )
    important_nodes = findings.get("important_nodes") if isinstance(findings.get("important_nodes"), list) else []
    if important_nodes:
        lines.extend(["", "### Important Nodes", ""])
        for node in important_nodes[:24]:
            if not isinstance(node, dict):
                continue
            address = f" @ `{node.get('address')}`" if node.get("address") else ""
            source = f" [{node.get('source')}]" if node.get("source") else ""
            lines.append(f"- `{node.get('kind')}` {node.get('label')}{address}{source}")

    issues = findings.get("issues") if isinstance(findings.get("issues"), list) else []
    notes = findings.get("notes") if isinstance(findings.get("notes"), list) else []
    if issues or notes:
        lines.extend(["", "## Issues And Notes", ""])
        for issue in issues[:12]:
            lines.append(f"- Issue: {issue}")
        for note in notes[:12]:
            lines.append(f"- Note: {note}")

    gaps = findings.get("evidence_gaps") if isinstance(findings.get("evidence_gaps"), list) else []
    if gaps:
        lines.extend(["", "## Setup And Coverage Gaps", ""])
        for gap in gaps[:16]:
            lines.append(f"- {gap}")

    tool_status = tooling.get("tool_status") if isinstance(tooling.get("tool_status"), dict) else {}
    if tool_status:
        lines.extend(["", "## Tool Status", ""])
        for name, status in sorted(tool_status.items()):
            if not isinstance(status, dict):
                continue
            parts = [str(status.get("status", "?"))]
            if status.get("functions_count"):
                parts.append(f"{status.get('functions_count')} functions")
            if status.get("cfg_nodes"):
                parts.append(f"{status.get('cfg_nodes')} CFG nodes")
            if status.get("error"):
                parts.append(f"error: {status.get('error')}")
            lines.append(f"- {name}: " + "; ".join(parts))

    lines.extend(
        [
            "",
            "## Investigation Journey",
            "",
            f"- Messages: {journey.get('message_count', 0)}",
            f"- Investigation graph nodes: {investigation_summary.get('node_count', 0)}",
            f"- Investigation graph edges: {investigation_summary.get('edge_count', 0)}",
        ]
    )
    trajectory_actions = journey.get("trajectory_actions") if isinstance(journey.get("trajectory_actions"), list) else []
    if trajectory_actions:
        lines.extend(["", "### Recent Actions", ""])
        for action in trajectory_actions[-20:]:
            if isinstance(action, dict):
                lines.append(f"- #{action.get('seq', '?')} `{action.get('action', '?')}`")

    lines.extend(
        [
            "",
            "## Reproduce / Continue",
            "",
            "- Open the r2d2 session and use the Map tab for segmented findings.",
            "- Run `uv run r2d2 mcp` to verify GhidraMCP and angr_mcp service reachability.",
            "- Export the JSON bundle for machine-readable graph and evidence handoff.",
        ]
    )
    return "\n".join(lines)


def _get_activity_events(db: Any, session_id: str, limit: int = 100) -> list[dict[str, Any]]:
    if not db:
        return []

    try:
        with db.connect() as conn:
            rows = conn.execute(
                """
                SELECT event_id, event_type, event_data, created_at
                FROM activity_events
                WHERE session_id = ?
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
        return [
            {
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "event_data": row["event_data"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    except Exception:
        return []


def _get_activity_context(db: Any, session_id: str, limit: int = 25) -> list[dict[str, Any]] | None:
    """Fetch recent user activity events for LLM context."""
    if not db:
        return None
    
    try:
        with db.connect() as conn:
            rows = conn.execute(
                """
                SELECT event_type, event_data, created_at
                FROM activity_events
                WHERE session_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
        
        activities = []
        for row in rows:
            try:
                event_data = json.loads(row["event_data"]) if row["event_data"] else {}
            except json.JSONDecodeError:
                event_data = {}
            activities.append({
                "event_type": row["event_type"],
                "event_data": event_data,
                "created_at": row["created_at"],
            })
        
        return list(reversed(activities))  # Chronological order
    except Exception:
        return None


def _format_activity_context(activities: list[dict[str, Any]] | None) -> str | None:
    """Format activity events into a readable context string for the LLM."""
    if not activities:
        return None
    
    lines = ["## Recent User Activity"]
    lines.append("(Use this to understand what the user has been exploring)")
    lines.append("")
    
    # Summarize patterns
    tab_visits: dict[str, int] = {}
    functions_viewed = []
    addresses_viewed = []
    code_selections = 0
    questions_asked = 0
    
    for event in activities:
        event_type = event.get("event_type", "")
        data = event.get("event_data", {})
        
        if event_type == "tab_switch":
            to_tab = data.get("to_tab", "")
            if to_tab:
                tab_visits[to_tab] = tab_visits.get(to_tab, 0) + 1
        elif event_type == "function_view":
            func_name = data.get("function_name")
            if func_name and func_name not in functions_viewed:
                functions_viewed.append(func_name)
        elif event_type == "address_hover":
            addr = data.get("address")
            if addr and addr not in addresses_viewed:
                addresses_viewed.append(addr)
        elif event_type == "code_select":
            code_selections += 1
        elif event_type == "ask_claude":
            questions_asked += 1
    
    # Build summary
    if tab_visits:
        most_visited = sorted(tab_visits.items(), key=lambda x: -x[1])[:3]
        tabs_str = ", ".join(f"{t}({c}x)" for t, c in most_visited)
        lines.append(f"- Tabs visited: {tabs_str}")
    
    if functions_viewed:
        lines.append(f"- Functions explored: {', '.join(functions_viewed[-5:])}")
    
    if addresses_viewed:
        lines.append(f"- Addresses examined: {', '.join(addresses_viewed[-5:])}")
    
    if code_selections > 0:
        lines.append(f"- Selected code {code_selections} time(s)")
    
    if questions_asked > 0:
        lines.append(f"- Asked {questions_asked} question(s) this session")
    
    # Show last 5 events as timeline
    recent_events = activities[-5:]
    if recent_events:
        lines.append("")
        lines.append("Recent timeline:")
        for event in recent_events:
            event_type = event.get("event_type", "")
            data = event.get("event_data", {})
            desc = _describe_activity_event(event_type, data)
            lines.append(f"  → {desc}")
    
    return "\n".join(lines)


def _describe_activity_event(event_type: str, data: dict[str, Any]) -> str:
    """Generate human-readable description of an activity event."""
    if event_type == "tab_switch":
        return f"Switched to {data.get('to_tab', '?')} tab"
    elif event_type == "function_view":
        return f"Viewed function {data.get('function_name', '?')}"
    elif event_type == "address_hover":
        return f"Examined address {data.get('address', '?')}"
    elif event_type == "code_select":
        lines = data.get("line_count", "?")
        return f"Selected {lines} lines of code"
    elif event_type == "annotation_add":
        return f"Added annotation at {data.get('address', '?')}"
    elif event_type == "search_query":
        return f"Searched for '{data.get('query', '?')}'"
    elif event_type == "cfg_navigate":
        target = data.get("block") or data.get("function") or "block"
        return f"Navigated CFG to {target}"
    elif event_type == "ask_claude":
        return f"Asked about {data.get('topic', 'code')}"
    else:
        return event_type


def _llm_context_cache_key(
    session: ChatSession,
    *,
    analysis_attachment: dict[str, Any],
    activity_context: list[dict[str, Any]] | None,
    investigation_graph: dict[str, Any] | None,
    config: Any | None,
) -> str:
    graph = analysis_attachment.get("analysis_graph") if isinstance(analysis_attachment.get("analysis_graph"), dict) else {}
    graph_summary = graph.get("summary") if isinstance(graph.get("summary"), dict) else {}
    investigation_summary = (
        investigation_graph.get("summary")
        if isinstance(investigation_graph, dict) and isinstance(investigation_graph.get("summary"), dict)
        else {}
    )
    activities = activity_context or []
    latest_activity = activities[-1].get("created_at") if activities and isinstance(activities[-1], dict) else None
    tool_status = analysis_attachment.get("tool_status") if isinstance(analysis_attachment.get("tool_status"), dict) else {}
    tool_fingerprint = {
        name: {
            "status": status.get("status"),
            "error": bool(status.get("error")),
            "warnings": len(status.get("warnings") or []),
        }
        for name, status in sorted(tool_status.items())
        if isinstance(status, dict)
    }
    payload = {
        "session_id": session.session_id,
        "binary": analysis_attachment.get("binary"),
        "trajectory_id": analysis_attachment.get("trajectory_id"),
        "plan": analysis_attachment.get("plan"),
        "issues": len(analysis_attachment.get("issues") or []),
        "notes": len(analysis_attachment.get("notes") or []),
        "graph_summary": graph_summary,
        "investigation_summary": investigation_summary,
        "activity_count": len(activities),
        "latest_activity": latest_activity,
        "tool_status": tool_fingerprint,
        "compact": bool(getattr(getattr(config, "llm", None), "compact_context", True)),
        "budget": int(getattr(getattr(config, "llm", None), "context_budget_chars", 24000)),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _build_budgeted_session_context(
    analysis: dict[str, Any],
    investigation_graph: dict[str, Any] | None,
    activity_context: list[dict[str, Any]] | None,
    *,
    config: Any | None,
) -> dict[str, Any]:
    budget = int(getattr(getattr(config, "llm", None), "context_budget_chars", 24000))
    budget = max(4000, budget)
    compact_context = bool(getattr(getattr(config, "llm", None), "compact_context", True))
    analysis_context = (
        _build_compact_analysis_context(analysis, investigation_graph)
        if compact_context
        else _build_analysis_context(analysis)
    )
    activity = _format_activity_context(activity_context)
    sections = [
        ("analysis", analysis_context, int(budget * 0.78)),
        ("activity", activity or "", int(budget * 0.12)),
    ]
    context, section_meta = _fit_context_sections(sections, budget)
    return {
        "context": context,
        "meta": {
            "budget_chars": budget,
            "used_chars": len(context),
            "sections": section_meta,
        },
    }


def _fit_context_sections(sections: list[tuple[str, str, int]], total_budget: int) -> tuple[str, list[dict[str, Any]]]:
    rendered: list[str] = []
    meta: list[dict[str, Any]] = []
    remaining = total_budget
    for name, text, preferred_budget in sections:
        if not text:
            meta.append({"name": name, "chars": 0, "budget": preferred_budget, "truncated": False})
            continue
        budget = max(0, min(preferred_budget, remaining))
        if budget <= 0:
            meta.append({"name": name, "chars": 0, "budget": preferred_budget, "truncated": True})
            continue
        fitted = _clamp_text_by_lines(text, budget)
        rendered.append(fitted)
        used = len(fitted)
        remaining = max(0, remaining - used - 2)
        meta.append({"name": name, "chars": used, "budget": budget, "truncated": len(fitted) < len(text)})
    return "\n\n".join(rendered), meta


def _clamp_text_by_lines(text: str, max_chars: int) -> str:
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    marker = "\n\n[... section compacted to fit context budget ...]"
    limit = max(0, max_chars - len(marker))
    lines = text.splitlines()
    kept: list[str] = []
    used = 0
    for line in lines:
        next_used = used + len(line) + 1
        if next_used > limit:
            break
        kept.append(line)
        used = next_used
    if not kept:
        return text[:limit] + marker
    return "\n".join(kept) + marker


def _build_llm_messages(
    history: list[StoredChatMessage],
    analysis_attachment: dict[str, Any] | None,
    activity_context: list[dict[str, Any]] | None = None,
    *,
    config: Any | None = None,
    investigation_graph: dict[str, Any] | None = None,
    prebuilt_context: str | None = None,
) -> list[LLMChatMessage]:
    """Build focused LLM messages.

    Compact mode is the default for local models: it uses graph summaries,
    selected evidence, and recent journey context instead of dumping raw
    adapter payloads on every turn.
    """
    
    user_goal = _extract_user_goal(history)
    
    # Build system prompt - friendly but technical
    system_parts = [
        """You are r2d2, a friendly reverse engineering assistant built for learning ARM assembly and binary analysis.

## Your Role
Help users understand binaries at their level. Start simple, go deeper when asked.

## Common Use Cases
1. **Analyze a specific block**: User selects code, asks about a function or basic block
2. **Open-ended exploration**: User asks broad questions, needs help narrowing down to interesting code
3. **Instrumentation planning**: User wants to hook/instrument specific code, needs to identify targets
4. **Educational**: User is learning about binary representation levels (source → assembly → machine code)

## Analysis Tools Available
The analysis uses multiple tools, each providing different insights:
- **radare2**: Disassembly, function discovery, imports, strings
- **angr**: Control Flow Graphs (CFG), symbolic execution paths
- **Capstone**: Instruction-level decoding with operand details
- **Ghidra**: Decompilation to C-like pseudocode, type recovery
- **AutoProfile**: Security features (NX, PIE, RELRO), risk assessment
- **DWARF**: Debug symbols, type info, source mappings (if available)
- **Frida**: Runtime instrumentation, dynamic analysis (if enabled)
- **GEF/GDB**: Execution tracing, register snapshots (if enabled)

When explaining, mention which tool provided specific information to help users understand the analysis.

## Frontend Tools (mention these naturally when helpful)
- **Summary**: Quick view of binary info, functions, imports, strings
- **Profile**: Security features, risk assessment, interesting strings
- **Disassembly**: Hover any ARM/x86 instruction for docs • Drag to select code • "Ask Claude" to explain
- **CFG**: Control flow graph with function list and block details
- **Decompiler**: C-like pseudocode from Ghidra (if enabled)
- **Dynamic**: Execution traces and register snapshots (if GEF enabled)
- **DWARF**: Debug symbols and source mappings (if available)
- **Annotations**: Click or drag-select to add notes that persist

## Style
- First response: 2-3 sentences max. What is it? What stands out?
- Follow-ups: Go as deep as needed
- Use code blocks for assembly snippets
- Reference addresses like `0x1234` and function names so the user can hover them for context
- If binary looks packed/encrypted/unusual, say so upfront
- When explaining code, relate assembly to higher-level concepts when helpful

## Address Citations
When referencing specific addresses in your response, always use the format `0x...` (e.g., `0x401000`).
The frontend will automatically make these addresses hoverable, showing the relevant assembly context.
This helps users follow along with your explanations in the disassembly view.""",
    ]
    
    if user_goal:
        system_parts.append(f"\n## User's Goal\n{user_goal}")
    
    compact_context = bool(getattr(getattr(config, "llm", None), "compact_context", True))

    if prebuilt_context:
        system_parts.append(prebuilt_context)
    elif analysis_attachment:
        ctx = (
            _build_compact_analysis_context(analysis_attachment, investigation_graph)
            if compact_context
            else _build_analysis_context(analysis_attachment)
        )
        system_parts.append(ctx)
    else:
        # Even without attachment, look for analysis in history
        for msg in history:
            if msg.role == "system":
                for att in (msg.attachments or []):
                    if isinstance(att, dict) and att.get("type") == "analysis_result":
                        ctx = (
                            _build_compact_analysis_context(att, investigation_graph)
                            if compact_context
                            else _build_analysis_context(att)
                        )
                        system_parts.append(ctx)
                        break
    
    # Include activity context for better situational awareness
    if activity_context and not prebuilt_context:
        activity_str = _format_activity_context(activity_context)
        if activity_str:
            system_parts.append(activity_str)
    
    max_chars = int(getattr(getattr(config, "llm", None), "context_budget_chars", 24000))
    system_prompt = "\n\n".join(system_parts)
    system_prompt = _clamp_text(system_prompt, max_chars)
    messages: list[LLMChatMessage] = [LLMChatMessage(role="system", content=system_prompt)]

    # Add conversation history - keep recent exchanges for context continuity.
    user_messages = [m for m in history if m.role in ("user", "assistant")]
    history_limit = 10 if compact_context else 15
    for item in user_messages[-history_limit:]:
        messages.append(
            LLMChatMessage(
                role=item.role,
                content=_clamp_text(item.content, 2500 if compact_context else 8000),
            )
        )
    
    return messages


def _build_compact_analysis_context(
    analysis: dict[str, Any],
    investigation_graph: dict[str, Any] | None,
) -> str:
    quick = analysis.get("quick_scan") or {}
    deep = analysis.get("deep_scan") or {}
    graph = analysis.get("analysis_graph") if isinstance(analysis.get("analysis_graph"), dict) else {}
    graph_summary = graph.get("summary", {}) if isinstance(graph, dict) else {}
    investigation_summary = (
        investigation_graph.get("summary", {})
        if isinstance(investigation_graph, dict)
        else {}
    )

    lines = ["## Compact Binary Analysis Context"]
    lines.append(f"Binary: {analysis.get('binary', 'unknown')}")

    r2_quick = quick.get("radare2", {}) if isinstance(quick, dict) else {}
    r2_info = r2_quick.get("info", {}) if isinstance(r2_quick, dict) else {}
    bin_meta = r2_info.get("bin", {}) if isinstance(r2_info, dict) else {}
    core = r2_info.get("core", {}) if isinstance(r2_info, dict) else {}
    if isinstance(bin_meta, dict):
        lines.append(
            "Target: "
            f"{bin_meta.get('arch', '?')}/{bin_meta.get('bits', '?')}-bit "
            f"{bin_meta.get('os', '?')} {core.get('format', '') if isinstance(core, dict) else ''}".strip()
        )

    if graph_summary:
        lines.append("\n### Findings Graph")
        lines.append(
            f"Nodes: {graph_summary.get('node_count', 0)}; "
            f"Edges: {graph_summary.get('edge_count', 0)}; "
            f"Tools: {', '.join(str(t) for t in graph_summary.get('tools', [])[:8])}"
        )
        node_kinds = graph_summary.get("node_kinds", {})
        if isinstance(node_kinds, dict):
            lines.append("Node kinds: " + ", ".join(f"{k}={v}" for k, v in sorted(node_kinds.items())[:12]))

    important_nodes = _select_graph_nodes(graph)
    if important_nodes:
        lines.append("\nImportant findings:")
        for node in important_nodes[:24]:
            addr = f" @ {node.get('address')}" if node.get("address") else ""
            source = node.get("source") or node.get("actor")
            suffix = f" [{source}]" if source else ""
            lines.append(f"- {node.get('kind')}: {node.get('label')}{addr}{suffix}")

    if investigation_summary:
        lines.append("\n### Investigation Journey")
        lines.append(
            f"Events: {investigation_summary.get('event_count', 0)}; "
            f"Nodes: {investigation_summary.get('node_count', 0)}; "
            f"Edges: {investigation_summary.get('edge_count', 0)}"
        )
        actors = investigation_summary.get("actor_counts", {})
        if isinstance(actors, dict):
            lines.append("Actors: " + ", ".join(f"{k}={v}" for k, v in sorted(actors.items())))

    evidence = analysis.get("evidence_coverage") or {}
    gaps = _summarize_evidence_gaps(evidence)
    if gaps:
        lines.append("\nSetup/tooling gaps:")
        for gap in gaps[:12]:
            lines.append(f"- {gap}")

    tool_status = analysis.get("tool_status") or {}
    if isinstance(tool_status, dict) and tool_status:
        lines.append("\nTool status:")
        for name, status in sorted(tool_status.items()):
            if not isinstance(status, dict):
                continue
            parts = [str(status.get("status", "?"))]
            if status.get("functions_count"):
                parts.append(f"{status.get('functions_count')} functions")
            if status.get("cfg_nodes"):
                parts.append(f"{status.get('cfg_nodes')} CFG nodes")
            if status.get("error"):
                parts.append(f"error: {status.get('error')}")
            lines.append(f"- {name}: " + "; ".join(parts))

    r2_deep = deep.get("radare2", {}) if isinstance(deep, dict) else {}
    entry_disasm = r2_deep.get("entry_disassembly") if isinstance(r2_deep, dict) else None
    if isinstance(entry_disasm, str) and entry_disasm.strip():
        disasm_lines = entry_disasm.strip().splitlines()[:35]
        lines.append("\nEntry disassembly excerpt:")
        lines.append("```asm")
        lines.extend(disasm_lines)
        lines.append("```")

    issues = analysis.get("issues", [])
    if issues:
        lines.append("\nIssues: " + "; ".join(str(issue) for issue in issues[:8]))

    return "\n".join(lines)


def _select_graph_nodes(graph: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    if not isinstance(nodes, list):
        return []

    priority = {
        "issue": 0,
        "function": 1,
        "import": 2,
        "string": 3,
        "decompilation": 4,
        "type": 5,
        "profile": 6,
        "tool": 7,
    }

    selected = [
        node for node in nodes
        if isinstance(node, dict) and node.get("kind") in priority
    ]
    selected.sort(
        key=lambda node: (
            priority.get(str(node.get("kind")), 99),
            0 if node.get("address") else 1,
            str(node.get("label", "")),
        )
    )
    return selected[:80]


def _summarize_evidence_gaps(evidence: dict[str, Any]) -> list[str]:
    matrix = evidence.get("matrix") if isinstance(evidence, dict) else None
    if not isinstance(matrix, dict):
        return []

    gaps: list[str] = []
    for tool, columns in sorted(matrix.items()):
        if not isinstance(columns, dict):
            continue
        missing = [name for name, status in columns.items() if status == "missing"]
        partial = [name for name, status in columns.items() if status == "partial"]
        if missing:
            gaps.append(f"{tool}: missing {', '.join(missing[:6])}")
        if partial:
            gaps.append(f"{tool}: partial {', '.join(partial[:6])}")
    return gaps


def _clamp_text(text: str, max_chars: int) -> str:
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    head = max_chars * 2 // 3
    tail = max_chars - head - 120
    if tail <= 0:
        return text[:max_chars]
    return (
        text[:head]
        + "\n\n[... compacted to fit local model context budget ...]\n\n"
        + text[-tail:]
    )


def _build_analysis_context(analysis: dict[str, Any]) -> str:
    """Build a compact analysis context for the LLM including actual disassembly.

    This context is critical for:
    1. Providing the LLM with binary details to answer questions
    2. Recording trajectories of analysis for learning
    3. Supporting educational use cases (explaining representation levels)
    """
    quick = analysis.get("quick_scan") or {}
    deep = analysis.get("deep_scan") or {}

    lines = ["## Analysis Results"]

    # Tool Attribution - document which tools contributed to the analysis
    # This helps the LLM explain what information comes from where
    tools_used = []
    tool_descriptions = {
        "autoprofile": "AutoProfile (security features, strings, risk analysis)",
        "radare2": "radare2 (disassembly, functions, imports, binary metadata)",
        "angr": "angr (CFG, symbolic execution, path analysis)",
        "capstone": "Capstone (instruction-level decoding)",
        "ghidra": "Ghidra (decompilation to C, type recovery)",
        "frida": "Frida (dynamic instrumentation, runtime info)",
        "gef": "GEF/GDB (execution tracing, register snapshots)",
        "dwarf": "DWARF (debug symbols, source mappings)",
        "identification": "libmagic (file type identification)",
    }

    for key in quick.keys():
        if key.lower() in tool_descriptions:
            tools_used.append(tool_descriptions[key.lower()])
    for key in deep.keys():
        if key.lower() in tool_descriptions and tool_descriptions[key.lower()] not in tools_used:
            tools_used.append(tool_descriptions[key.lower()])

    if tools_used:
        lines.append("\n### Tools Used")
        lines.append("The following analysis tools contributed to this session:")
        for tool in tools_used:
            lines.append(f"  - {tool}")
        lines.append("")
    
    # Binary info
    r2_quick = quick.get("radare2", {}) if isinstance(quick, dict) else {}
    arch_info = "unknown"
    if isinstance(r2_quick, dict):
        bin_info = r2_quick.get("info", {})
        if isinstance(bin_info, dict):
            core = bin_info.get("core", {})
            bin_meta = bin_info.get("bin", {})
            if isinstance(core, dict):
                lines.append(f"File: {core.get('file', 'unknown')}")
                lines.append(f"Format: {core.get('format', 'unknown')}")
            if isinstance(bin_meta, dict):
                arch = bin_meta.get('arch', '?')
                bits = bin_meta.get('bits', '?')
                arch_info = f"{arch}/{bits}-bit"
                # Provide clearer arch description for ARM Thumb
                if arch == "arm" and bits == 16:
                    arch_info = "ARM32 (Thumb mode, 16-bit instructions)"
                elif arch == "arm" and bits == 32:
                    arch_info = "ARM32"
                elif arch == "arm" and bits == 64:
                    arch_info = "ARM64 (AArch64)"
                lines.append(f"Arch: {arch_info}")
                lines.append(f"OS: {bin_meta.get('os', '?')}")
                if bin_meta.get('compiler'):
                    lines.append(f"Compiler: {bin_meta.get('compiler')}")
    
    # Counts
    r2_deep = deep.get("radare2", {}) if isinstance(deep, dict) else {}
    functions = r2_deep.get("functions", []) if isinstance(r2_deep, dict) else []
    func_count = len(functions) if isinstance(functions, list) else 0
    
    imports = r2_quick.get("imports", []) if isinstance(r2_quick, dict) else []
    import_count = len(imports) if isinstance(imports, list) else 0
    
    strings = r2_quick.get("strings", []) if isinstance(r2_quick, dict) else []
    string_count = len(strings) if isinstance(strings, list) else 0
    
    lines.append(f"\nFunctions: {func_count}")
    lines.append(f"Imports: {import_count}")
    lines.append(f"Strings: {string_count}")
    
    # Top functions with addresses
    if isinstance(functions, list) and functions:
        lines.append("\nTop functions:")
        for fn in functions[:8]:
            if isinstance(fn, dict):
                name = fn.get("name", "?")
                offset = fn.get("offset")
                size = fn.get("size", 0)
                addr_str = f"0x{offset:x}" if isinstance(offset, int) else "?"
                lines.append(f"  - {name} @ {addr_str} ({size} bytes)")
    
    # Top imports
    if isinstance(imports, list) and imports:
        lines.append("\nKey imports:")
        for imp in imports[:10]:
            if isinstance(imp, dict):
                name = imp.get("name", "?")
                lines.append(f"  - {name}")
    
    # Entry point disassembly - THIS IS CRITICAL for answering ASM questions
    entry_disasm = r2_deep.get("entry_disassembly") if isinstance(r2_deep, dict) else None
    if isinstance(entry_disasm, str) and entry_disasm.strip():
        # Limit to reasonable size but include enough for context
        disasm_lines = entry_disasm.strip().split('\n')[:80]
        lines.append("\n## Entry Point Disassembly")
        lines.append("```asm")
        lines.extend(disasm_lines)
        lines.append("```")
    
    # Also include general disassembly if entry is not available
    if not entry_disasm:
        general_disasm = r2_deep.get("disassembly") if isinstance(r2_deep, dict) else None
        if isinstance(general_disasm, str) and general_disasm.strip():
            disasm_lines = general_disasm.strip().split('\n')[:60]
            lines.append("\n## Disassembly (first 60 lines)")
            lines.append("```asm")
            lines.extend(disasm_lines)
            lines.append("```")
    
    # Include function CFG snippets for richer context
    func_cfgs = r2_deep.get("function_cfgs", []) if isinstance(r2_deep, dict) else []
    if isinstance(func_cfgs, list) and func_cfgs:
        lines.append("\n## Function Details")
        for cfg in func_cfgs[:5]:  # Top 5 functions with CFG
            if isinstance(cfg, dict):
                name = cfg.get("name", "unknown")
                offset = cfg.get("offset", "?")
                block_count = cfg.get("block_count", 0)
                lines.append(f"\n### {name} @ {offset}")
                lines.append(f"Blocks: {block_count}")
                
                # Include block disassembly
                blocks = cfg.get("blocks", [])
                for block in blocks[:3]:  # First 3 blocks per function
                    if isinstance(block, dict):
                        block_offset = block.get("offset", "?")
                        block_disasm = block.get("disassembly", [])
                        if block_disasm:
                            lines.append(f"\nBlock @ {block_offset}:")
                            lines.append("```asm")
                            for instr in block_disasm[:15]:
                                if isinstance(instr, dict):
                                    addr = instr.get("addr", "")
                                    opcode = instr.get("opcode", "")
                                    lines.append(f"  {addr}  {opcode}")
                            lines.append("```")
    
    # Sample strings
    if isinstance(strings, list) and strings:
        interesting = []
        for s in strings[:50]:
            if isinstance(s, dict):
                val = s.get("string", "")
                if isinstance(val, str) and len(val) >= 6 and len(val) <= 100:
                    interesting.append(val)
        if interesting:
            lines.append("\nNotable strings:")
            for s in interesting[:8]:
                lines.append(f"  - {s}")
    
    # DWARF debug information (if available)
    dwarf_data = deep.get("dwarf", {}) if isinstance(deep, dict) else {}
    if isinstance(dwarf_data, dict) and dwarf_data.get("has_dwarf"):
        lines.append("\n## DWARF Debug Information")
        lines.append(f"DWARF Version: {dwarf_data.get('dwarf_version', '?')}")

        dwarf_functions = dwarf_data.get("functions", [])
        if isinstance(dwarf_functions, list) and dwarf_functions:
            lines.append(f"\nDebug symbols for {len(dwarf_functions)} functions:")
            for dfn in dwarf_functions[:10]:
                if isinstance(dfn, dict):
                    name = dfn.get("name", "?")
                    low_pc = dfn.get("low_pc")
                    params = dfn.get("parameters", [])
                    param_names = ", ".join(p.get("name", "?") for p in params[:5] if isinstance(p, dict))
                    addr_str = f"0x{low_pc:x}" if isinstance(low_pc, int) else "?"
                    lines.append(f"  - {name}({param_names}) @ {addr_str}")

        dwarf_types = dwarf_data.get("types", [])
        if isinstance(dwarf_types, list) and dwarf_types:
            named_types = [t for t in dwarf_types if isinstance(t, dict) and t.get("name")]
            if named_types:
                lines.append(f"\nDefined types ({len(named_types)}):")
                for dtype in named_types[:8]:
                    tag = dtype.get("tag", "").replace("DW_TAG_", "")
                    name = dtype.get("name", "?")
                    size = dtype.get("byte_size")
                    size_str = f" ({size} bytes)" if size else ""
                    lines.append(f"  - {tag}: {name}{size_str}")

        source_files = dwarf_data.get("source_files", [])
        if isinstance(source_files, list) and source_files:
            lines.append(f"\nSource files ({len(source_files)}):")
            for sf in source_files[:5]:
                lines.append(f"  - {sf}")

    # Ghidra decompilation (if available via bridge)
    ghidra_data = deep.get("ghidra", {}) if isinstance(deep, dict) else {}
    if isinstance(ghidra_data, dict) and ghidra_data.get("mode") == "bridge":
        lines.append("\n## Ghidra Decompilation")
        lines.append(f"Functions: {ghidra_data.get('function_count', 0)}")
        lines.append(f"Decompiled: {ghidra_data.get('decompiled_count', 0)}")
        lines.append(f"Types: {ghidra_data.get('type_count', 0)}")

        # Top decompiled functions with C code
        decompiled = ghidra_data.get("decompiled", [])
        if isinstance(decompiled, list) and decompiled:
            lines.append("\nDecompiled functions:")
            for func in decompiled[:5]:
                if isinstance(func, dict):
                    name = func.get("name", "?")
                    addr = func.get("address", "?")
                    sig = func.get("signature", "")
                    c_code = func.get("decompiled_c", "")
                    lines.append(f"\n### {name} @ {addr}")
                    if sig:
                        lines.append(f"Signature: `{sig}`")
                    if c_code:
                        # Truncate long decompiled code
                        c_lines = c_code.strip().split('\n')[:30]
                        lines.append("```c")
                        lines.extend(c_lines)
                        if len(c_code.strip().split('\n')) > 30:
                            lines.append("// ... truncated ...")
                        lines.append("```")

        # Key data structures (structs)
        types = ghidra_data.get("types", [])
        if isinstance(types, list) and types:
            struct_types = [t for t in types if isinstance(t, dict) and t.get("kind") == "struct"]
            if struct_types:
                lines.append("\nKey data structures:")
                for stype in struct_types[:5]:
                    name = stype.get("name", "?")
                    size = stype.get("size", 0)
                    members = stype.get("members", [])
                    lines.append(f"\n#### struct {name} ({size} bytes)")
                    if members:
                        for m in members[:10]:
                            if isinstance(m, dict):
                                mname = m.get("name", "?")
                                mtype = m.get("type", "?")
                                moffset = m.get("offset", 0)
                                lines.append(f"  +{moffset}: {mtype} {mname}")

        # Cross-reference summary
        xref_map = ghidra_data.get("xref_map", {})
        if isinstance(xref_map, dict) and xref_map:
            lines.append("\nCross-references (key functions):")
            for addr, refs in list(xref_map.items())[:5]:
                if isinstance(refs, dict):
                    to_refs = refs.get("to", [])
                    from_refs = refs.get("from", [])
                    if to_refs or from_refs:
                        lines.append(f"\n{addr}:")
                        if to_refs:
                            callers = [r.get("from_function") or r.get("from_address") for r in to_refs[:3] if isinstance(r, dict)]
                            if callers:
                                lines.append(f"  Called by: {', '.join(str(c) for c in callers)}")
                        if from_refs:
                            callees = [r.get("to_function") or r.get("to_address") for r in from_refs[:3] if isinstance(r, dict)]
                            if callees:
                                lines.append(f"  Calls: {', '.join(str(c) for c in callees)}")

    # Issues/notes
    issues = analysis.get("issues", [])
    if issues:
        lines.append(f"\nIssues: {', '.join(str(i) for i in issues[:3])}")

    return "\n".join(lines)


def _format_message_for_llm(message: StoredChatMessage) -> str:
    payload = message.content
    attachment_segments: list[str] = []
    for attachment in message.attachments or []:
        if not isinstance(attachment, dict):
            continue
        attachment_type = attachment.get("type", "attachment")
        if attachment_type == "analysis_result":
            attachment_segments.append(_render_analysis_summary(attachment))
        else:
            attachment_segments.append(
                f"[{attachment_type}] {json.dumps(attachment, default=str)[:4000]}"
            )
    if attachment_segments:
        payload += "\n\nAttachments:\n" + "\n".join(attachment_segments)
    return payload


def _extract_snippets(deep_scan: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Extract code snippets from deep scan results for session persistence."""
    snippets: list[dict[str, Any]] = []
    
    if not deep_scan:
        return snippets
    
    # Extract from angr if available
    angr_data = deep_scan.get("angr", {})
    if isinstance(angr_data, dict):
        angr_snippets = angr_data.get("snippets", [])
        for snippet in angr_snippets[:100]:
            if isinstance(snippet, dict) and snippet.get("instructions"):
                snippets.append({
                    "source": "angr",
                    "address": snippet.get("addr", "0x0"),
                    "function": snippet.get("function_name") or snippet.get("function"),
                    "instructions": snippet.get("instructions", [])[:20],
                })
    
    # Extract from radare2 if available
    r2_data = deep_scan.get("radare2", {})
    if isinstance(r2_data, dict):
        r2_snippets = r2_data.get("snippets", [])
        for snippet in r2_snippets[:100]:
            if isinstance(snippet, dict):
                for block in snippet.get("blocks", [])[:10]:
                    if block.get("disassembly"):
                        snippets.append({
                            "source": "radare2",
                            "address": block.get("offset", "0x0"),
                            "function": snippet.get("function"),
                            "instructions": block.get("disassembly", [])[:20],
                        })
    
    return snippets[:200]  # Limit total snippets


def _render_analysis_summary(analysis: dict[str, Any]) -> str:
    quick = analysis.get("quick_scan") or {}
    deep = analysis.get("deep_scan") or {}
    issues = analysis.get("issues") or []
    notes = analysis.get("notes") or []

    function_count = len(deep.get("functions", [])) if isinstance(deep.get("functions"), list) else 0
    imports = quick.get("imports") if isinstance(quick, dict) else None
    import_count = len(imports) if isinstance(imports, list) else 0

    lines = [
        "[Analysis Result]",
        f"Binary: {analysis.get('binary')}",
        f"Functions discovered: {function_count}",
        f"Imports detected: {import_count}",
    ]
    if issues:
        lines.append("Issues: " + "; ".join(str(issue) for issue in issues[:10]))
    if notes:
        lines.append("Notes: " + "; ".join(str(note) for note in notes[:10]))

    quick_info = quick.get("info") if isinstance(quick, dict) else None
    if isinstance(quick_info, dict):
        bin_meta = quick_info.get("bin")
        if isinstance(bin_meta, dict):
            arch = bin_meta.get("arch")
            compiler = bin_meta.get("compiler")
            entry = bin_meta.get("baddr")
            if arch:
                lines.append(f"Architecture: {arch}")
            if compiler:
                lines.append(f"Compiler: {compiler}")
            if entry:
                lines.append(f"Entry point: {entry:#x}")

    return "\n".join(lines)


__all__ = ["create_app"]
