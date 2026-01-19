"""Flask web frontend for r2d2 with progress streaming."""

from __future__ import annotations

import json
import queue
import threading
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from flask import Flask, Response, jsonify, request, send_from_directory
from flask_cors import CORS  # type: ignore[import-untyped]

from ..analysis import AnalysisOrchestrator, AnalysisResult
from ..llm import ChatMessage as LLMChatMessage, LLMBridge
from ..state import AppState, build_state
from ..storage.chat import ChatDAO
from ..storage.models import ChatMessage as StoredChatMessage, ChatSession
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
    CORS(app)

    # Set up debug logging for Flask
    setup_flask_debug(app)

    jobs = JobRegistry()
    chat_dao: ChatDAO = state.chat_dao
    llm_bridge = LLMBridge(state.config)

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
        # Check tool availability with install hints
        tools_status = _get_tools_status(state)
        
        return jsonify({
            "status": "ok",
            "model": llm_bridge.model,
            "provider": llm_bridge.providers[0] if llm_bridge.providers else "anthropic",
            "available_models": llm_bridge.available_models,
            "model_names": llm_bridge.model_display_names,
            "ghidra_ready": bool(state.env.ghidra and state.env.ghidra.is_ready),
            "tools": tools_status,
        })

    def _get_tools_status(state: AppState) -> dict[str, Any]:
        """Get detailed status of all analysis tools."""
        tools: dict[str, Any] = {}
        
        # Check Python packages
        def check_import(module: str) -> bool:
            try:
                __import__(module)
                return True
            except ImportError:
                return False
        
        # radare2/r2pipe
        tools["radare2"] = {
            "available": check_import("r2pipe"),
            "install_hint": "uv sync --extra analyzers",
            "description": "Disassembly, functions, imports, strings",
        }
        
        # angr
        tools["angr"] = {
            "available": check_import("angr"),
            "install_hint": "uv sync --extra analyzers",
            "description": "CFG analysis, symbolic execution",
        }
        
        # Capstone
        tools["capstone"] = {
            "available": check_import("capstone"),
            "install_hint": "uv sync --extra analyzers",
            "description": "Instruction-level disassembly",
        }
        
        # python-magic
        tools["libmagic"] = {
            "available": check_import("magic"),
            "install_hint": "uv sync --extra analyzers; brew install libmagic (macOS)",
            "description": "File type identification",
        }
        
        # Frida
        tools["frida"] = {
            "available": check_import("frida"),
            "install_hint": "uv sync --extra analyzers",
            "description": "Dynamic instrumentation",
        }
        
        # pyelftools (for DWARF)
        tools["dwarf"] = {
            "available": check_import("elftools"),
            "install_hint": "uv sync --extra analyzers",
            "description": "Debug symbol parsing",
        }
        
        # GEF/GDB (requires Docker image)
        import shutil
        import subprocess
        docker_available = shutil.which("docker") is not None
        gef_image_available = False
        if docker_available:
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
        
        # Ghidra
        ghidra_env = state.env.ghidra
        tools["ghidra"] = {
            "available": ghidra_env.is_ready or ghidra_env.bridge_available if ghidra_env else False,
            "headless_ready": ghidra_env.is_ready if ghidra_env else False,
            "bridge_available": ghidra_env.bridge_available if ghidra_env else False,
            "bridge_connected": ghidra_env.bridge_connected if ghidra_env else False,
            "install_hint": "Set GHIDRA_INSTALL_DIR or start Ghidra Bridge server",
            "description": "Decompilation, type recovery",
        }
        
        # AutoProfile (always available - pure Python)
        tools["autoprofile"] = {
            "available": True,
            "install_hint": None,
            "description": "Security profile, strings analysis",
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
            
            llm_messages = _build_llm_messages(history, analysis_attachment, activity_context)
            try:
                assistant_response = llm_bridge.chat(llm_messages)
            except RuntimeError as exc:  # pragma: no cover - handled at runtime
                response_payload["error"] = str(exc)
                response_payload["messages"] = [
                    _message_to_dict(message) for message in chat_dao.list_messages(session.session_id)
                ]
                return jsonify(response_payload), 503

            metadata_attachment = [{
                "type": "llm_response_meta",
                "provider": llm_bridge.last_provider,
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
        return jsonify({"path": str(save_path), "filename": save_path.name})

    @app.post("/api/analyze")
    def analyze() -> Any:
        body = request.get_json(silent=True) or {}
        binary_path = body.get("binary")
        user_goal = body.get("user_goal", "").strip()
        quick_only = body.get("quick_only", False)
        enable_angr = body.get("enable_angr", True)
        enable_ghidra = body.get("enable_ghidra", True)
        enable_gef = body.get("enable_gef", True)
        enable_frida = body.get("enable_frida", True)

        debug.analysis_start(binary_path or "unknown", {
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
                plan = orchestrator.create_plan(quick_only=quick_only)
                plan.run_angr = enable_angr and not quick_only
                result = orchestrator.analyze(path, plan=plan, progress_callback=_progress)
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
        """List available cross-compilers."""
        try:
            from ..compilation.compiler import detect_compilers, _is_docker_available, _docker_image_exists, DOCKER_COMPILER_IMAGE
            compilers = detect_compilers()
            
            docker_available = _is_docker_available()
            docker_image_exists = docker_available and _docker_image_exists(DOCKER_COMPILER_IMAGE)
            
            result = {}
            for arch, compiler_list in compilers.items():
                result[arch] = [
                    {
                        "name": c.name,
                        "path": str(c.path),
                        "version": c.version,
                        "is_clang": c.is_clang,
                    }
                    for c in compiler_list
                ]
            return jsonify({
                "compilers": result,
                "available_architectures": [a for a, c in compilers.items() if c],
                "docker_available": docker_available,
                "docker_image_exists": docker_image_exists,
            })
        except ImportError:
            return jsonify({
                "compilers": {},
                "available_architectures": [],
                "docker_available": False,
                "docker_image_exists": False,
                "error": "Compilation module not available",
            })

    @app.post("/api/compilers/preview")
    def preview_compile_command() -> Any:
        """Preview the compilation command that would run."""
        try:
            from ..compilation.compiler import get_compile_command_preview
            body = request.get_json(silent=True) or {}
            
            architecture = body.get("architecture", "arm64")
            optimization = body.get("optimization", "-O0")
            freestanding = body.get("freestanding", False)
            output_name = body.get("output_name", "output")
            
            preview = get_compile_command_preview(
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
            if state.dao:
                state.dao.record_action(
                    trajectory_id=session_id,
                    adapter="ghidra_scripting",
                    stage="script_generation",
                    payload={
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
            if state.dao:
                state.dao.record_action(
                    trajectory_id=session_id,
                    adapter="ghidra_scripting",
                    stage="script_execution",
                    payload={
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
            if state.dao:
                state.dao.record_action(
                    trajectory_id=session_id,
                    adapter="ghidra_scripting",
                    stage="script_execution",
                    payload={
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


def _build_llm_messages(
    history: list[StoredChatMessage],
    analysis_attachment: dict[str, Any] | None,
    activity_context: list[dict[str, Any]] | None = None,
) -> list[LLMChatMessage]:
    """Build focused LLM messages with FULL analysis context for every message.
    
    The analysis context is ALWAYS included in the system prompt to ensure
    the LLM has consistent access to binary information throughout the conversation.
    Activity context provides insight into what the user has been exploring.
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
    
    # ALWAYS include the full analysis context - this is critical for coherent responses
    if analysis_attachment:
        ctx = _build_analysis_context(analysis_attachment)
        system_parts.append(ctx)
    else:
        # Even without attachment, look for analysis in history
        for msg in history:
            if msg.role == "system":
                for att in (msg.attachments or []):
                    if isinstance(att, dict) and att.get("type") == "analysis_result":
                        ctx = _build_analysis_context(att)
                        system_parts.append(ctx)
                        break
    
    # Include activity context for better situational awareness
    if activity_context:
        activity_str = _format_activity_context(activity_context)
        if activity_str:
            system_parts.append(activity_str)
    
    system_prompt = "\n\n".join(system_parts)
    messages: list[LLMChatMessage] = [LLMChatMessage(role="system", content=system_prompt)]

    # Add conversation history - keep last 15 exchanges for context continuity
    user_messages = [m for m in history if m.role in ("user", "assistant")]
    for item in user_messages[-15:]:
        messages.append(
            LLMChatMessage(
                role=item.role,
                content=item.content,
            )
        )
    
    return messages


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
