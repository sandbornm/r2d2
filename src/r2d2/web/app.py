"""Flask web frontend for r2d2 with progress streaming."""

from __future__ import annotations

import json
import queue
import threading
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from flask import Flask, Response, jsonify, request, send_from_directory
from flask_cors import CORS

from ..analysis import AnalysisOrchestrator, AnalysisResult
from ..llm import ChatMessage as LLMChatMessage, LLMBridge
from ..state import AppState, build_state
from ..storage.chat import ChatDAO
from ..storage.models import ChatMessage as StoredChatMessage, ChatSession
from ..utils.serialization import to_json


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
        return jsonify({
            "status": "ok",
            "model": llm_bridge.model,
            "provider": llm_bridge.providers[0] if llm_bridge.providers else "anthropic",
            "available_models": llm_bridge.available_models,
            "model_names": llm_bridge.model_display_names,
            "ghidra_ready": bool(state.env.ghidra and state.env.ghidra.is_ready),
        })

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
            llm_messages = _build_llm_messages(history, analysis_attachment)
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
        
        if not binary_path:
            return jsonify({"error": "Missing 'binary' in request body"}), 400

        path = Path(binary_path)
        if not path.exists():
            return jsonify({"error": f"Binary path does not exist: {binary_path}"}), 404

        session = chat_dao.get_or_create_session(str(path), title=path.name)
        
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
                orchestrator = AnalysisOrchestrator(state.config, state.env, trajectory_dao=state.dao)
                result = orchestrator.analyze(path, progress_callback=_progress)
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
            extra_flags = []
            if freestanding:
                extra_flags = ["-ffreestanding", "-nostdlib", "-static"]

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
        original_binary = body.get("original_binary", "").strip()
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

    return app


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


def _build_llm_messages(
    history: list[StoredChatMessage],
    analysis_attachment: dict[str, Any] | None,
) -> list[LLMChatMessage]:
    """Build focused LLM messages with FULL analysis context for every message.
    
    The analysis context is ALWAYS included in the system prompt to ensure
    the LLM has consistent access to binary information throughout the conversation.
    """
    
    user_goal = _extract_user_goal(history)
    
    # Build system prompt - friendly but technical
    system_parts = [
        """You are r2d2, a friendly reverse engineering assistant built for learning ARM assembly and binary analysis.

## Your Role
Help users understand binaries at their level. Start simple, go deeper when asked.

## Frontend Tools (mention these naturally when helpful)
- **Summary**: Quick view of binary info, functions, imports, strings
- **Disassembly**: Hover any ARM/x86 instruction for docs • Drag to select code • "Ask Claude" to explain
- **CFG**: Control flow graph with function list
- **Annotations**: Click 📝 or drag-select to add notes that persist

## Style
- First response: 2-3 sentences max. What is it? What stands out?
- Follow-ups: Go as deep as needed
- Use code blocks for assembly snippets
- Reference addresses like `0x1234` and function names
- If binary looks packed/encrypted/unusual, say so upfront""",
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
    """Build a compact analysis context for the LLM including actual disassembly."""
    quick = analysis.get("quick_scan") or {}
    deep = analysis.get("deep_scan") or {}
    
    lines = ["## Analysis Results"]
    
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
