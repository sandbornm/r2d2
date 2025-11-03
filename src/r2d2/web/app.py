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
        active_model = llm_bridge.providers[0] if llm_bridge.providers else state.config.llm.model
        return jsonify({
            "status": "ok",
            "model": active_model,
            "ghidra_ready": bool(state.env.ghidra and state.env.ghidra.is_ready),
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

    @app.post("/api/analyze")
    def analyze() -> Any:
        body = request.get_json(silent=True) or {}
        binary_path = body.get("binary")
        if not binary_path:
            return jsonify({"error": "Missing 'binary' in request body"}), 400

        path = Path(binary_path)
        if not path.exists():
            return jsonify({"error": f"Binary path does not exist: {binary_path}"}), 404

        session = chat_dao.get_or_create_session(str(path), title=path.name)

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

                analysis_attachment = {
                    "type": "analysis_result",
                    "binary": str(result.binary),
                    "plan": asdict(result.plan),
                    "quick_scan": result.quick_scan,
                    "deep_scan": result.deep_scan,
                    "notes": result.notes,
                    "issues": result.issues,
                    "trajectory_id": result.trajectory_id,
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
    def stream(job_id: str) -> Response:
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


def _build_llm_messages(
    history: list[StoredChatMessage],
    analysis_attachment: dict[str, Any] | None,
) -> list[LLMChatMessage]:
    messages: list[LLMChatMessage] = [
        LLMChatMessage(
            role="system",
            content="You are assisting with reverse engineering of ELF binaries. "
            "Use provided analysis context, point out suspicious patterns, and suggest next steps.",
        )
    ]

    include_analysis = False
    if analysis_attachment:
        summary_text = _render_analysis_summary(analysis_attachment)
        messages.append(LLMChatMessage(role="system", content=summary_text))
        include_analysis = True

    for item in history:
        messages.append(
            LLMChatMessage(
                role=item.role,
                content=_format_message_for_llm(item),
            )
        )
    conversational_start = 1 + (1 if include_analysis else 0)
    conversational_history = messages[conversational_start:]
    trimmed_history = conversational_history[-40:]
    return messages[:conversational_start] + trimmed_history


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
