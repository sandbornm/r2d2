"""Flask web frontend for r2d2 with progress streaming."""

from __future__ import annotations

import json
import queue
import threading
import uuid
from pathlib import Path
from typing import Any, Optional

from flask import Flask, Response, jsonify, request, send_from_directory
from flask_cors import CORS

from ..analysis import AnalysisOrchestrator, AnalysisResult
from ..state import AppState, build_state
from ..utils.serialization import to_json


class Job:
    def __init__(self, job_id: str) -> None:
        self.id = job_id
        self.queue: "queue.Queue[dict[str, Any]]" = queue.Queue()
        self.status = "queued"
        self.result: AnalysisResult | None = None
        self.error: str | None = None

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
            "model": state.config.llm.model,
            "ghidra_ready": bool(state.env.ghidra and state.env.ghidra.is_ready),
        })

    @app.get("/api/environment")
    def environment() -> Any:
        return jsonify(_serialize(state.env))

    @app.post("/api/analyze")
    def analyze() -> Any:
        body = request.get_json(silent=True) or {}
        binary_path = body.get("binary")
        if not binary_path:
            return jsonify({"error": "Missing 'binary' in request body"}), 400

        path = Path(binary_path)
        if not path.exists():
            return jsonify({"error": f"Binary path does not exist: {binary_path}"}), 404

        job = jobs.create()
        job.status = "running"
        def _progress(event: str, payload: dict[str, Any]) -> None:
            job.put(event, payload)

        def _worker() -> None:
            job.put("job_started", {"binary": binary_path})
            try:
                orchestrator = AnalysisOrchestrator(state.config, state.env, trajectory_dao=state.dao)
                result = orchestrator.analyze(path, progress_callback=_progress)
                job.result = result
                job.status = "completed"
                job.put("analysis_result", _serialize(result))
                job.put("job_completed", {"issues": result.issues, "notes": result.notes})
            except Exception as exc:  # pragma: no cover - defensive
                job.error = str(exc)
                job.status = "failed"
                job.put("job_failed", {"error": str(exc)})
            finally:
                job.put("__close__")

        thread = threading.Thread(target=_worker, name=f"job-{job.id}", daemon=True)
        thread.start()

        return jsonify({"job_id": job.id})

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
                yield f"event: {event}\n"
                yield f"data: {json.dumps(data)}\n\n"

        return Response(_event_stream(), mimetype="text/event-stream")

    return app


__all__ = ["create_app"]
