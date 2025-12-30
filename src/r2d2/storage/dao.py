"""Data access helpers for trajectory storage."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .db import Database
from .models import AnalysisTrajectory, TrajectoryAction


class TrajectoryDAO:
    def __init__(self, db: Database) -> None:
        self._db = db

    def start_trajectory(self, binary_path: str | "Path") -> AnalysisTrajectory:
        trajectory = AnalysisTrajectory(binary_path=str(binary_path))
        with self._db.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO trajectories (trajectory_id, binary_path, created_at) VALUES (?, ?, ?)",
                (trajectory.trajectory_id, trajectory.binary_path, trajectory.created_at.isoformat()),
            )
        return trajectory

    def append_action(self, trajectory: AnalysisTrajectory, action: TrajectoryAction) -> None:
        trajectory.append(action)
        with self._db.connect() as conn:
            seq = self._next_seq(conn, trajectory.trajectory_id)
            conn.execute(
                """
                INSERT INTO trajectory_actions (trajectory_id, seq, action, payload, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    trajectory.trajectory_id,
                    seq,
                    action.action,
                    json.dumps(action.payload, default=str),
                    action.created_at.isoformat(),
                ),
            )

    def finish_trajectory(self, trajectory: AnalysisTrajectory) -> None:
        trajectory.completed_at = datetime.now(timezone.utc)
        with self._db.connect() as conn:
            conn.execute(
                "UPDATE trajectories SET completed_at = ? WHERE trajectory_id = ?",
                (trajectory.completed_at.isoformat(), trajectory.trajectory_id),
            )

    def list_recent(self, limit: int = 5) -> Iterable[AnalysisTrajectory]:
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM trajectories ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        for row in rows:
            trajectory = AnalysisTrajectory(
                binary_path=row["binary_path"],
                trajectory_id=row["trajectory_id"],
                created_at=datetime.fromisoformat(row["created_at"]),
                completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
            )
            yield trajectory

    @staticmethod
    def _next_seq(conn: Any, trajectory_id: str) -> int:
        seq = conn.execute(
            "SELECT MAX(seq) FROM trajectory_actions WHERE trajectory_id = ?",
            (trajectory_id,),
        ).fetchone()[0]
        return int(seq or 0) + 1
