"""Domain models for persisted trajectories."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
import uuid


@dataclass(slots=True)
class TrajectoryAction:
    action: str
    payload: Any
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass(slots=True)
class AnalysisTrajectory:
    binary_path: str
    trajectory_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    actions: list[TrajectoryAction] = field(default_factory=list)

    def append(self, action: TrajectoryAction) -> None:
        self.actions.append(action)
