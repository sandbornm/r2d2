"""Domain models for persisted trajectories."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Sequence
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


@dataclass(slots=True)
class ChatSession:
    binary_path: str
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    trajectory_id: str | None = None
    title: str | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    message_count: int = 0


AttachmentType = dict[str, Any]


@dataclass(slots=True)
class ChatMessage:
    session_id: str
    role: str
    content: str
    attachments: Sequence[AttachmentType] = field(default_factory=list)
    message_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: datetime = field(default_factory=datetime.utcnow)
