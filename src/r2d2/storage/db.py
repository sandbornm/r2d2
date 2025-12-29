"""SQLite database helpers."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterator


class Database:
    """Thin wrapper around sqlite3 for app needs."""

    def __init__(self, path: Path) -> None:
        self._path = path.expanduser()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    @property
    def path(self) -> Path:
        return self._path

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _ensure_schema(self) -> None:
        with sqlite3.connect(self._path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS trajectories (
                    trajectory_id TEXT PRIMARY KEY,
                    binary_path TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    notes TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS trajectory_actions (
                    trajectory_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    payload TEXT,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (trajectory_id, seq),
                    FOREIGN KEY (trajectory_id) REFERENCES trajectories (trajectory_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chat_sessions (
                    session_id TEXT PRIMARY KEY,
                    binary_path TEXT NOT NULL,
                    trajectory_id TEXT,
                    title TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    message_count INTEGER DEFAULT 0
                )
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chat_messages (
                    message_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    attachments TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES chat_sessions (session_id) ON DELETE CASCADE
                )
                """
            )
            
            # Annotations for disassembly lines
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS annotations (
                    annotation_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    binary_path TEXT NOT NULL,
                    address TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES chat_sessions (session_id) ON DELETE CASCADE,
                    UNIQUE (session_id, address)
                )
                """
            )
            
            # User activity events for context tracking
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS activity_events (
                    event_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_data TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES chat_sessions (session_id) ON DELETE CASCADE
                )
                """
            )
            
            # Index for efficient activity lookups
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_activity_session_time 
                ON activity_events (session_id, created_at DESC)
                """
            )

    def iter_actions(self, trajectory_id: str) -> Iterator[sqlite3.Row]:
        with self.connect() as conn:
            yield from conn.execute(
                "SELECT * FROM trajectory_actions WHERE trajectory_id = ? ORDER BY seq",
                (trajectory_id,),
            )
