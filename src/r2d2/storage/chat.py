"""Chat session persistence helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable

from .db import Database
from .models import AttachmentType, ChatMessage, ChatSession


class ChatDAO:
    """Manage persisted chat sessions and messages for analysis transcripts."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # Session management -------------------------------------------------
    def get_or_create_session(
        self,
        binary_path: str,
        trajectory_id: str | None = None,
        *,
        title: str | None = None,
    ) -> ChatSession:
        with self._db.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM chat_sessions
                WHERE binary_path = ?
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (binary_path,),
            ).fetchone()
            if row:
                session = self._row_to_session(row)
                needs_update = False
                if trajectory_id and session.trajectory_id != trajectory_id:
                    session.trajectory_id = trajectory_id
                    needs_update = True
                if title and not session.title:
                    session.title = title
                    needs_update = True
                if needs_update:
                    session.updated_at = datetime.now(timezone.utc)
                    conn.execute(
                        """
                        UPDATE chat_sessions
                        SET trajectory_id = ?, title = ?, updated_at = ?
                        WHERE session_id = ?
                        """,
                        (
                            session.trajectory_id,
                            session.title,
                            session.updated_at.isoformat(),
                            session.session_id,
                        ),
                    )
                return session

            session = ChatSession(binary_path=binary_path, trajectory_id=trajectory_id, title=title)
            conn.execute(
                """
                INSERT INTO chat_sessions (session_id, binary_path, trajectory_id, title, created_at, updated_at, message_count)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.binary_path,
                    session.trajectory_id,
                    session.title,
                    session.created_at.isoformat(),
                    session.updated_at.isoformat(),
                    session.message_count,
                ),
            )
            return session

    def list_sessions(self, limit: int = 20) -> list[ChatSession]:
        with self._db.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM chat_sessions
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_session(row) for row in rows]

    def get_session(self, session_id: str) -> ChatSession | None:
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM chat_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if not row:
            return None
        return self._row_to_session(row)

    def list_sessions_for_binary(self, binary_path: str) -> list[ChatSession]:
        with self._db.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM chat_sessions
                WHERE binary_path = ?
                ORDER BY updated_at DESC
                """,
                (binary_path,),
            ).fetchall()
        return [self._row_to_session(row) for row in rows]

    def delete_session(self, session_id: str) -> bool:
        """Delete a session and all its messages."""
        with self._db.connect() as conn:
            # Delete messages first
            conn.execute(
                "DELETE FROM chat_messages WHERE session_id = ?",
                (session_id,),
            )
            # Delete session
            result = conn.execute(
                "DELETE FROM chat_sessions WHERE session_id = ?",
                (session_id,),
            )
            return result.rowcount > 0

    # Message management -------------------------------------------------
    def append_message(
        self,
        session_id: str,
        role: str,
        content: str,
        *,
        attachments: Iterable[AttachmentType] | None = None,
    ) -> ChatMessage:
        message = ChatMessage(
            session_id=session_id,
            role=role,
            content=content,
            attachments=list(attachments or []),
        )
        with self._db.connect() as conn:
            conn.execute(
                """
                INSERT INTO chat_messages (message_id, session_id, role, content, attachments, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    message.message_id,
                    message.session_id,
                    message.role,
                    message.content,
                    json.dumps(message.attachments),
                    message.created_at.isoformat(),
                ),
            )
            conn.execute(
                """
                UPDATE chat_sessions
                SET updated_at = ?, message_count = message_count + 1
                WHERE session_id = ?
                """,
                (
                    message.created_at.isoformat(),
                    session_id,
                ),
            )
        return message

    def list_messages(self, session_id: str, limit: int = 100) -> list[ChatMessage]:
        with self._db.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM chat_messages
                WHERE session_id = ?
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (session_id, limit),
            ).fetchall()
        return [self._row_to_message(row) for row in rows]

    # Internal helpers ---------------------------------------------------
    @staticmethod
    def _row_to_session(row) -> ChatSession:
        session = ChatSession(
            binary_path=row["binary_path"],
            session_id=row["session_id"],
            trajectory_id=row["trajectory_id"],
            title=row["title"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            message_count=row["message_count"] or 0,
        )
        return session

    @staticmethod
    def _row_to_message(row) -> ChatMessage:
        attachments_raw = row["attachments"] or "[]"
        try:
            attachments = json.loads(attachments_raw)
        except json.JSONDecodeError:
            attachments = []
        message = ChatMessage(
            session_id=row["session_id"],
            role=row["role"],
            content=row["content"],
            attachments=attachments,
            message_id=row["message_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )
        return message


__all__ = ["ChatDAO"]
