"""Unit tests for storage module."""

from pathlib import Path
import json

import pytest

from r2d2.storage import ChatDAO, Database
from r2d2.storage.models import (
    ChatSession,
    ChatMessage,
    TrajectoryAction,
    AnalysisTrajectory,
    CodeSnippet,
    SnippetStore,
)


class TestDatabase:
    """Tests for Database class."""

    def test_create_database(self, tmp_db_path):
        """Test creating a new database."""
        db = Database(tmp_db_path)

        assert tmp_db_path.exists()

    def test_database_creates_tables(self, tmp_db_path):
        """Test database creates required tables."""
        db = Database(tmp_db_path)

        # Check that tables exist by querying sqlite_master
        with db.connect() as conn:
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            tables = {row[0] for row in cursor.fetchall()}

        assert "trajectories" in tables
        assert "trajectory_actions" in tables
        assert "chat_sessions" in tables
        assert "chat_messages" in tables

    def test_database_connection_context_manager(self, tmp_db_path):
        """Test database connection context manager."""
        db = Database(tmp_db_path)

        with db.connect() as conn:
            cursor = conn.execute("SELECT 1")
            result = cursor.fetchone()

        assert result[0] == 1


class TestChatDAO:
    """Tests for ChatDAO class."""

    def test_create_session(self, chat_dao):
        """Test creating a new chat session."""
        session = chat_dao.get_or_create_session(
            "/tmp/test.bin",
            trajectory_id="traj-123",
            title="Test Session",
        )

        assert session.session_id is not None
        assert session.binary_path == "/tmp/test.bin"
        assert session.trajectory_id == "traj-123"
        assert session.title == "Test Session"
        assert session.message_count == 0

    def test_get_existing_session(self, chat_dao):
        """Test retrieving an existing session."""
        # Create session
        session1 = chat_dao.get_or_create_session("/tmp/test.bin")

        # Get same session
        session2 = chat_dao.get_or_create_session("/tmp/test.bin")

        assert session1.session_id == session2.session_id

    def test_append_message(self, chat_dao):
        """Test appending a message to a session."""
        session = chat_dao.get_or_create_session("/tmp/test.bin")
        message = chat_dao.append_message(
            session.session_id,
            role="user",
            content="Hello, analyze this binary",
        )

        assert message.role == "user"
        assert message.content == "Hello, analyze this binary"
        assert message.session_id == session.session_id

    def test_append_message_with_attachments(self, chat_dao):
        """Test appending a message with attachments."""
        session = chat_dao.get_or_create_session("/tmp/test.bin")
        attachments = [
            {"type": "analysis_result", "data": {"functions": 10}},
        ]
        message = chat_dao.append_message(
            session.session_id,
            role="system",
            content="Analysis complete",
            attachments=attachments,
        )

        assert message.attachments == attachments

    def test_list_messages(self, chat_dao):
        """Test listing messages for a session."""
        session = chat_dao.get_or_create_session("/tmp/test.bin")

        # Add multiple messages
        chat_dao.append_message(session.session_id, "user", "Message 1")
        chat_dao.append_message(session.session_id, "assistant", "Response 1")
        chat_dao.append_message(session.session_id, "user", "Message 2")

        messages = chat_dao.list_messages(session.session_id)

        assert len(messages) == 3
        assert messages[0].content == "Message 1"
        assert messages[1].role == "assistant"

    def test_list_sessions(self, chat_dao):
        """Test listing all sessions."""
        # Create multiple sessions
        chat_dao.get_or_create_session("/tmp/test1.bin")
        chat_dao.get_or_create_session("/tmp/test2.bin")
        chat_dao.get_or_create_session("/tmp/test3.bin")

        sessions = chat_dao.list_sessions()

        assert len(sessions) >= 3

    def test_session_message_count_updates(self, chat_dao):
        """Test session message count updates after appending."""
        session = chat_dao.get_or_create_session("/tmp/test.bin")
        assert session.message_count == 0

        chat_dao.append_message(session.session_id, "user", "Hello")

        # Get updated session
        updated = chat_dao.get_or_create_session("/tmp/test.bin")
        assert updated.message_count == 1


class TestStorageModels:
    """Tests for storage models."""

    def test_chat_session_model(self):
        """Test ChatSession model creation."""
        session = ChatSession(
            binary_path="/tmp/test.bin",
            session_id="test-123",
            trajectory_id="traj-456",
            title="Test Session",
            message_count=5,
        )

        assert session.session_id == "test-123"
        assert session.message_count == 5

    def test_chat_message_model(self):
        """Test ChatMessage model creation."""
        message = ChatMessage(
            session_id="session-456",
            role="user",
            content="Test message",
            attachments=[],
            message_id="msg-123",
        )

        assert message.message_id == "msg-123"
        assert message.role == "user"

    def test_trajectory_action_model(self):
        """Test TrajectoryAction model creation."""
        action = TrajectoryAction(
            action="radare2.quick",
            payload={"functions": 10, "strings": 50},
        )

        assert action.action == "radare2.quick"
        assert action.payload["functions"] == 10

    def test_analysis_trajectory_model(self):
        """Test AnalysisTrajectory model creation."""
        trajectory = AnalysisTrajectory(
            binary_path="/tmp/test.bin",
            trajectory_id="traj-123",
        )
        trajectory.append(TrajectoryAction("libmagic.quick", {"type": "ELF"}))
        trajectory.append(TrajectoryAction("radare2.quick", {"functions": 5}))

        assert trajectory.trajectory_id == "traj-123"
        assert len(trajectory.actions) == 2

    def test_code_snippet_model(self):
        """Test CodeSnippet model creation."""
        snippet = CodeSnippet(
            address="0x1000",
            function_name="main",
            instructions=[
                {"addr": "0x1000", "mnemonic": "push", "op_str": "{fp, lr}"},
            ],
            source="radare2",
        )

        assert snippet.address == "0x1000"
        assert snippet.source == "radare2"
        assert len(snippet.instructions) == 1

    def test_snippet_store_model(self):
        """Test SnippetStore model creation."""
        store = SnippetStore(
            session_id="test-session",
            binary_path="/tmp/test.bin",
        )
        store.add_snippet(CodeSnippet("0x1000", "main", None, None, [], "radare2"))
        store.add_snippet(CodeSnippet("0x1100", "helper", None, None, [], "angr"))

        assert len(store.snippets) == 2

    def test_snippet_store_add_from_angr(self):
        """Test adding snippets from angr data."""
        store = SnippetStore(
            session_id="test-session",
            binary_path="/tmp/test.bin",
        )
        block_data = {
            "addr": "0x1000",
            "function_name": "main",
            "function": "0x1000",
            "bytes": "04e02de5",
            "instructions": [
                {"addr": "0x1000", "mnemonic": "push", "op_str": "{fp, lr}"},
            ],
        }

        store.add_from_angr(block_data)

        assert len(store.snippets) == 1
        assert store.snippets[0].source == "angr"
        assert store.snippets[0].function_name == "main"

    def test_snippet_store_add_from_radare2(self):
        """Test adding snippets from radare2 data."""
        store = SnippetStore(
            session_id="test-session",
            binary_path="/tmp/test.bin",
        )
        block_data = {
            "offset": "0x1000",
            "function": "main",
            "disassembly": [
                {"addr": "0x1000", "opcode": "push {fp, lr}", "bytes": "04e02de5"},
            ],
        }

        store.add_from_radare2(block_data)

        assert len(store.snippets) == 1
        assert store.snippets[0].source == "radare2"

    def test_snippet_to_dict(self):
        """Test CodeSnippet to_dict serialization."""
        snippet = CodeSnippet(
            address="0x1000",
            function_name="main",
            instructions=[{"addr": "0x1000", "mnemonic": "nop"}],
            source="radare2",
        )

        data = snippet.to_dict()

        assert data["address"] == "0x1000"
        assert data["function_name"] == "main"
        assert data["source"] == "radare2"
        assert "created_at" in data

    def test_snippet_from_dict(self):
        """Test CodeSnippet from_dict deserialization."""
        data = {
            "address": "0x1000",
            "function_name": "main",
            "source": "angr",
            "instructions": [],
        }

        snippet = CodeSnippet.from_dict(data)

        assert snippet.address == "0x1000"
        assert snippet.function_name == "main"
        assert snippet.source == "angr"

    def test_snippet_store_to_dict(self):
        """Test SnippetStore to_dict serialization."""
        store = SnippetStore(
            session_id="test-session",
            binary_path="/tmp/test.bin",
        )
        store.add_snippet(CodeSnippet("0x1000", "main", None, None, [], "radare2"))

        data = store.to_dict()

        assert data["session_id"] == "test-session"
        assert data["snippet_count"] == 1
        assert len(data["snippets"]) == 1
