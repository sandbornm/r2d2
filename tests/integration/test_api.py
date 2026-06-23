"""Integration tests for the Flask API."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

# Mark all tests in this module as integration tests
pytestmark = pytest.mark.integration


@pytest.fixture
def minimal_elf(tmp_path: Path) -> Path:
    """Create a minimal ELF file for testing."""
    elf_path = tmp_path / "test_binary.elf"
    # Minimal 64-bit ELF header
    elf_bytes = (
        b'\x7fELF'                      # Magic
        b'\x02'                          # 64-bit
        b'\x01'                          # Little endian
        b'\x01'                          # ELF version
        b'\x00'                          # OS/ABI
        + b'\x00' * 8                    # Padding
        + b'\x02\x00'                    # Type: executable
        + b'\x3e\x00'                    # Machine: x86-64
        + b'\x01\x00\x00\x00'           # Version
        + b'\x00' * 48                   # Rest of header
    )
    elf_path.write_bytes(elf_bytes)
    return elf_path


@pytest.fixture
def app_client(tmp_path: Path):
    """Create a test client for the Flask app."""
    # Create a temporary config with test database
    from r2d2.web.app import create_app

    with patch.dict('os.environ', {'R2D2_WEB_DEBUG': 'false'}):
        # Patch the config to use tmp_path for database
        with patch('r2d2.config.load_config') as mock_config:
            from r2d2.config import AppConfig, StorageSettings, AnalysisSettings

            test_config = AppConfig()
            test_config.storage = StorageSettings(
                database_path=tmp_path / "test.db",
                auto_migrate=True,
            )
            test_config.analysis = AnalysisSettings(
                enable_angr=False,
                enable_ghidra=False,
                require_elf=False,
            )
            mock_config.return_value = test_config

            app = create_app()
            app.config['TESTING'] = True

            with app.test_client() as client:
                yield client


class TestHealthEndpoint:
    """Tests for /api/health endpoint."""

    def test_health_returns_ok(self, app_client):
        """Test health endpoint returns OK status."""
        response = app_client.get('/api/health')

        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'ok'
        assert 'model' in data
        assert 'provider' in data
        assert data['features']['show_compiler'] is False

    def test_health_includes_model_info(self, app_client):
        """Test health includes model information."""
        response = app_client.get('/api/health')
        data = response.get_json()

        assert 'available_models' in data
        assert isinstance(data['available_models'], list)


class TestModelsEndpoint:
    """Tests for /api/models endpoint."""

    def test_list_models(self, app_client):
        """Test listing available models."""
        response = app_client.get('/api/models')

        assert response.status_code == 200
        data = response.get_json()
        assert 'models' in data
        assert 'current' in data

    def test_set_model_requires_model_param(self, app_client):
        """Test set model requires model parameter."""
        response = app_client.post(
            '/api/models',
            json={},
            content_type='application/json',
        )

        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data


class TestEnvironmentEndpoint:
    """Tests for /api/environment endpoint."""

    def test_environment_returns_report(self, app_client):
        """Test environment endpoint returns tool status."""
        response = app_client.get('/api/environment')

        assert response.status_code == 200
        data = response.get_json()
        assert 'python_version' in data
        assert 'tools' in data


class TestChatsEndpoint:
    """Tests for /api/chats endpoints."""

    def test_list_chats_empty(self, app_client):
        """Test listing chats when empty."""
        response = app_client.get('/api/chats')

        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)

    def test_list_chats_with_limit(self, app_client):
        """Test listing chats with limit parameter."""
        response = app_client.get('/api/chats?limit=5')

        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)

    def test_chat_detail_not_found(self, app_client):
        """Test getting non-existent chat session."""
        response = app_client.get('/api/chats/nonexistent-session-id')

        assert response.status_code == 404

    def test_delete_chat_not_found(self, app_client):
        """Test deleting non-existent chat session."""
        response = app_client.delete('/api/chats/nonexistent-session-id')

        assert response.status_code == 404

    def test_chat_bundle_exports_json_and_markdown(self, app_client, minimal_elf):
        """Test compact analysis bundle export for an existing chat session."""
        analyze_response = app_client.post(
            '/api/analyze',
            json={
                'binary': str(minimal_elf),
                'quick_only': True,
                'enable_angr': False,
                'enable_ghidra': False,
                'enable_gef': False,
                'enable_frida': False,
            },
            content_type='application/json',
        )
        session_id = analyze_response.get_json()['session_id']
        attachment = {
            "type": "analysis_result",
            "binary": str(minimal_elf),
            "plan": {"quick": True, "deep": False, "run_angr": False, "persist_trajectory": True},
            "quick_scan": {
                "firmware": {
                    "top_level_format": "firmware_container",
                    "container_type": "filesystem_image",
                    "sha256": "abc123",
                    "size_bytes": 1024,
                    "scan": {"signature_count": 2},
                    "embedded_artifacts": [{"kind": "squashfs", "name": "SquashFS"}],
                    "recommended_targets": [{"kind": "squashfs"}],
                    "carved_targets": [{"path": "/tmp/rootfs"}],
                },
                "radare2": {"info": {"bin": {"arch": "arm", "bits": 32, "os": "linux"}, "core": {"format": "elf"}}},
            },
            "deep_scan": {},
            "notes": ["firmware inventory completed"],
            "issues": ["missing ghidra_gdb"],
            "trajectory_id": "traj-test",
            "tool_availability": {"firmware": True, "angr_mcp": False},
            "tool_status": {"firmware": {"status": "completed", "functions_count": 0}},
            "evidence_coverage": {
                "columns": ["metadata"],
                "rows": ["ghidra_gdb"],
                "matrix": {"ghidra_gdb": {"metadata": "missing"}},
            },
            "analysis_graph": {
                "schema_version": "r2d2.analysis_graph.v1",
                "binary": str(minimal_elf),
                "generated_at": "2026-01-01T00:00:00Z",
                "nodes": [
                    {"id": "issue:1", "kind": "issue", "label": "missing ghidra_gdb", "properties": {}},
                    {"id": "string:1", "kind": "string", "label": "http://example", "address": "0x1000", "properties": {}},
                ],
                "edges": [],
                "summary": {"node_count": 2, "edge_count": 0, "tools": ["firmware"]},
            },
        }
        message_response = app_client.post(
            f'/api/chats/{session_id}/messages',
            json={"content": "synthetic analysis", "attachments": [attachment]},
            content_type='application/json',
        )
        assert message_response.status_code == 200

        bundle_response = app_client.get(f'/api/chats/{session_id}/bundle')
        assert bundle_response.status_code == 200
        bundle = bundle_response.get_json()
        assert bundle["schema_version"] == "r2d2.analysis_bundle.v1"
        assert bundle["schema_url"] == "schemas/analysis_bundle.schema.json"
        assert bundle["subject"]["sha256"] == "abc123"
        assert bundle["findings"]["evidence_gaps"] == ["ghidra_gdb: missing metadata"]
        assert "report_markdown" in bundle

        markdown_response = app_client.get(f'/api/chats/{session_id}/bundle?format=markdown')
        assert markdown_response.status_code == 200
        assert markdown_response.mimetype == "text/markdown"
        assert "# r2d2 Analysis Report" in markdown_response.get_data(as_text=True)


class TestAnalyzeEndpoint:
    """Tests for /api/analyze endpoint."""

    def test_analyze_requires_binary(self, app_client):
        """Test analyze endpoint requires binary path."""
        response = app_client.post(
            '/api/analyze',
            json={},
            content_type='application/json',
        )

        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data
        assert 'binary' in data['error'].lower()

    def test_analyze_binary_not_found(self, app_client):
        """Test analyze with non-existent binary."""
        response = app_client.post(
            '/api/analyze',
            json={'binary': '/nonexistent/path/to/binary'},
            content_type='application/json',
        )

        assert response.status_code == 404
        data = response.get_json()
        assert 'error' in data

    def test_analyze_returns_job_id(self, app_client, minimal_elf):
        """Test analyze returns job ID for valid binary."""
        response = app_client.post(
            '/api/analyze',
            json={'binary': str(minimal_elf)},
            content_type='application/json',
        )

        assert response.status_code == 200
        data = response.get_json()
        assert 'job_id' in data
        assert 'session_id' in data


class TestUploadEndpoint:
    """Tests for /api/upload endpoint."""

    def test_upload_requires_file(self, app_client):
        """Test upload requires file parameter."""
        response = app_client.post('/api/upload')

        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data

    def test_upload_file(self, app_client, minimal_elf):
        """Test uploading a file."""
        with open(minimal_elf, 'rb') as f:
            response = app_client.post(
                '/api/upload',
                data={'file': (f, 'test_binary.elf')},
                content_type='multipart/form-data',
            )

        assert response.status_code == 200
        data = response.get_json()
        assert 'path' in data
        assert 'filename' in data
        assert 'size_bytes' in data
        assert 'max_size_bytes' in data

    def test_upload_rejects_file_over_limit(self, app_client, tmp_path):
        """Test oversized uploads return JSON error."""
        app_client.application.config['MAX_CONTENT_LENGTH'] = 8
        oversized = tmp_path / "oversized.bin"
        oversized.write_bytes(b"A" * 64)

        with open(oversized, 'rb') as f:
            response = app_client.post(
                '/api/upload',
                data={'file': (f, 'oversized.bin')},
                content_type='multipart/form-data',
            )

        assert response.status_code == 413
        data = response.get_json()
        assert 'hard limit' in data['error']


class TestChatMessagesEndpoint:
    """Tests for /api/chats/<session_id>/messages endpoint."""

    def test_post_message_to_invalid_session(self, app_client):
        """Test posting message to non-existent session."""
        response = app_client.post(
            '/api/chats/nonexistent-session/messages',
            json={'content': 'test message'},
            content_type='application/json',
        )

        assert response.status_code == 404

    def test_post_message_requires_content(self, app_client, minimal_elf):
        """Test posting message requires content or attachments."""
        # First create a session via analyze
        analyze_response = app_client.post(
            '/api/analyze',
            json={'binary': str(minimal_elf)},
            content_type='application/json',
        )
        session_id = analyze_response.get_json()['session_id']

        # Try to post empty message
        response = app_client.post(
            f'/api/chats/{session_id}/messages',
            json={'content': ''},
            content_type='application/json',
        )

        assert response.status_code == 400

    def test_llm_error_returns_service_unavailable(self, app_client, minimal_elf):
        """Test LLM failures return JSON 503 instead of bubbling as 500."""
        from r2d2.llm import LLMError

        analyze_response = app_client.post(
            '/api/analyze',
            json={'binary': str(minimal_elf)},
            content_type='application/json',
        )
        session_id = analyze_response.get_json()['session_id']

        with patch('r2d2.web.app.LLMBridge.chat', side_effect=LLMError("model missing")):
            response = app_client.post(
                f'/api/chats/{session_id}/messages',
                json={'content': 'summarize briefly', 'call_llm': True},
                content_type='application/json',
            )

        assert response.status_code == 503
        data = response.get_json()
        assert data['error'] == "model missing"
        assert any(message['role'] == 'user' for message in data['messages'])


class TestAnnotationsEndpoint:
    """Tests for /api/chats/<session_id>/annotations endpoints."""

    def test_list_annotations_invalid_session(self, app_client):
        """Test listing annotations for non-existent session."""
        response = app_client.get('/api/chats/nonexistent/annotations')

        assert response.status_code == 404

    def test_create_annotation_requires_address(self, app_client, minimal_elf):
        """Test creating annotation requires address."""
        # Create a session
        analyze_response = app_client.post(
            '/api/analyze',
            json={'binary': str(minimal_elf)},
            content_type='application/json',
        )
        session_id = analyze_response.get_json()['session_id']

        response = app_client.post(
            f'/api/chats/{session_id}/annotations',
            json={'note': 'test note'},
            content_type='application/json',
        )

        assert response.status_code == 400


class TestJobStreamEndpoint:
    """Tests for /api/jobs/<job_id>/stream endpoint."""

    def test_stream_invalid_job(self, app_client):
        """Test streaming non-existent job returns 404."""
        response = app_client.get('/api/jobs/nonexistent-job-id/stream')

        # Note: This returns a tuple (Response, status_code) for error
        assert response.status_code == 404
