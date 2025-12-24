"""Integration tests for the Flask API."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

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
