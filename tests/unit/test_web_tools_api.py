"""Tests for tool execution API endpoints."""

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture
def client():
    """Create test client with mocked dependencies."""
    with patch('r2d2.web.app.build_state') as mock_build:
        mock_state = MagicMock()
        mock_state.chat_dao = MagicMock()
        mock_state.config.ghidra.use_bridge = False
        mock_state.env.ghidra.bridge_connected = False
        mock_state.env.ghidra.is_ready = False
        mock_state.dao = None
        mock_state.db = None
        mock_build.return_value = mock_state

        from r2d2.web.app import create_app
        app = create_app()
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client


class TestToolsExecuteEndpoint:
    """Test POST /api/tools/execute endpoint."""

    def test_execute_requires_tool(self, client):
        """Returns 400 when tool is missing."""
        response = client.post('/api/tools/execute', json={
            'script': 'print("hello")',
            'language': 'python',
        })
        assert response.status_code == 400
        assert 'tool' in response.get_json()['error'].lower()

    def test_execute_requires_script(self, client):
        """Returns 400 when script is missing."""
        response = client.post('/api/tools/execute', json={
            'tool': 'ghidra',
            'language': 'python',
        })
        assert response.status_code == 400
        assert 'script' in response.get_json()['error'].lower()

    def test_execute_validates_tool_name(self, client):
        """Returns 400 for invalid tool name."""
        response = client.post('/api/tools/execute', json={
            'tool': 'invalid_tool',
            'script': 'print("hello")',
            'language': 'python',
        })
        assert response.status_code == 400
        assert 'tool' in response.get_json()['error'].lower()

    def test_execute_validates_language(self, client):
        """Returns 400 for invalid language."""
        response = client.post('/api/tools/execute', json={
            'tool': 'ghidra',
            'script': 'print("hello")',
            'language': 'invalid_lang',
        })
        assert response.status_code == 400
        assert 'language' in response.get_json()['error'].lower()

    def test_execute_returns_validation_errors(self, client):
        """Returns validation errors for invalid script."""
        response = client.post('/api/tools/execute', json={
            'tool': 'ghidra',
            'script': 'def broken(',  # Invalid Python syntax
            'language': 'python',
        })
        data = response.get_json()
        assert 'validation' in data
        assert data['validation']['valid'] is False
        assert len(data['validation']['errors']) > 0

    def test_execute_ghidra_without_bridge_returns_error(self, client):
        """Returns error when Ghidra bridge not configured."""
        response = client.post('/api/tools/execute', json={
            'tool': 'ghidra',
            'script': 'print("hello")',
            'language': 'python',
        })
        data = response.get_json()
        # Script is valid but Ghidra bridge not available
        assert 'validation' in data
        assert data['validation']['valid'] is True
        assert 'error' in data
        assert 'ghidra' in data['error'].lower() or 'bridge' in data['error'].lower()

    def test_execute_radare2_without_r2pipe_returns_error(self, client):
        """Returns error when r2pipe not initialized."""
        response = client.post('/api/tools/execute', json={
            'tool': 'radare2',
            'script': 'aaa',
            'language': 'r2',
        })
        data = response.get_json()
        # Validation passes but execution fails
        assert 'validation' in data
        # r2 commands don't have syntax checking like Python, so they validate
        # But execution should fail without r2pipe
        assert 'error' in data or (
            data.get('execution') and data['execution'].get('status') == 'error'
        )

    def test_execute_success_returns_output(self, client):
        """Returns execution output on success."""
        with patch('r2d2.web.app.build_state') as mock_build:
            mock_state = MagicMock()
            mock_state.chat_dao = MagicMock()
            mock_state.config.ghidra.use_bridge = True
            mock_state.env.ghidra.bridge_connected = True
            mock_state.ghidra_client = MagicMock()
            mock_state.ghidra_client.is_connected.return_value = True
            mock_state.ghidra_client.execute_script.return_value = {
                'output': 'Hello from Ghidra',
                'error': None,
            }
            mock_state.dao = None
            mock_state.db = None
            mock_build.return_value = mock_state

            from r2d2.web.app import create_app
            app = create_app()
            app.config['TESTING'] = True

            with app.test_client() as test_client:
                response = test_client.post('/api/tools/execute', json={
                    'tool': 'ghidra',
                    'script': 'print("hello")',
                    'language': 'python',
                    'session_id': 'test-session',
                })

                assert response.status_code == 200
                data = response.get_json()
                assert data['validation']['valid'] is True
                assert data['execution']['status'] == 'success'
                assert 'Hello from Ghidra' in data['execution']['stdout']

    def test_execute_empty_script_returns_error(self, client):
        """Returns 400 for empty script."""
        response = client.post('/api/tools/execute', json={
            'tool': 'ghidra',
            'script': '   ',  # Just whitespace
            'language': 'python',
        })
        assert response.status_code == 400
        assert 'script' in response.get_json()['error'].lower()

    def test_execute_unimplemented_tool_returns_error(self, client):
        """Returns error for unimplemented tool executor."""
        response = client.post('/api/tools/execute', json={
            'tool': 'angr',
            'script': 'print("test")',
            'language': 'python',
        })
        data = response.get_json()
        # Validation passes but executor not implemented
        assert 'validation' in data
        assert data['validation']['valid'] is True
        assert 'error' in data
        assert 'not' in data['error'].lower() and 'implement' in data['error'].lower()


class TestToolsStatusEndpoint:
    """Test GET /api/tools/status endpoint."""

    def test_status_returns_all_tools(self, client):
        """Returns status for all supported tools."""
        response = client.get('/api/tools/status')
        assert response.status_code == 200
        data = response.get_json()

        # Should have status for all tools
        assert 'tools' in data
        tools = data['tools']
        assert 'ghidra' in tools
        assert 'radare2' in tools
        assert 'angr' in tools
        assert 'binwalk' in tools
        assert 'gdb' in tools

    def test_status_tool_has_required_fields(self, client):
        """Each tool status has required fields."""
        response = client.get('/api/tools/status')
        data = response.get_json()

        for tool_name, tool_status in data['tools'].items():
            assert 'available' in tool_status, f"{tool_name} missing 'available'"
            assert 'description' in tool_status, f"{tool_name} missing 'description'"
            assert isinstance(tool_status['available'], bool)

    def test_status_ghidra_has_bridge_info(self, client):
        """Ghidra status includes bridge connection info."""
        response = client.get('/api/tools/status')
        data = response.get_json()

        ghidra = data['tools']['ghidra']
        assert 'bridge_available' in ghidra
        assert 'bridge_connected' in ghidra
        assert 'headless_available' in ghidra

    def test_status_includes_summary(self, client):
        """Status includes summary of available tools."""
        response = client.get('/api/tools/status')
        data = response.get_json()

        assert 'available_count' in data
        assert 'total_count' in data
        assert isinstance(data['available_count'], int)
        assert isinstance(data['total_count'], int)
        assert data['total_count'] >= data['available_count']
