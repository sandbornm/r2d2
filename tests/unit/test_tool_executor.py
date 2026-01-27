"""Tests for tool executor."""

import pytest
from unittest.mock import MagicMock, patch

from r2d2.tools.executor import ToolExecutor, GhidraExecutor
from r2d2.tools.models import (
    ExecutionStatus,
    ScriptLanguage,
    ToolName,
    ValidationResult,
)


class TestToolExecutor:
    """Test base ToolExecutor."""

    def test_validate_before_execute(self):
        """Executor validates script before execution."""
        executor = ToolExecutor()

        # Invalid Python script
        script = "def broken("
        result = executor.execute(
            script=script,
            language=ScriptLanguage.PYTHON,
            tool=ToolName.GHIDRA,
        )

        assert result.validation is not None
        assert not result.validation.valid
        assert result.execution is None  # Not executed

    def test_valid_script_executes(self):
        """Valid script proceeds to execution."""
        executor = ToolExecutor()

        with patch.object(executor, '_do_execute') as mock_exec:
            mock_exec.return_value = (ExecutionStatus.SUCCESS, "output", "", None, None)

            result = executor.execute(
                script="print('hello')",
                language=ScriptLanguage.PYTHON,
                tool=ToolName.GHIDRA,
            )

            assert result.validation is not None
            assert result.validation.valid
            assert result.execution is not None
            assert result.execution.status == ExecutionStatus.SUCCESS


class TestGhidraExecutor:
    """Test Ghidra-specific executor."""

    def test_requires_connection(self):
        """Ghidra executor requires bridge connection."""
        mock_client = MagicMock()
        mock_client.is_connected.return_value = False

        executor = GhidraExecutor(client=mock_client)
        result = executor.execute(
            script="print(currentProgram)",
            language=ScriptLanguage.PYTHON,
            tool=ToolName.GHIDRA,
        )

        assert result.execution is not None
        assert result.execution.status == ExecutionStatus.CONNECTION_LOST

    def test_executes_with_connection(self):
        """Ghidra executor runs script when connected."""
        mock_client = MagicMock()
        mock_client.is_connected.return_value = True
        mock_client.execute_script.return_value = {"output": "test", "error": None}

        executor = GhidraExecutor(client=mock_client)
        result = executor.execute(
            script="print(currentProgram)",
            language=ScriptLanguage.PYTHON,
            tool=ToolName.GHIDRA,
        )

        assert result.execution is not None
        assert result.execution.status == ExecutionStatus.SUCCESS
