"""Tests for tool executor."""

import pytest
from unittest.mock import MagicMock, patch

from r2d2.tools.executor import (
    ExecutionContext,
    ExecutionOutput,
    GhidraExecutor,
    Radare2Executor,
    ToolExecutor,
)
from r2d2.tools.models import (
    ExecutionResult,
    ExecutionStatus,
    ScriptLanguage,
    ToolName,
    ValidationResult,
)


class TestExecutionContext:
    """Test ExecutionContext dataclass."""

    def test_default_timeout(self):
        """ExecutionContext has 30000ms default timeout."""
        ctx = ExecutionContext(
            script="print('hello')",
            language=ScriptLanguage.PYTHON,
            tool=ToolName.GHIDRA,
        )
        assert ctx.timeout_ms == 30000

    def test_all_fields(self):
        """ExecutionContext stores all fields correctly."""
        validation = ValidationResult(valid=True)
        ctx = ExecutionContext(
            script="print('hello')",
            language=ScriptLanguage.PYTHON,
            tool=ToolName.GHIDRA,
            timeout_ms=5000,
            validation=validation,
        )
        assert ctx.script == "print('hello')"
        assert ctx.language == ScriptLanguage.PYTHON
        assert ctx.tool == ToolName.GHIDRA
        assert ctx.timeout_ms == 5000
        assert ctx.validation == validation


class TestExecutionOutput:
    """Test ExecutionOutput dataclass."""

    def test_default_result_is_empty_dict(self):
        """ExecutionOutput defaults result to empty dict."""
        output = ExecutionOutput()
        assert output.result == {}
        assert output.validation is None
        assert output.execution is None

    def test_to_trajectory_entry(self):
        """ExecutionOutput.to_trajectory_entry creates valid entry."""
        validation = ValidationResult(valid=True)
        execution = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            duration_ms=100,
            stdout="output",
        )
        output = ExecutionOutput(
            validation=validation,
            execution=execution,
            result={"key": "value"},
        )

        entry = output.to_trajectory_entry(
            intent="find malloc calls",
            script="print(functions)",
            language=ScriptLanguage.PYTHON,
            tool=ToolName.GHIDRA,
            context_summary="Found 3 calls",
        )

        assert entry.tool == ToolName.GHIDRA
        assert entry.intent == "find malloc calls"
        assert entry.script == "print(functions)"
        assert entry.script_language == ScriptLanguage.PYTHON
        assert entry.validation == validation
        assert entry.execution == execution
        assert entry.result == {"key": "value"}
        assert entry.context_summary == "Found 3 calls"


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

    def test_exception_during_execution(self):
        """Execution exceptions are captured with status ERROR."""
        executor = ToolExecutor()

        with patch.object(executor, '_do_execute') as mock_exec:
            mock_exec.side_effect = RuntimeError("Connection failed")

            result = executor.execute(
                script="print('hello')",
                language=ScriptLanguage.PYTHON,
                tool=ToolName.GHIDRA,
            )

            assert result.validation is not None
            assert result.validation.valid
            assert result.execution is not None
            assert result.execution.status == ExecutionStatus.ERROR
            assert result.execution.exception == "RuntimeError"
            assert "Connection failed" in result.execution.stderr

    def test_timeout_error_handling(self):
        """TimeoutError is captured with TIMEOUT status."""
        executor = ToolExecutor()

        with patch.object(executor, '_do_execute') as mock_exec:
            mock_exec.side_effect = TimeoutError("Script timed out")

            result = executor.execute(
                script="print('hello')",
                language=ScriptLanguage.PYTHON,
                tool=ToolName.GHIDRA,
            )

            assert result.execution is not None
            assert result.execution.status == ExecutionStatus.TIMEOUT
            assert "timed out" in result.execution.stderr.lower()

    def test_parse_output_called(self):
        """_parse_output is called after successful execution."""
        executor = ToolExecutor()

        with patch.object(executor, '_do_execute') as mock_exec:
            mock_exec.return_value = (ExecutionStatus.SUCCESS, "stdout", "stderr", None, None)

            result = executor.execute(
                script="print('hello')",
                language=ScriptLanguage.PYTHON,
                tool=ToolName.GHIDRA,
            )

            # Default _parse_output returns raw_output and raw_stderr
            assert result.result["raw_output"] == "stdout"
            assert result.result["raw_stderr"] == "stderr"

    def test_pre_execute_check_can_short_circuit(self):
        """_pre_execute_check can return early before execution."""

        class ShortCircuitExecutor(ToolExecutor):
            def _pre_execute_check(self, validation):
                return ExecutionOutput(
                    validation=validation,
                    execution=ExecutionResult(
                        status=ExecutionStatus.ERROR,
                        duration_ms=0,
                        stderr="Pre-check failed",
                    ),
                )

        executor = ShortCircuitExecutor()
        result = executor.execute(
            script="print('hello')",
            language=ScriptLanguage.PYTHON,
            tool=ToolName.GHIDRA,
        )

        assert result.execution is not None
        assert result.execution.status == ExecutionStatus.ERROR
        assert "Pre-check failed" in result.execution.stderr


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
        assert result.execution.stdout == "test"

    def test_handles_execution_error(self):
        """Ghidra executor captures bridge errors."""
        mock_client = MagicMock()
        mock_client.is_connected.return_value = True
        mock_client.execute_script.return_value = {
            "output": "partial",
            "error": "NameError: undefined variable",
        }

        executor = GhidraExecutor(client=mock_client)
        result = executor.execute(
            script="print(undefined)",
            language=ScriptLanguage.PYTHON,
            tool=ToolName.GHIDRA,
        )

        assert result.execution is not None
        assert result.execution.status == ExecutionStatus.ERROR
        assert "NameError" in result.execution.stderr

    def test_validation_still_checked_when_disconnected(self):
        """Validation runs even if connection check fails."""
        mock_client = MagicMock()
        mock_client.is_connected.return_value = False

        executor = GhidraExecutor(client=mock_client)
        result = executor.execute(
            script="def broken(",  # Invalid syntax
            language=ScriptLanguage.PYTHON,
            tool=ToolName.GHIDRA,
        )

        # Validation still ran
        assert result.validation is not None
        # But we get connection lost status, not validation failure
        assert result.execution is not None
        assert result.execution.status == ExecutionStatus.CONNECTION_LOST


class TestRadare2Executor:
    """Test radare2-specific executor."""

    def test_r2pipe_not_initialized(self):
        """Returns error when r2pipe is None."""
        executor = Radare2Executor(r2pipe=None)

        result = executor.execute(
            script="aaa",
            language=ScriptLanguage.R2,
            tool=ToolName.RADARE2,
        )

        assert result.execution is not None
        assert result.execution.status == ExecutionStatus.ERROR
        assert "not initialized" in result.execution.stderr.lower()

    def test_executes_commands(self):
        """Executes r2 commands via r2pipe."""
        mock_r2 = MagicMock()
        mock_r2.cmd.side_effect = ["Analysis complete", "func1\nfunc2\nfunc3"]

        executor = Radare2Executor(r2pipe=mock_r2)

        result = executor.execute(
            script="aaa\nafl",
            language=ScriptLanguage.R2,
            tool=ToolName.RADARE2,
        )

        assert result.execution is not None
        assert result.execution.status == ExecutionStatus.SUCCESS
        assert "Analysis complete" in result.execution.stdout
        assert "func1" in result.execution.stdout
        mock_r2.cmd.assert_any_call("aaa")
        mock_r2.cmd.assert_any_call("afl")

    def test_skips_empty_lines(self):
        """Empty lines in script are skipped."""
        mock_r2 = MagicMock()
        mock_r2.cmd.return_value = "output"

        executor = Radare2Executor(r2pipe=mock_r2)

        result = executor.execute(
            script="aaa\n\n\nafl\n",
            language=ScriptLanguage.R2,
            tool=ToolName.RADARE2,
        )

        assert result.execution is not None
        assert result.execution.status == ExecutionStatus.SUCCESS
        # Only 2 calls, not 4 (empty lines skipped)
        assert mock_r2.cmd.call_count == 2

    def test_r2_property_getter_setter(self):
        """r2pipe can be set via property."""
        executor = Radare2Executor()
        assert executor.r2 is None

        mock_r2 = MagicMock()
        executor.r2 = mock_r2
        assert executor.r2 is mock_r2

    def test_handles_r2pipe_exception(self):
        """Exceptions from r2pipe are captured."""
        mock_r2 = MagicMock()
        mock_r2.cmd.side_effect = Exception("Connection closed")

        executor = Radare2Executor(r2pipe=mock_r2)

        result = executor.execute(
            script="aaa",
            language=ScriptLanguage.R2,
            tool=ToolName.RADARE2,
        )

        assert result.execution is not None
        assert result.execution.status == ExecutionStatus.ERROR
        assert "Connection closed" in result.execution.stderr
