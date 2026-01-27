"""Tool executor for r2d2 binary analysis copilot.

This module provides the execution framework for running scripts against
analysis tools (Ghidra, radare2, etc.) with validation-before-execution
semantics.

The executor pattern ensures:
1. All scripts are validated before execution
2. Invalid scripts never reach the tool
3. Execution results are captured with timing and error details
4. Results can be converted to trajectory entries for history
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from r2d2.tools.models import (
    ExecutionResult,
    ExecutionStatus,
    ScriptLanguage,
    ToolName,
    TrajectoryEntry,
    ValidationResult,
)
from r2d2.tools.validator import ScriptValidator


@dataclass
class ExecutionContext:
    """Context for script execution.

    Contains all information needed to execute a script, including
    the script itself, target tool, and execution parameters.
    """

    script: str
    language: ScriptLanguage
    tool: ToolName
    timeout_ms: int = 30000
    validation: ValidationResult | None = None


@dataclass
class ExecutionOutput:
    """Output from script execution.

    Contains validation results, execution results, and any
    structured output from the tool.
    """

    validation: ValidationResult | None = None
    execution: ExecutionResult | None = None
    result: dict[str, Any] = field(default_factory=dict)

    def to_trajectory_entry(
        self,
        intent: str,
        script: str,
        language: ScriptLanguage,
        tool: ToolName,
        context_summary: str | None = None,
    ) -> TrajectoryEntry:
        """Convert execution output to a trajectory entry.

        Args:
            intent: Human-readable description of what the script does
            script: The script that was executed
            language: Script language
            tool: Target tool
            context_summary: Optional summary of analysis context

        Returns:
            TrajectoryEntry suitable for storage in trajectory history
        """
        return TrajectoryEntry(
            tool=tool,
            intent=intent,
            script=script,
            script_language=language,
            validation=self.validation,
            execution=self.execution,
            result=self.result,
            context_summary=context_summary,
        )


@runtime_checkable
class BridgeClient(Protocol):
    """Protocol for tool bridge clients.

    Bridge clients provide remote execution of scripts against
    analysis tools like Ghidra.
    """

    def is_connected(self) -> bool:
        """Check if the bridge connection is active."""
        ...

    def execute_script(self, script: str) -> dict[str, Any]:
        """Execute a script and return the result."""
        ...


class ToolExecutor:
    """Base executor for tool scripts.

    Provides validation-before-execution semantics. Subclasses
    implement _do_execute for tool-specific execution logic.

    This class is not abstract - it has a default _do_execute that
    raises NotImplementedError, allowing tests to patch it.

    Note on timeout_ms:
        The timeout parameter is passed to _do_execute() but enforcement
        is left to the subclass implementation. This allows tools with
        built-in timeout support (like network calls) to use their
        native mechanisms. The base class catches TimeoutError if raised.
    """

    def execute(
        self,
        script: str,
        language: ScriptLanguage,
        tool: ToolName,
        timeout_ms: int = 30000,
        intent: str = "",
    ) -> ExecutionOutput:
        """Execute a script with validation.

        The script is validated before execution. If validation fails,
        execution is skipped and the validation errors are returned.

        Flow:
        1. Validate script syntax and patterns
        2. Run pre-execution checks (override _pre_execute_check())
        3. Execute the script via _do_execute()
        4. Parse output via _parse_output()

        Args:
            script: Script content to execute
            language: Script language (python, r2, shell)
            tool: Target tool (ghidra, radare2, etc.)
            timeout_ms: Execution timeout in milliseconds (enforcement is
                tool-specific; see Note on timeout_ms in class docstring)
            intent: Human-readable description of script purpose

        Returns:
            ExecutionOutput with validation and execution results
        """
        # Step 1: Validate the script
        validation = ScriptValidator.validate(script, language, tool)

        # Step 2: Pre-execution checks (connection, etc.)
        pre_check_result = self._pre_execute_check(validation)
        if pre_check_result is not None:
            return pre_check_result

        # Step 3: If validation fails, return early without execution
        if not validation.valid:
            return ExecutionOutput(validation=validation, execution=None, result={})

        # Step 4: Execute the script
        start_time = time.monotonic()
        try:
            status, stdout, stderr, exception, traceback = self._do_execute(
                script=script,
                language=language,
                tool=tool,
                timeout_ms=timeout_ms,
            )
        except NotImplementedError:
            # Base class doesn't implement execution
            raise
        except TimeoutError:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            execution = ExecutionResult(
                status=ExecutionStatus.TIMEOUT,
                duration_ms=duration_ms,
                stdout="",
                stderr="Execution timed out",
            )
            return ExecutionOutput(validation=validation, execution=execution)
        except Exception as e:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            execution = ExecutionResult(
                status=ExecutionStatus.ERROR,
                duration_ms=duration_ms,
                stdout="",
                stderr=str(e),
                exception=type(e).__name__,
            )
            return ExecutionOutput(validation=validation, execution=execution)

        duration_ms = int((time.monotonic() - start_time) * 1000)

        execution = ExecutionResult(
            status=status,
            duration_ms=duration_ms,
            stdout=stdout or "",
            stderr=stderr or "",
            exception=exception,
            traceback=traceback,
        )

        # Parse the output to structured data
        result = self._parse_output(stdout or "", stderr or "")

        return ExecutionOutput(validation=validation, execution=execution, result=result)

    def _pre_execute_check(
        self, validation: ValidationResult
    ) -> ExecutionOutput | None:
        """Hook for pre-execution checks (connection, availability, etc.).

        Override in subclasses to add checks that should run before
        execution but after validation. Return None to continue with
        execution, or return an ExecutionOutput to short-circuit.

        Args:
            validation: The validation result from script validation

        Returns:
            None to continue execution, or ExecutionOutput to return early
        """
        return None

    def _do_execute(
        self,
        script: str,
        language: ScriptLanguage,
        tool: ToolName,
        timeout_ms: int,
    ) -> tuple[ExecutionStatus, str | None, str | None, str | None, str | None]:
        """Execute the script (to be implemented by subclasses).

        Args:
            script: Validated script content
            language: Script language
            tool: Target tool
            timeout_ms: Execution timeout

        Returns:
            Tuple of (status, stdout, stderr, exception, traceback)

        Raises:
            NotImplementedError: Base class doesn't implement execution
        """
        raise NotImplementedError("Subclasses must implement _do_execute")

    def _parse_output(self, stdout: str, stderr: str) -> dict[str, Any]:
        """Parse execution output to structured data.

        Override in subclasses for tool-specific parsing.

        Args:
            stdout: Standard output from script execution
            stderr: Standard error from script execution

        Returns:
            Dictionary with parsed output data
        """
        return {"raw_output": stdout, "raw_stderr": stderr}


class GhidraExecutor(ToolExecutor):
    """Executor for Ghidra bridge scripts.

    Executes Python scripts against a running Ghidra instance
    via the Ghidra bridge protocol.
    """

    def __init__(self, client: BridgeClient) -> None:
        """Initialize with a bridge client.

        Args:
            client: Bridge client for communicating with Ghidra
        """
        self.client = client

    def _pre_execute_check(
        self, validation: ValidationResult
    ) -> ExecutionOutput | None:
        """Check Ghidra bridge connection before execution.

        Returns CONNECTION_LOST status if not connected.
        """
        if not self.client.is_connected():
            execution = ExecutionResult(
                status=ExecutionStatus.CONNECTION_LOST,
                duration_ms=0,
                stdout="",
                stderr="Ghidra bridge is not connected",
            )
            return ExecutionOutput(validation=validation, execution=execution, result={})
        return None

    def _do_execute(
        self,
        script: str,
        language: ScriptLanguage,
        tool: ToolName,
        timeout_ms: int,
    ) -> tuple[ExecutionStatus, str | None, str | None, str | None, str | None]:
        """Execute script via Ghidra bridge.

        Args:
            script: Python script to execute in Ghidra
            language: Script language (should be PYTHON)
            tool: Target tool (should be GHIDRA)
            timeout_ms: Execution timeout (passed to bridge if supported)

        Returns:
            Tuple of (status, stdout, stderr, exception, traceback)
        """
        result = self.client.execute_script(script)
        error = result.get("error")
        if error:
            return ExecutionStatus.ERROR, result.get("output", ""), str(error), None, None
        return ExecutionStatus.SUCCESS, result.get("output", ""), "", None, None


class Radare2Executor(ToolExecutor):
    """Executor for radare2 commands.

    Executes r2 commands via r2pipe against a binary.
    """

    def __init__(self, r2pipe: Any = None) -> None:
        """Initialize with an optional r2pipe instance.

        Args:
            r2pipe: r2pipe instance connected to a binary (optional)
        """
        self._r2 = r2pipe

    @property
    def r2(self) -> Any:
        """Get the r2pipe instance."""
        return self._r2

    @r2.setter
    def r2(self, value: Any) -> None:
        """Set the r2pipe instance."""
        self._r2 = value

    def _do_execute(
        self,
        script: str,
        language: ScriptLanguage,
        tool: ToolName,
        timeout_ms: int,
    ) -> tuple[ExecutionStatus, str | None, str | None, str | None, str | None]:
        """Execute r2 commands via r2pipe.

        Args:
            script: r2 commands to execute (one per line)
            language: Script language (should be R2)
            tool: Target tool (should be RADARE2)
            timeout_ms: Execution timeout

        Returns:
            Tuple of (status, stdout, stderr, exception, traceback)
        """
        if self._r2 is None:
            return (
                ExecutionStatus.ERROR,
                None,
                "r2pipe not initialized",
                "RuntimeError",
                None,
            )

        try:
            # Execute each command and collect output
            outputs = []
            for line in script.strip().split("\n"):
                line = line.strip()
                if line:
                    result = self._r2.cmd(line)
                    if result:
                        outputs.append(result)

            stdout = "\n".join(outputs)
            return ExecutionStatus.SUCCESS, stdout, "", None, None

        except Exception as e:
            return (
                ExecutionStatus.ERROR,
                None,
                str(e),
                type(e).__name__,
                None,
            )
