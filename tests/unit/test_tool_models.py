"""Unit tests for tool execution models.

Following TDD: these tests are written FIRST, before any implementation.
"""

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError as PydanticValidationError


class TestToolNameEnum:
    """Tests for ToolName enum."""

    def test_all_tools_defined(self):
        """Test all expected tools are in the enum."""
        from r2d2.tools.models import ToolName

        assert ToolName.GHIDRA.value == "ghidra"
        assert ToolName.RADARE2.value == "radare2"
        assert ToolName.ANGR.value == "angr"
        assert ToolName.BINWALK.value == "binwalk"
        assert ToolName.GDB.value == "gdb"


class TestScriptLanguageEnum:
    """Tests for ScriptLanguage enum."""

    def test_all_languages_defined(self):
        """Test all expected languages are in the enum."""
        from r2d2.tools.models import ScriptLanguage

        assert ScriptLanguage.PYTHON.value == "python"
        assert ScriptLanguage.R2.value == "r2"
        assert ScriptLanguage.SHELL.value == "shell"


class TestArchitectureEnum:
    """Tests for Architecture enum."""

    def test_all_architectures_defined(self):
        """Test all expected architectures are in the enum."""
        from r2d2.tools.models import Architecture

        assert Architecture.ARM32.value == "arm32"
        assert Architecture.AARCH64.value == "aarch64"


class TestBinaryFormatEnum:
    """Tests for BinaryFormat enum."""

    def test_all_formats_defined(self):
        """Test all expected formats are in the enum."""
        from r2d2.tools.models import BinaryFormat

        assert BinaryFormat.ELF.value == "elf"
        assert BinaryFormat.MACHO.value == "macho"


class TestSubject:
    """Tests for Subject model."""

    def test_valid_subject(self, tmp_path: Path):
        """Test creating a valid Subject."""
        from r2d2.tools.models import Subject, Architecture, BinaryFormat

        # Create a real file
        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        sha256 = "a" * 64  # Valid 64 hex chars
        subject = Subject(
            path=binary_path,
            sha256=sha256,
            arch=Architecture.ARM32,
            format=BinaryFormat.ELF,
            size_bytes=104,
        )

        assert subject.path == binary_path
        assert subject.sha256 == sha256
        assert subject.arch == Architecture.ARM32
        assert subject.format == BinaryFormat.ELF
        assert subject.size_bytes == 104

    def test_path_must_exist(self, tmp_path: Path):
        """Test that path must point to an existing file."""
        from r2d2.tools.models import Subject, Architecture, BinaryFormat

        nonexistent = tmp_path / "nonexistent"
        with pytest.raises(PydanticValidationError) as exc_info:
            Subject(
                path=nonexistent,
                sha256="a" * 64,
                arch=Architecture.ARM32,
                format=BinaryFormat.ELF,
                size_bytes=100,
            )
        assert "path" in str(exc_info.value).lower()

    def test_sha256_must_be_64_hex_chars(self, tmp_path: Path):
        """Test sha256 validation."""
        from r2d2.tools.models import Subject, Architecture, BinaryFormat

        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        # Too short
        with pytest.raises(PydanticValidationError) as exc_info:
            Subject(
                path=binary_path,
                sha256="a" * 63,
                arch=Architecture.ARM32,
                format=BinaryFormat.ELF,
                size_bytes=104,
            )
        assert "sha256" in str(exc_info.value).lower()

        # Too long
        with pytest.raises(PydanticValidationError) as exc_info:
            Subject(
                path=binary_path,
                sha256="a" * 65,
                arch=Architecture.ARM32,
                format=BinaryFormat.ELF,
                size_bytes=104,
            )
        assert "sha256" in str(exc_info.value).lower()

        # Invalid chars
        with pytest.raises(PydanticValidationError) as exc_info:
            Subject(
                path=binary_path,
                sha256="g" * 64,  # 'g' is not a valid hex char
                arch=Architecture.ARM32,
                format=BinaryFormat.ELF,
                size_bytes=104,
            )
        assert "sha256" in str(exc_info.value).lower()

    def test_size_bytes_must_be_positive(self, tmp_path: Path):
        """Test size_bytes must be > 0."""
        from r2d2.tools.models import Subject, Architecture, BinaryFormat

        binary_path = tmp_path / "test_binary"
        binary_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        with pytest.raises(PydanticValidationError) as exc_info:
            Subject(
                path=binary_path,
                sha256="a" * 64,
                arch=Architecture.ARM32,
                format=BinaryFormat.ELF,
                size_bytes=0,
            )
        assert "size_bytes" in str(exc_info.value).lower()

        with pytest.raises(PydanticValidationError) as exc_info:
            Subject(
                path=binary_path,
                sha256="a" * 64,
                arch=Architecture.ARM32,
                format=BinaryFormat.ELF,
                size_bytes=-1,
            )
        assert "size_bytes" in str(exc_info.value).lower()


class TestValidationError:
    """Tests for ValidationError model."""

    def test_create_validation_error(self):
        """Test creating a ValidationError."""
        from r2d2.tools.models import ValidationError

        error = ValidationError(
            location="line 5",
            message="undefined variable 'x'",
            suggestion="Did you mean 'y'?",
            severity="error",
        )

        assert error.location == "line 5"
        assert error.message == "undefined variable 'x'"
        assert error.suggestion == "Did you mean 'y'?"
        assert error.severity == "error"

    def test_suggestion_is_optional(self):
        """Test that suggestion field is optional."""
        from r2d2.tools.models import ValidationError

        error = ValidationError(
            location="line 10",
            message="syntax error",
            severity="error",
        )

        assert error.suggestion is None

    def test_severity_must_be_error_or_warning(self):
        """Test severity validation."""
        from r2d2.tools.models import ValidationError

        # Valid severities
        ValidationError(location="a", message="b", severity="error")
        ValidationError(location="a", message="b", severity="warning")

        # Invalid severity
        with pytest.raises(PydanticValidationError):
            ValidationError(location="a", message="b", severity="info")


class TestValidationResult:
    """Tests for ValidationResult model."""

    def test_valid_result(self):
        """Test creating a valid ValidationResult."""
        from r2d2.tools.models import ValidationResult

        result = ValidationResult(
            valid=True,
            errors=[],
            warnings=[],
            validated_at=datetime.now(timezone.utc),
        )

        assert result.valid is True
        assert result.errors == []
        assert result.warnings == []

    def test_result_with_errors(self):
        """Test ValidationResult with errors."""
        from r2d2.tools.models import ValidationResult, ValidationError

        errors = [
            ValidationError(location="line 1", message="error 1", severity="error"),
            ValidationError(location="line 2", message="error 2", severity="error"),
        ]
        result = ValidationResult(
            valid=False,
            errors=errors,
            warnings=[],
            validated_at=datetime.now(timezone.utc),
        )

        assert result.valid is False
        assert len(result.errors) == 2

    def test_error_summary_property(self):
        """Test error_summary property returns formatted string."""
        from r2d2.tools.models import ValidationResult, ValidationError

        errors = [
            ValidationError(location="line 1", message="error 1", severity="error"),
            ValidationError(location="line 2", message="error 2", severity="error"),
        ]
        result = ValidationResult(
            valid=False,
            errors=errors,
            warnings=[],
            validated_at=datetime.now(timezone.utc),
        )

        summary = result.error_summary
        assert "line 1" in summary
        assert "error 1" in summary
        assert "line 2" in summary
        assert "error 2" in summary

    def test_error_summary_empty_when_no_errors(self):
        """Test error_summary is empty string when no errors."""
        from r2d2.tools.models import ValidationResult

        result = ValidationResult(
            valid=True,
            errors=[],
            warnings=[],
            validated_at=datetime.now(timezone.utc),
        )

        assert result.error_summary == ""


class TestExecutionStatus:
    """Tests for ExecutionStatus enum."""

    def test_all_statuses_defined(self):
        """Test all expected statuses are in the enum."""
        from r2d2.tools.models import ExecutionStatus

        assert ExecutionStatus.SUCCESS.value == "success"
        assert ExecutionStatus.ERROR.value == "error"
        assert ExecutionStatus.TIMEOUT.value == "timeout"
        assert ExecutionStatus.CANCELLED.value == "cancelled"
        assert ExecutionStatus.CONNECTION_LOST.value == "connection_lost"


class TestExecutionResult:
    """Tests for ExecutionResult model."""

    def test_successful_result(self):
        """Test creating a successful ExecutionResult."""
        from r2d2.tools.models import ExecutionResult, ExecutionStatus

        result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            duration_ms=150,
            stdout="output here",
            stderr="",
        )

        assert result.status == ExecutionStatus.SUCCESS
        assert result.duration_ms == 150
        assert result.stdout == "output here"
        assert result.stderr == ""
        assert result.exception is None
        assert result.traceback is None

    def test_error_result_with_exception(self):
        """Test ExecutionResult with exception details."""
        from r2d2.tools.models import ExecutionResult, ExecutionStatus

        result = ExecutionResult(
            status=ExecutionStatus.ERROR,
            duration_ms=50,
            stdout="",
            stderr="",
            exception="RuntimeError",
            traceback="Traceback...",
        )

        assert result.status == ExecutionStatus.ERROR
        assert result.exception == "RuntimeError"
        assert result.traceback == "Traceback..."

    def test_error_display_property_formats_error(self):
        """Test error_display property returns formatted error message."""
        from r2d2.tools.models import ExecutionResult, ExecutionStatus

        result = ExecutionResult(
            status=ExecutionStatus.ERROR,
            duration_ms=50,
            stdout="",
            stderr="error output",
            exception="RuntimeError",
            traceback="File line 1\nFile line 2",
        )

        display = result.error_display
        assert "RuntimeError" in display
        assert "error output" in display or "File line" in display

    def test_error_display_empty_for_success(self):
        """Test error_display returns empty string for success status."""
        from r2d2.tools.models import ExecutionResult, ExecutionStatus

        result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            duration_ms=100,
            stdout="output",
            stderr="",
        )

        assert result.error_display == ""


class TestTrajectoryEntry:
    """Tests for TrajectoryEntry model."""

    def test_create_basic_entry(self):
        """Test creating a basic TrajectoryEntry."""
        from r2d2.tools.models import TrajectoryEntry, ToolName

        entry = TrajectoryEntry(
            tool=ToolName.GHIDRA,
            intent="List all functions",
        )

        # Should have auto-generated id and timestamp
        assert entry.id is not None
        assert isinstance(UUID(entry.id), UUID)  # Valid UUID
        assert entry.timestamp is not None
        assert entry.tool == ToolName.GHIDRA
        assert entry.intent == "List all functions"
        assert entry.script is None
        assert entry.script_language is None
        assert entry.validation is None
        assert entry.execution is None
        assert entry.result is None
        assert entry.context_summary is None

    def test_full_entry_with_all_fields(self):
        """Test creating a TrajectoryEntry with all fields."""
        from r2d2.tools.models import (
            TrajectoryEntry,
            ToolName,
            ScriptLanguage,
            ValidationResult,
            ExecutionResult,
            ExecutionStatus,
        )

        validation = ValidationResult(
            valid=True,
            errors=[],
            warnings=[],
            validated_at=datetime.now(timezone.utc),
        )
        execution = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            duration_ms=100,
            stdout="functions: main, helper",
            stderr="",
        )

        entry = TrajectoryEntry(
            tool=ToolName.GHIDRA,
            intent="List all functions",
            script="print(getCurrentProgram().getFunctionManager().getFunctions(True))",
            script_language=ScriptLanguage.PYTHON,
            validation=validation,
            execution=execution,
            result={"functions": ["main", "helper"]},
            context_summary="Analyzing ARM binary with 2 functions",
        )

        assert entry.script is not None
        assert entry.script_language == ScriptLanguage.PYTHON
        assert entry.validation.valid is True
        assert entry.execution.status == ExecutionStatus.SUCCESS
        assert entry.result == {"functions": ["main", "helper"]}
        assert entry.context_summary == "Analyzing ARM binary with 2 functions"

    def test_script_requires_language(self):
        """Test that providing script requires script_language."""
        from r2d2.tools.models import TrajectoryEntry, ToolName

        with pytest.raises(PydanticValidationError) as exc_info:
            TrajectoryEntry(
                tool=ToolName.GHIDRA,
                intent="List functions",
                script="print('hello')",
                # Missing script_language
            )
        # Should mention the cross-field validation failure
        assert "script_language" in str(exc_info.value).lower()

    def test_execution_requires_valid_validation(self):
        """Test that execution result requires valid validation."""
        from r2d2.tools.models import (
            TrajectoryEntry,
            ToolName,
            ScriptLanguage,
            ValidationResult,
            ValidationError,
            ExecutionResult,
            ExecutionStatus,
        )

        invalid_validation = ValidationResult(
            valid=False,
            errors=[ValidationError(location="line 1", message="error", severity="error")],
            warnings=[],
            validated_at=datetime.now(timezone.utc),
        )
        execution = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            duration_ms=100,
            stdout="output",
            stderr="",
        )

        with pytest.raises(PydanticValidationError) as exc_info:
            TrajectoryEntry(
                tool=ToolName.GHIDRA,
                intent="List functions",
                script="print('hello')",
                script_language=ScriptLanguage.PYTHON,
                validation=invalid_validation,
                execution=execution,  # Should not have execution if validation failed
            )
        # Should mention validation must be valid for execution
        assert "validation" in str(exc_info.value).lower()
