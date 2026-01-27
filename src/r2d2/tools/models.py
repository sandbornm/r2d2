"""Type models for tool execution in r2d2 binary analysis copilot.

This module defines strict Pydantic v2 models for:
- Tool and script type enumerations
- Binary subject metadata with validation
- Script validation errors and results
- Execution status and results
- Trajectory entries for analysis history
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _utcnow() -> datetime:
    """Return current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)


class ToolName(str, Enum):
    """Supported analysis tools."""

    GHIDRA = "ghidra"
    RADARE2 = "radare2"
    ANGR = "angr"
    BINWALK = "binwalk"
    GDB = "gdb"


class ScriptLanguage(str, Enum):
    """Supported script languages for tool execution."""

    PYTHON = "python"
    R2 = "r2"
    SHELL = "shell"


class Architecture(str, Enum):
    """Supported CPU architectures."""

    ARM32 = "arm32"
    AARCH64 = "aarch64"


class BinaryFormat(str, Enum):
    """Supported binary formats."""

    ELF = "elf"
    MACHO = "macho"


class Subject(BaseModel):
    """Binary subject for analysis with strict validation.

    Represents a binary file to be analyzed, with validated metadata.
    """

    model_config = ConfigDict(strict=True, frozen=True)

    path: Path = Field(description="Path to the binary file (must exist)")
    sha256: str = Field(description="SHA256 hash of the binary (64 hex characters)")
    arch: Architecture = Field(description="CPU architecture")
    format: BinaryFormat = Field(description="Binary format")
    size_bytes: int = Field(gt=0, description="File size in bytes (must be positive)")

    @field_validator("path")
    @classmethod
    def path_must_exist(cls, v: Path) -> Path:
        """Validate that the path points to an existing file."""
        v = v.resolve()
        if not v.exists():
            raise ValueError(f"path does not exist: {v}")
        if not v.is_file():
            raise ValueError(f"path is not a file: {v}")
        return v

    @field_validator("sha256")
    @classmethod
    def sha256_must_be_valid(cls, v: str) -> str:
        """Validate SHA256 hash format (64 hexadecimal characters)."""
        if len(v) != 64:
            raise ValueError(f"sha256 must be exactly 64 characters, got {len(v)}")
        if not re.match(r"^[a-fA-F0-9]{64}$", v):
            raise ValueError("sha256 must contain only hexadecimal characters")
        return v.lower()


class ValidationError(BaseModel):
    """A single validation error or warning from script validation.

    Used to report issues found during script validation before execution.
    """

    model_config = ConfigDict(strict=True, frozen=True)

    location: str = Field(description="Location of the error (e.g., 'line 5')")
    message: str = Field(description="Error message describing the issue")
    suggestion: str | None = Field(default=None, description="Optional suggestion for fixing")
    severity: str = Field(description="Severity level: 'error' or 'warning'")

    @field_validator("severity")
    @classmethod
    def severity_must_be_valid(cls, v: str) -> str:
        """Validate severity is either 'error' or 'warning'."""
        if v not in ("error", "warning"):
            raise ValueError(f"severity must be 'error' or 'warning', got '{v}'")
        return v


class ValidationResult(BaseModel):
    """Result of script validation.

    Contains validation status, any errors/warnings, and provides
    a summary property for error display.
    """

    model_config = ConfigDict(strict=True, frozen=True)

    valid: bool = Field(description="Whether the script passed validation")
    errors: list[ValidationError] = Field(
        default_factory=list, description="List of validation errors"
    )
    warnings: list[ValidationError] = Field(
        default_factory=list, description="List of validation warnings"
    )
    validated_at: datetime = Field(
        default_factory=_utcnow, description="Timestamp of validation"
    )

    @property
    def error_summary(self) -> str:
        """Return a formatted summary of all errors.

        Returns:
            Formatted string with all errors, or empty string if no errors.
        """
        if not self.errors:
            return ""
        lines = []
        for err in self.errors:
            lines.append(f"[{err.location}] {err.message}")
            if err.suggestion:
                lines.append(f"  Suggestion: {err.suggestion}")
        return "\n".join(lines)


class ExecutionStatus(str, Enum):
    """Status of script execution."""

    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    CONNECTION_LOST = "connection_lost"


class ExecutionResult(BaseModel):
    """Result of script execution.

    Contains execution status, timing, output streams, and any exception details.
    Provides an error_display property for formatted error messages.
    """

    model_config = ConfigDict(strict=True, frozen=True)

    status: ExecutionStatus = Field(description="Execution status")
    duration_ms: int = Field(ge=0, description="Execution duration in milliseconds")
    stdout: str = Field(default="", description="Standard output")
    stderr: str = Field(default="", description="Standard error")
    exception: str | None = Field(default=None, description="Exception type if error occurred")
    traceback: str | None = Field(default=None, description="Stack traceback if error occurred")

    @property
    def error_display(self) -> str:
        """Return a formatted error message for display.

        Returns:
            Formatted error string, or empty string if success status.
        """
        if self.status == ExecutionStatus.SUCCESS:
            return ""

        parts = []

        # Special handling for timeout status
        if self.status == ExecutionStatus.TIMEOUT:
            parts.append(f"Timeout exceeded after {self.duration_ms}ms")

        if self.exception:
            parts.append(f"Exception: {self.exception}")
        if self.stderr:
            parts.append(f"Stderr: {self.stderr}")
        if self.traceback:
            parts.append(f"Traceback:\n{self.traceback}")
        return "\n".join(parts) if parts else f"Status: {self.status.value}"


class TrajectoryEntry(BaseModel):
    """A single entry in the analysis trajectory.

    Records tool invocations with intent, script, validation, execution,
    and results for debugging and replay.

    Cross-field validation ensures:
    - script requires script_language
    - execution requires valid validation
    """

    model_config = ConfigDict(strict=True)

    id: str = Field(default_factory=lambda: uuid4().hex, description="Unique entry ID (UUID)")
    timestamp: datetime = Field(default_factory=_utcnow, description="Entry timestamp")
    tool: ToolName = Field(description="Tool being invoked")
    intent: str = Field(
        min_length=1, max_length=1000, description="Human-readable description of the action intent"
    )
    script: str | None = Field(default=None, description="Script to execute")
    script_language: ScriptLanguage | None = Field(
        default=None, description="Language of the script"
    )
    validation: ValidationResult | None = Field(
        default=None, description="Validation result for the script"
    )
    execution: ExecutionResult | None = Field(
        default=None, description="Execution result"
    )
    result: dict[str, Any] | None = Field(
        default=None, description="Parsed/structured result data"
    )
    context_summary: str | None = Field(
        default=None, max_length=500, description="Brief summary of analysis context"
    )

    @model_validator(mode="after")
    def validate_cross_field_dependencies(self) -> "TrajectoryEntry":
        """Validate cross-field dependencies.

        - script requires script_language to be set
        - execution requires validation to be valid (not failed)
        """
        # Script requires language
        if self.script is not None and self.script_language is None:
            raise ValueError("script_language is required when script is provided")

        # Execution requires valid validation
        if self.execution is not None:
            if self.validation is None:
                raise ValueError("validation is required when execution is provided")
            if not self.validation.valid:
                raise ValueError(
                    "execution cannot be provided when validation failed (valid=False)"
                )

        return self
