"""Script validator for r2d2 tool execution.

This module provides validation for scripts before execution,
including syntax checking, dangerous pattern detection, and
tool-specific API usage warnings.

Note: This validator DETECTS dangerous patterns in user-submitted scripts
to prevent them from being executed. It does not execute any code itself.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar

from r2d2.tools.models import (
    ScriptLanguage,
    ToolName,
    ValidationError,
    ValidationResult,
)


class ScriptValidator:
    """Validates scripts before execution.

    Provides AST-based validation for Python scripts and pattern-based
    validation for shell and r2 commands. Detects dangerous patterns
    and provides suggestions for common API misuse.

    This class is a security boundary - it validates user scripts to
    prevent execution of dangerous commands.
    """

    # Ghidra API patterns that commonly cause issues
    # Maps pattern to (replacement suggestion, hint message)
    GHIDRA_FIXES: ClassVar[dict[str, tuple[str, str]]] = {
        r"\bgetFunctions\s*\(": (
            "currentProgram.getFunctionManager().getFunctions(True)",
            "Use currentProgram.getFunctionManager().getFunctions() instead of bare getFunctions()",
        ),
        r"\bgetBytes\s*\(": (
            "currentProgram.getMemory().getBytes(addr, bytearray(size))",
            "Use currentProgram.getMemory().getBytes() for reading memory",
        ),
        r"\bgetDataAt\s*\(": (
            "currentProgram.getListing().getDataAt(addr)",
            "Use currentProgram.getListing().getDataAt() for data access",
        ),
        r"\bgetSymbols\s*\(": (
            "currentProgram.getSymbolTable().getSymbols(name)",
            "Use currentProgram.getSymbolTable().getSymbols() for symbol lookup",
        ),
    }

    # Dangerous shell patterns that should be rejected as errors
    # These patterns are DETECTED to BLOCK dangerous commands
    # Each tuple is (regex pattern, description)
    DANGEROUS_SHELL_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(-[a-zA-Z]*f[a-zA-Z]*\s+)?/\s*$", "rm -rf / is destructive"),
        (r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(-[a-zA-Z]*r[a-zA-Z]*\s+)?/\s*$", "rm -rf / is destructive"),
        (r"\bmkfs\.", "mkfs commands can destroy filesystems"),
        (r"\bdd\s+.*of=/dev/", "dd writing to device files is dangerous"),
        (r"\bchmod\s+(-[a-zA-Z]*R[a-zA-Z]*\s+)?777\s+/", "chmod -R 777 is insecure"),
    ]

    # Dangerous r2 patterns (shell escapes) - DETECTED to WARN users
    DANGEROUS_R2_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (r"^!", "Shell escape at start of command"),
        (r";\s*!", "Shell escape after semicolon"),
    ]

    # Dangerous Python patterns that warrant warnings - DETECTED to WARN users
    # These detect code that could be dangerous if executed
    DANGEROUS_PYTHON_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (r"\bos\.system\s*\(", "os.system() executes shell commands - use subprocess with shell=False"),
        (r"\bsubprocess\.[a-z]+\s*\([^)]*shell\s*=\s*True", "shell=True in subprocess is dangerous with untrusted input"),
        (r"\beval\s*\(", "eval() can execute arbitrary code"),
        (r"\bexec\s*\(", "exec() can execute arbitrary code"),
    ]

    @classmethod
    def validate(
        cls, script: str, language: ScriptLanguage, tool: ToolName
    ) -> ValidationResult:
        """Validate a script before execution.

        Args:
            script: The script content to validate
            language: The scripting language (python, r2, shell)
            tool: The target tool (ghidra, radare2, angr, etc.)

        Returns:
            ValidationResult with valid=True if script passes validation,
            or valid=False with errors if validation fails.
            Warnings are included for potentially problematic patterns.
        """
        if language == ScriptLanguage.PYTHON:
            return cls._validate_python(script, tool)
        elif language == ScriptLanguage.R2:
            return cls._validate_r2(script)
        elif language == ScriptLanguage.SHELL:
            return cls._validate_shell(script, tool)
        else:
            # Unknown language - pass through with warning
            return ValidationResult(
                valid=True,
                errors=[],
                warnings=[
                    ValidationError(
                        location="script",
                        message=f"Unknown language: {language}",
                        severity="warning",
                    )
                ],
            )

    @classmethod
    def _validate_python(cls, script: str, tool: ToolName) -> ValidationResult:
        """Validate Python script using AST parsing.

        Args:
            script: Python script content
            tool: Target tool for tool-specific checks

        Returns:
            ValidationResult with syntax errors and tool-specific warnings
        """
        errors: list[ValidationError] = []
        warnings: list[ValidationError] = []

        # Try to parse the script
        try:
            ast.parse(script)
        except SyntaxError as e:
            line_num = e.lineno or 1
            errors.append(
                ValidationError(
                    location=f"line {line_num}",
                    message=f"Syntax error: {e.msg}",
                    suggestion="Fix the Python syntax error",
                    severity="error",
                )
            )
            return ValidationResult(valid=False, errors=errors, warnings=warnings)

        # Check for dangerous Python patterns
        warnings.extend(cls._check_dangerous_python(script))

        # Check tool-specific patterns
        if tool == ToolName.GHIDRA:
            warnings.extend(cls._check_ghidra_patterns(script))
        elif tool == ToolName.ANGR:
            warnings.extend(cls._check_angr_patterns(script))

        return ValidationResult(valid=True, errors=errors, warnings=warnings)

    @classmethod
    def _validate_r2(cls, script: str) -> ValidationResult:
        """Validate radare2 commands.

        Checks for shell escapes and other dangerous patterns.

        Args:
            script: r2 command script

        Returns:
            ValidationResult with warnings for shell escapes
        """
        errors: list[ValidationError] = []
        warnings: list[ValidationError] = []

        # Check each line for dangerous patterns
        for i, line in enumerate(script.strip().split("\n"), start=1):
            line = line.strip()
            if not line:
                continue

            for pattern, description in cls.DANGEROUS_R2_PATTERNS:
                if re.search(pattern, line):
                    warnings.append(
                        ValidationError(
                            location=f"line {i}",
                            message=f"Shell escape detected: {description}",
                            suggestion="Avoid shell escapes in r2 scripts for security",
                            severity="warning",
                        )
                    )

        return ValidationResult(valid=True, errors=errors, warnings=warnings)

    @classmethod
    def _validate_shell(cls, script: str, tool: ToolName) -> ValidationResult:
        """Validate shell commands.

        Checks for dangerous patterns that could cause system damage.

        Args:
            script: Shell script content
            tool: Target tool for context

        Returns:
            ValidationResult with errors for dangerous commands
        """
        errors: list[ValidationError] = []
        warnings: list[ValidationError] = []

        # Check for dangerous patterns
        for pattern, description in cls.DANGEROUS_SHELL_PATTERNS:
            if re.search(pattern, script, re.IGNORECASE | re.MULTILINE):
                errors.append(
                    ValidationError(
                        location="script",
                        message=f"Dangerous command detected: {description}",
                        suggestion="Remove or modify the dangerous command",
                        severity="error",
                    )
                )

        valid = len(errors) == 0
        return ValidationResult(valid=valid, errors=errors, warnings=warnings)

    @classmethod
    def _check_ghidra_patterns(cls, script: str) -> list[ValidationError]:
        """Check for common Ghidra API misuse patterns.

        Args:
            script: Python script content

        Returns:
            List of ValidationError warnings for API misuse
        """
        warnings: list[ValidationError] = []

        for pattern, (replacement, hint) in cls.GHIDRA_FIXES.items():
            matches = list(re.finditer(pattern, script))
            for match in matches:
                # Find line number
                line_num = script[: match.start()].count("\n") + 1
                warnings.append(
                    ValidationError(
                        location=f"line {line_num}",
                        message=hint,
                        suggestion=f"Use: {replacement}",
                        severity="warning",
                    )
                )

        return warnings

    @classmethod
    def _check_angr_patterns(cls, script: str) -> list[ValidationError]:
        """Check for common angr API misuse patterns.

        Args:
            script: Python script content

        Returns:
            List of ValidationError warnings for API misuse
        """
        warnings: list[ValidationError] = []

        # Check for common angr issues
        # Note: These are informational for now, not strict errors

        # Example: using deprecated APIs
        if "b.loader" in script and "proj.loader" not in script:
            warnings.append(
                ValidationError(
                    location="script",
                    message="'b.loader' is an older angr pattern",
                    suggestion="Use 'proj.loader' with modern angr",
                    severity="warning",
                )
            )

        return warnings

    @classmethod
    def _check_dangerous_python(cls, script: str) -> list[ValidationError]:
        """Check for dangerous Python patterns.

        This method DETECTS dangerous patterns in user-submitted scripts
        to warn about potential security issues before execution.

        Args:
            script: Python script content

        Returns:
            List of ValidationError warnings for dangerous patterns
        """
        warnings: list[ValidationError] = []

        for pattern, description in cls.DANGEROUS_PYTHON_PATTERNS:
            matches = list(re.finditer(pattern, script))
            for match in matches:
                line_num = script[: match.start()].count("\n") + 1
                warnings.append(
                    ValidationError(
                        location=f"line {line_num}",
                        message=description,
                        suggestion="Consider using safer alternatives",
                        severity="warning",
                    )
                )

        return warnings
