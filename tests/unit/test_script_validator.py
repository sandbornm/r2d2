"""Unit tests for script validator.

Following TDD: these tests are written FIRST, before any implementation.
"""

import pytest


class TestPythonValidation:
    """Tests for Python script validation."""

    def test_valid_python_passes(self):
        """Test that valid Python code passes validation."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        script = """
def analyze_function(func):
    name = func.getName()
    entry = func.getEntryPoint()
    return (name, entry)

result = analyze_function(current_function)
print(result)
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        assert result.valid is True
        assert len(result.errors) == 0

    def test_syntax_error_detected(self):
        """Test that Python syntax errors are detected with line numbers."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        script = """def broken_function(
    # Missing closing paren and colon
    print("hello"
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        assert result.valid is False
        assert len(result.errors) >= 1
        # Should include line number in location
        assert "line" in result.errors[0].location.lower()

    def test_ghidra_api_warning(self):
        """Test that Ghidra API misuse generates warnings with suggestions."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        # Using getFunctions() without FunctionManager
        script = """
functions = getFunctions(True)  # Wrong - should use FunctionManager
for func in functions:
    print(func.getName())
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        # Should still be valid (just warnings) but have warnings
        assert len(result.warnings) >= 1
        # Warning should suggest using FunctionManager or currentProgram
        warning = result.warnings[0]
        assert (
            "FunctionManager" in (warning.suggestion or "")
            or "currentProgram" in (warning.suggestion or "")
        )


class TestR2Validation:
    """Tests for radare2 script/command validation."""

    def test_valid_r2_command(self):
        """Test that valid r2 commands pass validation."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        script = """
aaa
afl
pdf @ main
"""
        result = ScriptValidator.validate(script, ScriptLanguage.R2, ToolName.RADARE2)

        assert result.valid is True
        assert len(result.errors) == 0

    def test_dangerous_command_warning(self):
        """Test that shell escape commands generate warnings."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        # Shell escape in r2
        script = """
aaa
!rm -rf /tmp/test
afl
"""
        result = ScriptValidator.validate(script, ScriptLanguage.R2, ToolName.RADARE2)

        # Should have warnings about shell escape
        assert len(result.warnings) >= 1
        # Check that a warning mentions shell or dangerous pattern
        warning_messages = " ".join(w.message.lower() for w in result.warnings)
        assert "shell" in warning_messages or "escape" in warning_messages


class TestShellValidation:
    """Tests for shell script validation."""

    def test_valid_binwalk_command(self):
        """Test that valid binwalk commands pass validation."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        script = "binwalk -e firmware.bin"
        result = ScriptValidator.validate(script, ScriptLanguage.SHELL, ToolName.BINWALK)

        assert result.valid is True
        assert len(result.errors) == 0

    def test_dangerous_shell_rejected(self):
        """Test that dangerous shell patterns are rejected as errors."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        # Dangerous command: rm -rf /
        script = "rm -rf /"
        result = ScriptValidator.validate(script, ScriptLanguage.SHELL, ToolName.BINWALK)

        assert result.valid is False
        assert len(result.errors) >= 1


class TestDangerousPythonPatterns:
    """Tests for dangerous Python pattern detection."""

    def test_os_system_warning(self):
        """Test that os.system calls generate warnings.

        Note: This tests detection of shell command execution patterns
        which could be dangerous if used with untrusted input.
        """
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        # Script that uses os.system - this is what we want to DETECT and WARN about
        script = 'import os\nos.system("ls -la")'
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        # Should have warnings about shell execution
        assert len(result.warnings) >= 1

    def test_subprocess_shell_warning(self):
        """Test that subprocess with shell=True generates warnings.

        Note: This tests detection of shell=True patterns which
        could be dangerous if used with untrusted input.
        """
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        # Script that uses subprocess.run with shell=True - detect and warn
        script = 'import subprocess\nsubprocess.run("ls", shell=True)'
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        # Should have warnings
        assert len(result.warnings) >= 1


class TestAngrPatternValidation:
    """Tests for angr-specific pattern validation."""

    def test_valid_angr_script(self):
        """Test that valid angr scripts pass validation."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        script = """
import angr
proj = angr.Project('./binary', auto_load_libs=False)
cfg = proj.analyses.CFGFast()
for func in cfg.kb.functions.values():
    print(func.name)
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.ANGR)

        assert result.valid is True

    def test_angr_state_not_stepped_warning(self):
        """Test warning when creating state but not using simulation manager."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        script = """
import angr
proj = angr.Project('./binary')
state = proj.factory.entry_state()
# Missing: simgr = proj.factory.simulation_manager(state)
# Missing: simgr.explore(find=...)
print(state.regs.pc)
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.ANGR)

        # This is a common mistake - creating state but not simulating
        # Should pass but may have warnings about incomplete simulation setup
        # For now, this is valid since we're just reading registers
        assert result.valid is True


class TestGhidraPatternValidation:
    """Tests for Ghidra-specific API pattern validation."""

    def test_get_bytes_warning(self):
        """Test that getBytes() without proper address generates warning."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        script = """
# Wrong: getBytes without proper context
data = getBytes(addr, 10)
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        # Should have warning about getBytes usage
        assert len(result.warnings) >= 1

    def test_get_data_at_warning(self):
        """Test that getDataAt() generates usage warning."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        script = """
data = getDataAt(addr)
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        # Should have warning about getDataAt usage
        assert len(result.warnings) >= 1

    def test_get_symbols_warning(self):
        """Test that getSymbols() generates usage warning."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        script = """
symbols = getSymbols("main")
"""
        result = ScriptValidator.validate(script, ScriptLanguage.PYTHON, ToolName.GHIDRA)

        # Should have warning about getSymbols usage
        assert len(result.warnings) >= 1


class TestDangerousShellPatterns:
    """Tests for dangerous shell pattern detection."""

    def test_mkfs_rejected(self):
        """Test that mkfs commands are rejected."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        script = "mkfs.ext4 /dev/sda1"
        result = ScriptValidator.validate(script, ScriptLanguage.SHELL, ToolName.BINWALK)

        assert result.valid is False

    def test_dd_to_dev_rejected(self):
        """Test that dd commands writing to devices are rejected."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        script = "dd if=/dev/zero of=/dev/sda"
        result = ScriptValidator.validate(script, ScriptLanguage.SHELL, ToolName.BINWALK)

        assert result.valid is False

    def test_chmod_recursive_777_warning(self):
        """Test that chmod -R 777 generates warning."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        script = "chmod -R 777 /some/path"
        result = ScriptValidator.validate(script, ScriptLanguage.SHELL, ToolName.BINWALK)

        # This should be rejected or warned
        assert result.valid is False or len(result.warnings) >= 1


class TestDangerousR2Patterns:
    """Tests for dangerous r2 pattern detection."""

    def test_shell_escape_at_start(self):
        """Test that ! at start of line is detected as shell escape."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        script = "!whoami"
        result = ScriptValidator.validate(script, ScriptLanguage.R2, ToolName.RADARE2)

        assert len(result.warnings) >= 1

    def test_shell_escape_after_semicolon(self):
        """Test that ; ! pattern is detected as shell escape."""
        from r2d2.tools.models import ScriptLanguage, ToolName
        from r2d2.tools.validator import ScriptValidator

        script = "aaa; !ls"
        result = ScriptValidator.validate(script, ScriptLanguage.R2, ToolName.RADARE2)

        assert len(result.warnings) >= 1
