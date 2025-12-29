"""Integration tests for the ARM cross-compiler.

These tests verify that the compiler module can:
1. Detect Docker availability and compiler image
2. Compile C source to ARM32 and ARM64 ELF binaries
3. Generate assembly output
4. Handle freestanding (no libc) compilation
5. Report errors correctly

Prerequisites:
- Docker must be installed and running
- The r2d2-compiler:latest image must be built (run scripts/setup_compiler.sh)

Run with:
    pytest tests/integration/test_compiler.py -v
    pytest tests/integration/test_compiler.py -v -k arm64  # ARM64 only
    pytest tests/integration/test_compiler.py -v -k freestanding  # Freestanding only
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

# Mark all tests as integration tests
pytestmark = pytest.mark.integration

if TYPE_CHECKING:
    from r2d2.compilation.compiler import Architecture, CompilerResult


# ============================================================================
# Test Constants - Sample C Programs
# ============================================================================

# Simple hello world (requires libc)
HELLO_C = """\
#include <stdio.h>

int main(void) {
    puts("Hello, ARM World!");
    return 0;
}
"""

# Fibonacci - demonstrates recursion
FIBONACCI_C = """\
int fib(int n) {
    if (n <= 1) return n;
    return fib(n - 1) + fib(n - 2);
}

int main(void) {
    volatile int result = fib(10);
    return (int)result;
}
"""

# Freestanding program - no libc dependencies
FREESTANDING_C = """\
// Freestanding ARM64 Hello World
// Uses direct syscalls to write and exit

static const char msg[] = "Hello from ARM64!\\n";

void _start(void) {
    // syscall: write(1, msg, sizeof(msg)-1)
    register long x0 __asm__("x0") = 1;           // fd = stdout
    register long x1 __asm__("x1") = (long)msg;   // buf
    register long x2 __asm__("x2") = sizeof(msg) - 1;
    register long x8 __asm__("x8") = 64;          // __NR_write
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x1), "r"(x2), "r"(x8));

    // syscall: exit(0)
    x0 = 0;
    x8 = 93;  // __NR_exit
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x8));
    __builtin_unreachable();
}
"""

# ARM32 freestanding program - simpler version that avoids r7 register issues
FREESTANDING_ARM32_C = """\
// Freestanding ARM32 program
// Minimal example without inline asm register constraints

void _start(void) {
    // Simple infinite loop - just tests that we can compile freestanding
    volatile int x = 42;
    while(1) {
        x++;
    }
}
"""

# Intentionally broken C code for error testing
BROKEN_C = """\
int main(void) {
    undefined_function();  // This will cause an error
    return 0;
}
"""

# Loop structure for testing
LOOP_C = """\
int main(void) {
    volatile int sum = 0;
    for (int i = 0; i < 100; i++) {
        sum += i;
    }
    return sum;
}
"""


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture(scope="module")
def docker_available() -> bool:
    """Check if Docker is available and running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


@pytest.fixture(scope="module")
def compiler_image_ready(docker_available: bool) -> bool:
    """Check if the compiler Docker image is built."""
    if not docker_available:
        return False
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", "r2d2-compiler:latest"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for compiler output."""
    output_dir = tmp_path / "compiler_output"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


@pytest.fixture
def sample_c_file(tmp_path: Path) -> Path:
    """Create a sample C file for testing."""
    c_file = tmp_path / "test.c"
    c_file.write_text(FIBONACCI_C)
    return c_file


# ============================================================================
# Docker Availability Tests
# ============================================================================

class TestDockerDetection:
    """Tests for Docker and compiler image detection."""

    def test_docker_check_utility(self, docker_available: bool):
        """Test that Docker availability check works."""
        from r2d2.compilation.compiler import _is_docker_available
        
        result = _is_docker_available()
        assert result == docker_available

    @pytest.mark.skipif(
        subprocess.run(["docker", "info"], capture_output=True).returncode != 0,
        reason="Docker not available"
    )
    def test_docker_image_check(self, compiler_image_ready: bool):
        """Test that Docker image check works."""
        from r2d2.compilation.compiler import _docker_image_exists, DOCKER_COMPILER_IMAGE
        
        result = _docker_image_exists(DOCKER_COMPILER_IMAGE)
        assert result == compiler_image_ready

    def test_detect_compilers_includes_docker(self, compiler_image_ready: bool):
        """Test that detect_compilers includes Docker-based compilers when available."""
        from r2d2.compilation.compiler import detect_compilers
        
        compilers = detect_compilers(include_docker=True)
        
        # Should always return a dict with all architectures
        assert "arm64" in compilers
        assert "arm32" in compilers
        assert "x86" in compilers
        assert "x86_64" in compilers

        if compiler_image_ready:
            # Docker compilers should be available
            arm64_names = [c.name for c in compilers["arm64"]]
            arm32_names = [c.name for c in compilers["arm32"]]
            
            # At least one compiler should be available for ARM targets
            assert len(compilers["arm64"]) > 0 or len(compilers["arm32"]) > 0


# ============================================================================
# ARM64 Compilation Tests
# ============================================================================

@pytest.mark.skipif(
    subprocess.run(["docker", "image", "inspect", "r2d2-compiler:latest"], 
                   capture_output=True).returncode != 0,
    reason="Compiler Docker image not available"
)
class TestARM64Compilation:
    """Tests for ARM64 cross-compilation."""

    def test_compile_simple_program(self, temp_output_dir: Path):
        """Test compiling a simple C program to ARM64."""
        from r2d2.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "fibonacci_arm64"
        result = compile_c_source(
            source=FIBONACCI_C,
            architecture="arm64",
            output=output_path,
            optimization="-O0",
        )
        
        assert result.success, f"Compilation failed: {result.stderr}"
        assert result.output_path is not None
        assert result.output_path.exists()
        assert result.architecture == "arm64"
        assert "aarch64" in result.compiler_used.lower() or "docker" in result.compiler_used.lower()

    def test_compile_file_path(self, sample_c_file: Path, temp_output_dir: Path):
        """Test compiling from a file path."""
        from r2d2.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "from_file"
        result = compile_c_source(
            source=sample_c_file,
            architecture="arm64",
            output=output_path,
        )
        
        assert result.success, f"Compilation failed: {result.stderr}"
        assert result.output_path is not None

    def test_compile_with_optimization(self, temp_output_dir: Path):
        """Test compilation with different optimization levels."""
        from r2d2.compilation.compiler import compile_c_source
        
        for opt in ["-O0", "-O1", "-O2", "-O3", "-Os"]:
            output_path = temp_output_dir / f"opt_{opt.replace('-', '')}"
            result = compile_c_source(
                source=LOOP_C,
                architecture="arm64",
                output=output_path,
                optimization=opt,
            )
            
            assert result.success, f"Compilation with {opt} failed: {result.stderr}"

    def test_compile_freestanding_arm64(self, temp_output_dir: Path):
        """Test freestanding compilation (no libc) for ARM64."""
        from r2d2.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "freestanding_arm64"
        result = compile_c_source(
            source=FREESTANDING_C,
            architecture="arm64",
            output=output_path,
            extra_flags=["-ffreestanding", "-nostdlib", "-static"],
        )
        
        assert result.success, f"Freestanding compilation failed: {result.stderr}"
        assert result.output_path is not None
        assert result.output_path.exists()

    def test_generate_assembly_arm64(self, temp_output_dir: Path):
        """Test generating ARM64 assembly output."""
        from r2d2.compilation.compiler import compile_to_asm
        
        result = compile_to_asm(
            source=FIBONACCI_C,
            architecture="arm64",
            optimization="-O0",
        )
        
        assert result.success, f"Assembly generation failed: {result.stderr}"
        assert result.assembly is not None
        
        # Check for ARM64 assembly patterns
        asm = result.assembly
        assert any(pattern in asm.lower() for pattern in [
            ".text",           # Text section
            "stp", "ldp",      # ARM64 stack operations
            "bl ", "ret",      # Branch/return
            "x0", "x1",        # ARM64 registers
            "w0", "w1",        # ARM64 32-bit aliases
        ]), f"Assembly doesn't look like ARM64:\n{asm[:500]}"

    def test_verify_elf_format(self, temp_output_dir: Path):
        """Test that compiled binary is valid ELF for aarch64."""
        from r2d2.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "verify_elf"
        result = compile_c_source(
            source=FIBONACCI_C,
            architecture="arm64",
            output=output_path,
        )
        
        assert result.success
        assert result.output_path is not None
        
        # Read ELF header
        with open(result.output_path, "rb") as f:
            header = f.read(20)
        
        # Verify ELF magic
        assert header[:4] == b"\x7fELF", "Not an ELF file"
        # Verify 64-bit (class)
        assert header[4] == 2, "Not a 64-bit ELF"
        # Verify little-endian
        assert header[5] == 1, "Not little-endian"
        # Machine type for AArch64 is 0xB7 (183)
        machine = int.from_bytes(header[18:20], "little")
        assert machine == 183, f"Not an ARM64 binary (machine type: {machine})"


# ============================================================================
# ARM32 Compilation Tests
# ============================================================================

@pytest.mark.skipif(
    subprocess.run(["docker", "image", "inspect", "r2d2-compiler:latest"], 
                   capture_output=True).returncode != 0,
    reason="Compiler Docker image not available"
)
class TestARM32Compilation:
    """Tests for ARM32 cross-compilation."""

    def test_compile_simple_program_arm32(self, temp_output_dir: Path):
        """Test compiling a simple C program to ARM32."""
        from r2d2.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "fibonacci_arm32"
        result = compile_c_source(
            source=FIBONACCI_C,
            architecture="arm32",
            output=output_path,
            optimization="-O0",
        )
        
        assert result.success, f"ARM32 compilation failed: {result.stderr}"
        assert result.output_path is not None
        assert result.architecture == "arm32"

    def test_compile_freestanding_arm32(self, temp_output_dir: Path):
        """Test freestanding compilation for ARM32."""
        from r2d2.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "freestanding_arm32"
        result = compile_c_source(
            source=FREESTANDING_ARM32_C,
            architecture="arm32",
            output=output_path,
            extra_flags=["-ffreestanding", "-nostdlib", "-static"],
        )
        
        assert result.success, f"ARM32 freestanding compilation failed: {result.stderr}"

    def test_verify_arm32_elf_format(self, temp_output_dir: Path):
        """Test that compiled binary is valid ELF for ARM32."""
        from r2d2.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "verify_arm32_elf"
        result = compile_c_source(
            source=FIBONACCI_C,
            architecture="arm32",
            output=output_path,
        )
        
        assert result.success
        assert result.output_path is not None
        
        # Read ELF header
        with open(result.output_path, "rb") as f:
            header = f.read(20)
        
        # Verify ELF magic
        assert header[:4] == b"\x7fELF", "Not an ELF file"
        # Verify 32-bit (class)
        assert header[4] == 1, "Not a 32-bit ELF"
        # Machine type for ARM is 0x28 (40)
        machine = int.from_bytes(header[18:20], "little")
        assert machine == 40, f"Not an ARM32 binary (machine type: {machine})"


# ============================================================================
# Error Handling Tests
# ============================================================================

class TestCompilerErrors:
    """Tests for compiler error handling."""

    @pytest.mark.skipif(
        subprocess.run(["docker", "image", "inspect", "r2d2-compiler:latest"], 
                       capture_output=True).returncode != 0,
        reason="Compiler Docker image not available"
    )
    def test_compilation_error_reported(self, temp_output_dir: Path):
        """Test that compilation errors are properly reported."""
        from r2d2.compilation.compiler import compile_c_source
        
        output_path = temp_output_dir / "broken"
        result = compile_c_source(
            source=BROKEN_C,
            architecture="arm64",
            output=output_path,
        )
        
        assert not result.success
        assert result.return_code != 0
        # Should have error message about undefined function
        assert "undefined" in result.stderr.lower() or "undeclared" in result.stderr.lower()

    def test_docker_not_available_error(self, monkeypatch):
        """Test error when Docker is not available."""
        from r2d2.compilation import compiler
        
        # Mock Docker as unavailable
        monkeypatch.setattr(compiler, "_is_docker_available", lambda: False)
        monkeypatch.setattr(compiler, "detect_compilers", lambda include_docker=True: {
            "arm64": [],
            "arm32": [],
            "x86": [],
            "x86_64": [],
        })
        
        from r2d2.compilation.compiler import compile_c_source
        
        result = compile_c_source(
            source=FIBONACCI_C,
            architecture="arm64",
        )
        
        assert not result.success
        assert "docker" in result.stderr.lower() or "compiler" in result.stderr.lower()

    def test_invalid_source_file(self, temp_output_dir: Path):
        """Test handling of non-existent source file."""
        from r2d2.compilation.compiler import compile_c_source
        
        result = compile_c_source(
            source=Path("/nonexistent/path/to/source.c"),
            architecture="arm64",
            output=temp_output_dir / "output",
        )
        
        assert not result.success


# ============================================================================
# API Integration Tests
# ============================================================================

@pytest.mark.skipif(
    subprocess.run(["docker", "image", "inspect", "r2d2-compiler:latest"], 
                   capture_output=True).returncode != 0,
    reason="Compiler Docker image not available"
)
class TestCompilerAPI:
    """Tests for the /api/compile endpoint."""

    @pytest.fixture
    def app_client(self, tmp_path: Path):
        """Create a test client for the Flask app."""
        from unittest.mock import patch
        from r2d2.web.app import create_app
        from r2d2.config import AppConfig, StorageSettings, AnalysisSettings

        with patch.dict('os.environ', {'R2D2_WEB_DEBUG': 'false'}):
            with patch('r2d2.config.load_config') as mock_config:
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

    def test_list_compilers_endpoint(self, app_client):
        """Test /api/compilers endpoint."""
        response = app_client.get('/api/compilers')
        
        assert response.status_code == 200
        data = response.get_json()
        assert "compilers" in data
        assert "arm64" in data["compilers"]
        assert "arm32" in data["compilers"]

    def test_compile_endpoint_requires_source(self, app_client):
        """Test that compile endpoint requires source."""
        response = app_client.post(
            '/api/compile',
            json={"architecture": "arm64"},
            content_type='application/json',
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_compile_endpoint_arm64(self, app_client):
        """Test compile endpoint with ARM64 target."""
        response = app_client.post(
            '/api/compile',
            json={
                "source": FIBONACCI_C,
                "architecture": "arm64",
                "optimization": "-O0",
                "emit_asm": True,
            },
            content_type='application/json',
        )
        
        assert response.status_code == 200, f"Compile failed: {response.get_json()}"
        data = response.get_json()
        assert data["success"] is True
        assert "output_path" in data
        assert data["architecture"] == "arm64"
        # Assembly should be included
        assert "assembly" in data

    def test_compile_endpoint_arm32(self, app_client):
        """Test compile endpoint with ARM32 target."""
        response = app_client.post(
            '/api/compile',
            json={
                "source": FIBONACCI_C,
                "architecture": "arm32",
                "optimization": "-O0",
            },
            content_type='application/json',
        )
        
        assert response.status_code == 200, f"Compile failed: {response.get_json()}"
        data = response.get_json()
        assert data["success"] is True
        assert data["architecture"] == "arm32"

    def test_compile_endpoint_freestanding(self, app_client):
        """Test compile endpoint with freestanding mode."""
        response = app_client.post(
            '/api/compile',
            json={
                "source": FREESTANDING_C,
                "architecture": "arm64",
                "freestanding": True,
            },
            content_type='application/json',
        )
        
        assert response.status_code == 200, f"Compile failed: {response.get_json()}"
        data = response.get_json()
        assert data["success"] is True

    def test_compile_endpoint_error_handling(self, app_client):
        """Test compile endpoint error handling."""
        response = app_client.post(
            '/api/compile',
            json={
                "source": BROKEN_C,
                "architecture": "arm64",
            },
            content_type='application/json',
        )
        
        # Should return 400 for compilation error
        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False
        assert "stderr" in data
        assert len(data["stderr"]) > 0


# ============================================================================
# Sample Programs Tests (from samples/c/)
# ============================================================================

@pytest.mark.skipif(
    subprocess.run(["docker", "image", "inspect", "r2d2-compiler:latest"], 
                   capture_output=True).returncode != 0,
    reason="Compiler Docker image not available"
)
class TestSamplePrograms:
    """Tests that compile sample programs from samples/c/."""

    @pytest.fixture
    def samples_dir(self) -> Path:
        """Get the samples/c directory."""
        project_root = Path(__file__).parent.parent.parent
        samples = project_root / "samples" / "c"
        if not samples.exists():
            pytest.skip("samples/c directory not found")
        return samples

    def test_compile_hello_c(self, samples_dir: Path, temp_output_dir: Path):
        """Test compiling hello.c sample."""
        from r2d2.compilation.compiler import compile_c_source
        
        hello_c = samples_dir / "hello.c"
        if not hello_c.exists():
            pytest.skip("hello.c not found")
        
        result = compile_c_source(
            source=hello_c,
            architecture="arm64",
            output=temp_output_dir / "hello",
        )
        
        assert result.success, f"Failed to compile hello.c: {result.stderr}"

    def test_compile_fibonacci_c(self, samples_dir: Path, temp_output_dir: Path):
        """Test compiling fibonacci.c sample."""
        from r2d2.compilation.compiler import compile_c_source
        
        fib_c = samples_dir / "fibonacci.c"
        if not fib_c.exists():
            pytest.skip("fibonacci.c not found")
        
        result = compile_c_source(
            source=fib_c,
            architecture="arm64",
            output=temp_output_dir / "fibonacci",
        )
        
        assert result.success, f"Failed to compile fibonacci.c: {result.stderr}"

    def test_compile_all_samples_arm64(self, samples_dir: Path, temp_output_dir: Path):
        """Test compiling all sample C files to ARM64."""
        from r2d2.compilation.compiler import compile_c_source
        
        # Files that require freestanding mode (define _start, no libc)
        FREESTANDING_FILES = {"syscalls.c"}
        
        c_files = list(samples_dir.glob("*.c"))
        assert len(c_files) > 0, "No C files found in samples/c"
        
        failed = []
        for c_file in c_files:
            output = temp_output_dir / c_file.stem
            
            # Some files need freestanding mode
            # Use -nostartfiles to avoid crt1.o conflict when code defines _start
            extra_flags = None
            if c_file.name in FREESTANDING_FILES:
                extra_flags = ["-ffreestanding", "-nostartfiles", "-nodefaultlibs", "-static"]
            
            result = compile_c_source(
                source=c_file,
                architecture="arm64",
                output=output,
                extra_flags=extra_flags,
            )
            
            if not result.success:
                failed.append((c_file.name, result.stderr))
        
        if failed:
            failure_msg = "\n".join(f"  {name}: {err[:100]}" for name, err in failed)
            pytest.fail(f"Failed to compile:\n{failure_msg}")

