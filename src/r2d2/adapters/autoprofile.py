"""Auto-profiling adapter for quick binary characterization.

Runs file, strings, readelf, checksec, and binwalk to profile a binary.
Identifies security features, interesting patterns, and risk indicators.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_LOGGER = logging.getLogger(__name__)

# Pattern categories for string analysis
NETWORK_PATTERNS = [
    r"socket", r"connect", r"listen", r"bind", r"accept",
    r"send", r"recv", r"http", r"https", r"ftp", r"ssh",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses
    r"://",  # URLs
]

CRYPTO_PATTERNS = [
    r"aes", r"des", r"rsa", r"sha\d*", r"md5", r"encrypt", r"decrypt",
    r"cipher", r"key", r"ssl", r"tls", r"certificate",
]

FILE_IO_PATTERNS = [
    r"fopen", r"fread", r"fwrite", r"open", r"read", r"write",
    r"close", r"unlink", r"remove", r"rename", r"/etc/", r"/proc/",
    r"/dev/", r"/tmp/",
]

DANGEROUS_PATTERNS = [
    r"system", r"exec", r"popen", r"fork", r"eval", r"gets",
    r"strcpy", r"strcat", r"sprintf", r"scanf", r"memcpy",
    r"setuid", r"setgid", r"chroot", r"ptrace",
]

SUSPICIOUS_PATTERNS = [
    r"backdoor", r"shell", r"exploit", r"payload", r"inject",
    r"hook", r"rootkit", r"keylog", r"password", r"credential",
]


@dataclass
class SecurityFeatures:
    """Security features detected via checksec or readelf."""
    relro: str = "unknown"  # no, partial, full
    stack_canary: bool | None = None
    nx: bool | None = None  # No Execute
    pie: bool | None = None  # Position Independent Executable
    fortify: bool | None = None
    rpath: bool | None = None
    runpath: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "relro": self.relro,
            "stack_canary": self.stack_canary,
            "nx": self.nx,
            "pie": self.pie,
            "fortify": self.fortify,
            "rpath": self.rpath,
            "runpath": self.runpath,
        }


@dataclass
class BinaryProfile:
    """Complete profile of a binary."""
    # Basic info
    file_type: str = ""
    architecture: str = ""
    bits: int | None = None
    endian: str = "unknown"
    is_stripped: bool | None = None
    has_debug_info: bool | None = None

    # Security
    security: SecurityFeatures = field(default_factory=SecurityFeatures)

    # Strings analysis
    total_strings: int = 0
    network_strings: list[str] = field(default_factory=list)
    crypto_strings: list[str] = field(default_factory=list)
    file_io_strings: list[str] = field(default_factory=list)
    dangerous_functions: list[str] = field(default_factory=list)
    suspicious_strings: list[str] = field(default_factory=list)

    # Binwalk findings
    embedded_files: list[dict[str, Any]] = field(default_factory=list)
    has_compressed_data: bool = False
    has_encrypted_data: bool = False

    # Risk indicators
    risk_level: str = "low"  # low, medium, high
    risk_factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_type": self.file_type,
            "architecture": self.architecture,
            "bits": self.bits,
            "endian": self.endian,
            "is_stripped": self.is_stripped,
            "has_debug_info": self.has_debug_info,
            "security": self.security.to_dict(),
            "total_strings": self.total_strings,
            "network_strings": self.network_strings[:20],  # Limit for API
            "crypto_strings": self.crypto_strings[:20],
            "file_io_strings": self.file_io_strings[:20],
            "dangerous_functions": self.dangerous_functions[:20],
            "suspicious_strings": self.suspicious_strings[:20],
            "embedded_files": self.embedded_files[:10],
            "has_compressed_data": self.has_compressed_data,
            "has_encrypted_data": self.has_encrypted_data,
            "risk_level": self.risk_level,
            "risk_factors": self.risk_factors,
        }


@dataclass(slots=True)
class AutoProfileAdapter:
    """Quick binary profiling using standard Unix tools."""

    name: str = "autoprofile"
    timeout: int = 30

    def is_available(self) -> bool:
        """Check if at least 'file' command is available."""
        return shutil.which("file") is not None

    def quick_scan(self, binary: Path, **kwargs: Any) -> dict[str, Any]:
        """Run quick profiling tools and return results."""
        if not binary.exists():
            return {"error": f"Binary not found: {binary}"}

        profile = BinaryProfile()

        # Run tools in parallel-ish manner
        self._run_file(binary, profile)
        self._run_strings(binary, profile)
        self._run_readelf(binary, profile)
        self._run_checksec(binary, profile)
        self._run_binwalk(binary, profile)

        # Calculate risk level
        self._calculate_risk(profile)

        return {
            "mode": "autoprofile",
            "profile": profile.to_dict(),
        }

    def deep_scan(
        self, binary: Path, *, resource_tree: Any | None = None, **kwargs: Any
    ) -> dict[str, Any]:
        """Deep scan is same as quick scan for autoprofile."""
        return self.quick_scan(binary, **kwargs)

    def _run_cmd(self, cmd: list[str], timeout: int | None = None) -> tuple[str, str, int]:
        """Run a command and return (stdout, stderr, returncode)."""
        timeout = timeout or self.timeout
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            _LOGGER.warning("Command timed out: %s", " ".join(cmd))
            return "", "timeout", -1
        except FileNotFoundError:
            return "", "command not found", -1
        except Exception as e:
            _LOGGER.warning("Command failed: %s - %s", " ".join(cmd), e)
            return "", str(e), -1

    def _run_file(self, binary: Path, profile: BinaryProfile) -> None:
        """Run 'file' command to identify binary type."""
        stdout, stderr, rc = self._run_cmd(["file", "-b", str(binary)])
        if rc == 0 and stdout:
            profile.file_type = stdout.strip()

            # Parse architecture from file output
            lower = stdout.lower()
            if "arm" in lower or "aarch64" in lower:
                profile.architecture = "arm64" if "aarch64" in lower or "64-bit" in lower else "arm32"
            elif "x86-64" in lower or "x86_64" in lower:
                profile.architecture = "x86_64"
            elif "80386" in lower or "i386" in lower:
                profile.architecture = "x86"
            elif "mips" in lower:
                profile.architecture = "mips64" if "64-bit" in lower else "mips32"

            # Parse bits
            if "64-bit" in lower:
                profile.bits = 64
            elif "32-bit" in lower:
                profile.bits = 32

            # Parse endianness
            if "lsb" in lower or "little" in lower:
                profile.endian = "little"
            elif "msb" in lower or "big" in lower:
                profile.endian = "big"

            # Check if stripped
            profile.is_stripped = "stripped" in lower and "not stripped" not in lower
            profile.has_debug_info = "with debug" in lower or "not stripped" in lower

    def _run_strings(self, binary: Path, profile: BinaryProfile) -> None:
        """Run 'strings' command and categorize findings."""
        stdout, stderr, rc = self._run_cmd(["strings", "-n", "4", str(binary)])
        if rc != 0:
            return

        all_strings = stdout.splitlines()
        profile.total_strings = len(all_strings)

        # Categorize strings
        for s in all_strings:
            s_lower = s.lower()

            # Check each category
            for pattern in NETWORK_PATTERNS:
                if re.search(pattern, s_lower):
                    if s not in profile.network_strings:
                        profile.network_strings.append(s)
                    break

            for pattern in CRYPTO_PATTERNS:
                if re.search(pattern, s_lower):
                    if s not in profile.crypto_strings:
                        profile.crypto_strings.append(s)
                    break

            for pattern in FILE_IO_PATTERNS:
                if re.search(pattern, s_lower):
                    if s not in profile.file_io_strings:
                        profile.file_io_strings.append(s)
                    break

            for pattern in DANGEROUS_PATTERNS:
                if re.search(pattern, s_lower):
                    if s not in profile.dangerous_functions:
                        profile.dangerous_functions.append(s)
                    break

            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, s_lower):
                    if s not in profile.suspicious_strings:
                        profile.suspicious_strings.append(s)
                    break

    def _run_readelf(self, binary: Path, profile: BinaryProfile) -> None:
        """Run readelf to check for security features and debug info."""
        if not shutil.which("readelf"):
            return

        # Check for debug sections
        stdout, stderr, rc = self._run_cmd(["readelf", "-S", str(binary)])
        if rc == 0:
            if ".debug_info" in stdout or ".debug_line" in stdout:
                profile.has_debug_info = True

        # Check dynamic section for security features
        stdout, stderr, rc = self._run_cmd(["readelf", "-d", str(binary)])
        if rc == 0:
            lower = stdout.lower()

            # RELRO check
            if "bind_now" in lower:
                profile.security.relro = "full"
            elif "relro" in stdout.lower():
                # Check for RELRO in program headers
                stdout_ph, _, _ = self._run_cmd(["readelf", "-l", str(binary)])
                if "gnu_relro" in stdout_ph.lower():
                    profile.security.relro = "partial"

            # RPATH/RUNPATH check
            profile.security.rpath = "rpath" in lower
            profile.security.runpath = "runpath" in lower

        # Check for FORTIFY
        stdout, stderr, rc = self._run_cmd(["readelf", "-s", str(binary)])
        if rc == 0:
            profile.security.fortify = "_chk@" in stdout

    def _run_checksec(self, binary: Path, profile: BinaryProfile) -> None:
        """Run checksec if available to get security features."""
        checksec = shutil.which("checksec") or shutil.which("checksec.sh")
        if not checksec:
            # Try to infer from readelf output we already have
            return

        stdout, stderr, rc = self._run_cmd([checksec, "--file", str(binary)])
        if rc != 0:
            # Try alternative checksec syntax
            stdout, stderr, rc = self._run_cmd([checksec, str(binary)])

        if rc == 0 and stdout:
            lower = stdout.lower()

            # Parse checksec output
            if "full relro" in lower:
                profile.security.relro = "full"
            elif "partial relro" in lower:
                profile.security.relro = "partial"
            elif "no relro" in lower:
                profile.security.relro = "none"

            profile.security.stack_canary = "canary found" in lower
            profile.security.nx = "nx enabled" in lower
            profile.security.pie = "pie enabled" in lower
            profile.security.fortify = "fortify" in lower and "no fortify" not in lower

    def _run_binwalk(self, binary: Path, profile: BinaryProfile) -> None:
        """Run binwalk to detect embedded files and data."""
        if not shutil.which("binwalk"):
            return

        stdout, stderr, rc = self._run_cmd(["binwalk", "-B", str(binary)])
        if rc != 0:
            return

        lines = stdout.strip().splitlines()
        for line in lines[3:]:  # Skip header
            if not line.strip():
                continue

            # Parse binwalk output: DECIMAL HEXADECIMAL DESCRIPTION
            parts = line.split(None, 2)
            if len(parts) >= 3:
                try:
                    offset = int(parts[0])
                    description = parts[2]

                    profile.embedded_files.append({
                        "offset": offset,
                        "description": description,
                    })

                    desc_lower = description.lower()
                    if any(c in desc_lower for c in ["compress", "gzip", "zlib", "lzma", "bzip"]):
                        profile.has_compressed_data = True
                    if any(c in desc_lower for c in ["encrypt", "aes", "des", "cipher"]):
                        profile.has_encrypted_data = True
                except ValueError:
                    continue

    def _calculate_risk(self, profile: BinaryProfile) -> None:
        """Calculate risk level based on findings."""
        risk_score = 0
        factors = []

        # Security feature checks
        if profile.security.relro == "none":
            risk_score += 1
            factors.append("No RELRO protection")
        if profile.security.stack_canary is False:
            risk_score += 1
            factors.append("No stack canary")
        if profile.security.nx is False:
            risk_score += 2
            factors.append("NX disabled (executable stack)")
        if profile.security.pie is False:
            risk_score += 1
            factors.append("Not position independent")

        # Dangerous functions
        if len(profile.dangerous_functions) > 5:
            risk_score += 2
            factors.append(f"{len(profile.dangerous_functions)} potentially dangerous functions")
        elif len(profile.dangerous_functions) > 0:
            risk_score += 1
            factors.append(f"{len(profile.dangerous_functions)} potentially dangerous function(s)")

        # Suspicious strings
        if len(profile.suspicious_strings) > 0:
            risk_score += 2
            factors.append(f"{len(profile.suspicious_strings)} suspicious string(s) found")

        # Network activity indicators
        if len(profile.network_strings) > 10:
            risk_score += 1
            factors.append("Significant network-related strings")

        # RPATH/RUNPATH (can be hijacked)
        if profile.security.rpath:
            risk_score += 1
            factors.append("RPATH set (potential DLL hijacking)")
        if profile.security.runpath:
            risk_score += 1
            factors.append("RUNPATH set (potential DLL hijacking)")

        # Encrypted/compressed content
        if profile.has_encrypted_data:
            risk_score += 1
            factors.append("Contains encrypted data sections")

        # Determine risk level
        if risk_score >= 5:
            profile.risk_level = "high"
        elif risk_score >= 2:
            profile.risk_level = "medium"
        else:
            profile.risk_level = "low"

        profile.risk_factors = factors
