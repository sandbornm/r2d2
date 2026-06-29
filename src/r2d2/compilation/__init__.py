"""Compilation module for assembling and compiling code."""

from .compiler import (
    Compiler,
    CompilerResult,
    detect_compilers,
    compile_c_source,
    compile_to_asm,
    assemble_source,
    get_compile_command_preview,
)
from .sniffer import preview_compile_with_capabilities, sniff_compiler_capabilities

__all__ = [
    "Compiler",
    "CompilerResult",
    "detect_compilers",
    "compile_c_source",
    "compile_to_asm",
    "assemble_source",
    "get_compile_command_preview",
    "preview_compile_with_capabilities",
    "sniff_compiler_capabilities",
]
