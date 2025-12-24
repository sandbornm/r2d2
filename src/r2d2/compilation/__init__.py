"""Compilation module for assembling and compiling code."""

from .compiler import (
    Compiler,
    CompilerResult,
    detect_compilers,
    compile_c_source,
    assemble_source,
)

__all__ = [
    "Compiler",
    "CompilerResult",
    "detect_compilers",
    "compile_c_source",
    "assemble_source",
]
