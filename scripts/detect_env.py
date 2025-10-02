#!/usr/bin/env python3
"""Standalone environment check script."""

from __future__ import annotations

import argparse
from pathlib import Path

from r2d2.config import load_config
from r2d2.environment import detect_environment
from r2d2.utils import to_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect r2d2 runtime environment")
    parser.add_argument("--config", type=Path, help="Optional config override", default=None)
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args()

    config = load_config(args.config)
    report = detect_environment(config)

    if args.json:
        print(to_json(report))
        return

    print(f"Python: {report.python_version}")
    print(f"uv available: {report.uv_available}")
    print(f"OpenAI key present: {report.openai_key_present}")
    for tool in report.tools:
        status = "ok" if tool.available else "missing"
        detail = tool.version or tool.details or ""
        print(f" - {tool.name}: {status} {detail}")
    if report.ghidra:
        print(f"Ghidra ready: {report.ghidra.is_ready}")
        for issue in report.ghidra.issues:
            print(f"   issue: {issue}")
        for note in report.ghidra.notes:
            print(f"   note: {note}")
    for issue in report.issues:
        print(f"ISSUE: {issue}")


if __name__ == "__main__":
    main()
