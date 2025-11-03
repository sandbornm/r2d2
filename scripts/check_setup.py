#!/usr/bin/env python3
"""Verify core r2d2 wiring (env vars, tooling, web app bootstrap)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure local src/ is on sys.path when running via `uv run scripts/...`
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from r2d2.state import build_state
from r2d2.web.app import create_app


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Optional path to config TOML (defaults to search order)",
    )
    args = parser.parse_args()

    state = build_state(args.config)
    errors: list[str] = []
    warnings: list[str] = []

    if not state.env.openai_key_present:
        errors.append(
            f"Environment variable {state.config.llm.api_key_env} is missing; set it before using the LLM."
        )

    ghidra_ready = bool(state.env.ghidra and state.env.ghidra.is_ready)
    if not ghidra_ready:
        warnings.append("Ghidra is not fully configured. Deep scans may be limited.")

    missing_tools = state.env.missing_tools()
    if missing_tools:
        warnings.append("Missing tools: " + ", ".join(missing_tools))

    try:
        create_app(args.config)
    except Exception as exc:  # pragma: no cover - defensive check
        errors.append(f"Failed to bootstrap web application: {exc}")

    print("r2d2 setup check\n==================")
    print(f"- Model: {state.config.llm.model}")
    print(f"- OPENAI key present: {'yes' if state.env.openai_key_present else 'no'}")
    print(f"- Ghidra ready: {'yes' if ghidra_ready else 'no'}")
    print(f"- Toolchain ready: {'yes' if not missing_tools else 'no'}")

    if warnings:
        print("\nWarnings:")
        for warning in warnings:
            print(f"  • {warning}")

    if errors:
        print("\nErrors:")
        for error in errors:
            print(f"  • {error}")
        return 1

    print("\nAll required components look good! 🎉")
    return 0


if __name__ == "__main__":
    sys.exit(main())
