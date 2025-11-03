#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Ensure local src/ is importable for Python entrypoints
export PYTHONPATH="$PROJECT_ROOT/src:${PYTHONPATH:-}"

if ! command -v uv >/dev/null 2>&1; then
  echo "[!] uv not found. Run scripts/setup.sh first." >&2
  exit 1
fi

echo "[*] Performing environment check"
uv run scripts/detect_env.py --json > .dry_run_env.json

if [ -f sample.bin ]; then
  echo "[*] Running quick analysis on sample.bin"
  uv run r2d2 sample.bin --quick --json > .dry_run_analysis.json || echo "[!] Analysis failed (expected if dependencies missing)"
else
  echo "[i] Place a sample binary at sample.bin to exercise analysis pipeline"
fi

echo "[*] Artifacts written to .dry_run_env.json and .dry_run_analysis.json"
