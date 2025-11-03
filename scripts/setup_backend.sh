#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

PYTHON_VERSION="3.11"

if ! command -v uv >/dev/null 2>&1; then
  echo "[!] uv is required. Install from https://github.com/astral-sh/uv" >&2
  exit 1
fi

if ! uv python list | grep -q "$PYTHON_VERSION"; then
  echo "[*] Installing Python $PYTHON_VERSION via uv"
  uv python install "$PYTHON_VERSION"
fi

echo "[*] Synchronising backend dependencies"
uv sync --python "$PYTHON_VERSION" --no-dev

echo "[*] Installing analyzer extras (radare2 bindings, capstone, angr)"
uv sync --python "$PYTHON_VERSION" --extra analyzers --no-dev || \
  echo "[!] Analyzer extras failed; install manually (radare2, capstone, angr)"

if grep -q "\"anthropic\"" pyproject.toml; then
  echo "[*] Ensuring LLM dependencies are installed"
  uv pip install anthropic || echo "[!] anthropic python package could not be installed automatically"
fi

mkdir -p "$HOME/.config/r2d2" "$HOME/.local/share/r2d2"
if [ ! -f "$HOME/.config/r2d2/config.toml" ]; then
  cp "$PROJECT_ROOT/config/default_config.toml" "$HOME/.config/r2d2/config.toml"
fi

echo "[*] Running environment diagnostics"
uv run scripts/detect_env.py || true

echo "[*] Backend setup complete"
