#!/usr/bin/env bash
# run_backend.sh - Start the r2d2 Flask backend
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "╭─────────────────────────────────────╮"
echo "│  r2d2 Backend · Flask API on :5050  │"
echo "╰─────────────────────────────────────╯"

# Check API keys
if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    echo "✓ ANTHROPIC_API_KEY set"
else
    echo "⚠ ANTHROPIC_API_KEY not set"
fi

echo ""
echo "Starting backend..."
exec uv run r2d2-web

