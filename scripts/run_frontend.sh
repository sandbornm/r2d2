#!/usr/bin/env bash
# run_frontend.sh - Start the r2d2 Vite frontend
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND_DIR="$PROJECT_ROOT/web/frontend"
cd "$FRONTEND_DIR"

echo "╭──────────────────────────────────────╮"
echo "│  r2d2 Frontend · Vite dev on :5173   │"
echo "╰──────────────────────────────────────╯"

# Install deps if needed
if [[ ! -d "node_modules" ]]; then
    echo "Installing dependencies..."
    npm install
fi

echo ""
echo "Starting frontend..."
exec npm run dev

