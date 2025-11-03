#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BACKEND=true
FRONTEND=true

usage() {
  cat <<'EOF'
Usage: scripts/setup.sh [--backend-only|--frontend-only]

Orchestrates full project bootstrap:
  1. Backend environment via scripts/setup_backend.sh
  2. Frontend dependencies via scripts/setup_frontend.sh

Options:
  --backend-only   Only run backend setup
  --frontend-only  Only run frontend setup
  -h, --help       Show this help message
EOF
}

for arg in "$@"; do
  case "$arg" in
    --backend-only)
      FRONTEND=false
      ;;
    --frontend-only)
      BACKEND=false
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[!] Unknown option: $arg" >&2
      usage
      exit 1
      ;;
  esac
done

if $BACKEND; then
  echo "[*] Running backend setup"
  "$PROJECT_ROOT/scripts/setup_backend.sh"
else
  echo "[*] Skipping backend setup"
fi

if $FRONTEND; then
  echo "[*] Running frontend setup"
  "$PROJECT_ROOT/scripts/setup_frontend.sh"
else
  echo "[*] Skipping frontend setup"
fi

echo "[*] Setup complete"
