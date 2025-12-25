#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BACKEND=true
FRONTEND=true
COMPILER=false

usage() {
  cat <<'EOF'
Usage: scripts/setup.sh [options]

Orchestrates full project bootstrap:
  1. Backend environment via scripts/setup_backend.sh
  2. Frontend dependencies via scripts/setup_frontend.sh
  3. Compiler container via scripts/setup_compiler.sh (optional)

Options:
  --backend-only    Only run backend setup
  --frontend-only   Only run frontend setup
  --compiler-only   Only run compiler container setup
  --with-compiler   Include compiler container setup (Docker required)
  --all             Run all setup including compiler
  -h, --help        Show this help message

Examples:
  # Standard setup (backend + frontend)
  ./scripts/setup.sh

  # Full setup including ARM compiler container
  ./scripts/setup.sh --with-compiler

  # Only set up the compiler container
  ./scripts/setup.sh --compiler-only
EOF
}

for arg in "$@"; do
  case "$arg" in
    --backend-only)
      FRONTEND=false
      COMPILER=false
      ;;
    --frontend-only)
      BACKEND=false
      COMPILER=false
      ;;
    --compiler-only)
      BACKEND=false
      FRONTEND=false
      COMPILER=true
      ;;
    --with-compiler)
      COMPILER=true
      ;;
    --all)
      BACKEND=true
      FRONTEND=true
      COMPILER=true
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

if $COMPILER; then
  echo "[*] Running compiler container setup"
  "$PROJECT_ROOT/scripts/setup_compiler.sh"
else
  echo "[*] Skipping compiler setup (use --with-compiler to include)"
fi

echo "[*] Setup complete"
