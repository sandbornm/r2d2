#!/usr/bin/env bash
################################################################################
# setup_compiler.sh - ARM Cross-Compiler Container Setup
#
# Builds and verifies the Docker container for ARM cross-compilation.
# This script can be run standalone or via scripts/setup.sh --compiler
#
# Prerequisites:
#   - Docker installed and running
#
# Usage:
#   ./scripts/setup_compiler.sh [options]
#
# Options:
#   --rebuild    Force rebuild the Docker image (don't use cache)
#   --verify     Only verify the image, don't build
#   --quiet      Suppress non-error output
#   -h, --help   Show this help message
################################################################################
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_IMAGE="r2d2-compiler:latest"
DOCKERFILE="Dockerfile.compiler"

# Default options
REBUILD=false
VERIFY_ONLY=false
QUIET=false

log() {
    if ! $QUIET; then
        echo -e "${BLUE}[*]${NC} $1"
    fi
}

log_success() {
    if ! $QUIET; then
        echo -e "${GREEN}[✓]${NC} $1"
    fi
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[✗]${NC} $1" >&2
}

usage() {
    cat <<'EOF'
Usage: scripts/setup_compiler.sh [options]

Sets up the Docker container for ARM cross-compilation.

Options:
  --rebuild    Force rebuild the Docker image (don't use cache)
  --verify     Only verify the image, don't build
  --quiet      Suppress non-error output
  -h, --help   Show this help message

The compiler container provides:
  - ARM32 (arm-linux-gnueabihf-gcc) cross-compiler
  - ARM64 (aarch64-linux-gnu-gcc) cross-compiler
  - Both compilers can compile C to ELF binaries

Examples:
  # First-time setup
  ./scripts/setup_compiler.sh

  # Force rebuild after Dockerfile changes
  ./scripts/setup_compiler.sh --rebuild

  # Check if container is ready
  ./scripts/setup_compiler.sh --verify
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rebuild)
            REBUILD=true
            shift
            ;;
        --verify)
            VERIFY_ONLY=true
            shift
            ;;
        --quiet)
            QUIET=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Check Docker availability
check_docker() {
    log "Checking Docker availability..."
    
    if ! command -v docker &>/dev/null; then
        log_error "Docker is not installed. Please install Docker Desktop or docker-ce."
        exit 1
    fi
    
    if ! docker info &>/dev/null; then
        log_error "Docker daemon is not running. Please start Docker."
        exit 1
    fi
    
    log_success "Docker is available and running"
}

# Check if image exists
image_exists() {
    docker image inspect "$DOCKER_IMAGE" &>/dev/null
}

# Build the Docker image
build_image() {
    log "Building Docker image: $DOCKER_IMAGE"
    
    local build_args=("--tag" "$DOCKER_IMAGE")
    
    if $REBUILD; then
        log "Forcing rebuild (no cache)..."
        build_args+=("--no-cache")
    fi
    
    build_args+=("--file" "$PROJECT_ROOT/$DOCKERFILE")
    build_args+=("$PROJECT_ROOT")
    
    if $QUIET; then
        docker build "${build_args[@]}" --quiet
    else
        docker build "${build_args[@]}"
    fi
    
    if [[ $? -eq 0 ]]; then
        log_success "Docker image built successfully"
    else
        log_error "Failed to build Docker image"
        exit 1
    fi
}

# Verify the toolchains in the container
verify_toolchains() {
    log "Verifying ARM toolchains..."
    
    local failed=false
    
    # Test ARM32 compiler (use -c since entrypoint is /bin/bash)
    log "  Testing ARM32 compiler (arm-linux-gnueabihf-gcc)..."
    if docker run --rm "$DOCKER_IMAGE" -c "arm-linux-gnueabihf-gcc --version" &>/dev/null; then
        local arm32_version
        arm32_version=$(docker run --rm "$DOCKER_IMAGE" -c "arm-linux-gnueabihf-gcc --version" 2>/dev/null | head -n1)
        log_success "  ARM32: $arm32_version"
    else
        log_error "  ARM32 compiler not working"
        failed=true
    fi
    
    # Test ARM64 compiler
    log "  Testing ARM64 compiler (aarch64-linux-gnu-gcc)..."
    if docker run --rm "$DOCKER_IMAGE" -c "aarch64-linux-gnu-gcc --version" &>/dev/null; then
        local arm64_version
        arm64_version=$(docker run --rm "$DOCKER_IMAGE" -c "aarch64-linux-gnu-gcc --version" 2>/dev/null | head -n1)
        log_success "  ARM64: $arm64_version"
    else
        log_error "  ARM64 compiler not working"
        failed=true
    fi
    
    if $failed; then
        log_error "Toolchain verification failed"
        exit 1
    fi
    
    log_success "All toolchains verified"
}

# Global variable for test cleanup
_TEST_TMPDIR=""

# Cleanup function for unexpected exits
cleanup_on_exit() {
    if [[ -n "$_TEST_TMPDIR" && -d "$_TEST_TMPDIR" ]]; then
        rm -rf "$_TEST_TMPDIR" 2>/dev/null || true
    fi
}
trap cleanup_on_exit EXIT

# Test compilation with a simple C program
test_compilation() {
    log "Running compilation tests..."
    
    local test_source='
#include <stdio.h>
int main(void) { return 42; }
'
    _TEST_TMPDIR=$(mktemp -d)
    local tmpdir="$_TEST_TMPDIR"
    
    echo "$test_source" > "$tmpdir/test.c"
    
    # Test ARM64 compilation (use -c to pass commands through bash entrypoint)
    log "  Compiling test program for ARM64..."
    if docker run --rm -v "$tmpdir:/compile" -w /compile "$DOCKER_IMAGE" \
        -c "aarch64-linux-gnu-gcc -o test_arm64 test.c" &>/dev/null; then
        
        # Verify it's an ELF for aarch64 using host file command or check ELF magic
        if [[ -f "$tmpdir/test_arm64" ]]; then
            local magic
            magic=$(head -c 4 "$tmpdir/test_arm64" 2>/dev/null | xxd -p || echo "")
            if [[ "$magic" == "7f454c46" ]]; then
                log_success "  ARM64 compilation produces valid ELF"
            else
                log_warn "  ARM64 binary may not be correct format (magic: $magic)"
            fi
        else
            log_warn "  ARM64 output file not found"
        fi
    else
        log_error "  ARM64 test compilation failed"
        return 1
    fi
    
    # Test ARM32 compilation
    log "  Compiling test program for ARM32..."
    if docker run --rm -v "$tmpdir:/compile" -w /compile "$DOCKER_IMAGE" \
        -c "arm-linux-gnueabihf-gcc -o test_arm32 test.c" &>/dev/null; then
        
        # Verify ELF magic bytes on host
        if [[ -f "$tmpdir/test_arm32" ]]; then
            local magic
            magic=$(head -c 4 "$tmpdir/test_arm32" 2>/dev/null | xxd -p || echo "")
            if [[ "$magic" == "7f454c46" ]]; then
                log_success "  ARM32 compilation produces valid ELF"
            else
                log_warn "  ARM32 binary may not be correct format (magic: $magic)"
            fi
        else
            log_warn "  ARM32 output file not found"
        fi
    else
        log_error "  ARM32 test compilation failed"
        return 1
    fi
    
    # Test freestanding compilation (no libc)
    log "  Testing freestanding compilation..."
    local freestanding_source='
void _start(void) {
    volatile int x = 42;
    while(1);
}
'
    echo "$freestanding_source" > "$tmpdir/freestanding.c"
    
    if docker run --rm -v "$tmpdir:/compile" -w /compile "$DOCKER_IMAGE" \
        -c "aarch64-linux-gnu-gcc -ffreestanding -nostdlib -static -o freestanding freestanding.c" &>/dev/null; then
        log_success "  Freestanding compilation works"
    else
        log_error "  Freestanding compilation failed"
        return 1
    fi
    
    # Cleanup (also handled by trap on exit)
    rm -rf "$tmpdir" 2>/dev/null || true
    _TEST_TMPDIR=""
    
    log_success "All compilation tests passed"
    return 0
}

# Print summary
print_summary() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ARM Compiler Container Ready"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  Image: $DOCKER_IMAGE"
    echo ""
    echo "  Available compilers:"
    echo "    • ARM32: arm-linux-gnueabihf-gcc"
    echo "    • ARM64: aarch64-linux-gnu-gcc"
    echo ""
    echo "  Usage in r2d2:"
    echo "    - The web UI compiler panel uses this automatically"
    echo "    - API: POST /api/compile with source and architecture"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
}

# Main execution
main() {
    cd "$PROJECT_ROOT"
    
    check_docker
    
    if $VERIFY_ONLY; then
        if image_exists; then
            log_success "Docker image exists: $DOCKER_IMAGE"
            verify_toolchains
            if ! test_compilation; then
                log_error "Compilation tests failed"
                exit 1
            fi
            print_summary
        else
            log_error "Docker image not found: $DOCKER_IMAGE"
            log "Run without --verify to build the image"
            exit 1
        fi
    else
        # Build if image doesn't exist or rebuild requested
        if ! image_exists || $REBUILD; then
            build_image
        else
            log_success "Docker image already exists: $DOCKER_IMAGE"
            log "Use --rebuild to force rebuild"
        fi
        
        verify_toolchains
        if ! test_compilation; then
            log_error "Compilation tests failed"
            exit 1
        fi
        print_summary
    fi
}

main "$@"

