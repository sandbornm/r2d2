# CLAUDE.md - Development Guide for r2d2

This document provides essential context for AI assistants and developers working on the r2d2 codebase.

## Project Overview

**r2d2** is a binary analysis copilot for learning ARM reverse engineering with AI. It combines fast local reverse engineering tools (radare2, angr, Capstone, Ghidra) with Claude-powered AI insights through a web interface and CLI.

## Quick Commands

```bash
# Setup
scripts/setup.sh                    # Full setup (backend + frontend)
uv sync --extra analyzers           # Install Python deps with analyzers

# Development
uv run r2d2-web                     # Start Flask backend on :5050
cd web/frontend && npm run dev      # Start Vite frontend on :5173

# Testing
uv run pytest                       # Run Python unit tests
uv run pytest tests/unit/           # Run only unit tests
uv run pytest tests/integration/    # Run integration tests
cd web/frontend && npm test         # Run frontend tests

# Linting & Type Checking
uv run ruff check src/              # Lint Python code
uv run mypy src/                    # Type check Python code
cd web/frontend && npm run lint     # Lint frontend code

# CLI Usage
uv run r2d2 analyze sample.bin --quick      # Quick analysis
uv run r2d2 analyze sample.bin              # Full analysis
uv run r2d2 env                             # Environment diagnostics

# Compilation (for ARM samples)
uv run r2d2 compile samples/c/hello.c --arch arm   # Compile C to ARM
```

## Architecture

### Backend (Python 3.11+, uv-managed)

```
src/r2d2/
├── cli.py                 # Typer CLI entry point
├── config.py              # Pydantic configuration management
├── state.py               # Application state container
├── adapters/              # Analysis tool adapters
│   ├── base.py            # AdapterRegistry and base classes
│   ├── radare2.py         # Primary disassembly (r2pipe)
│   ├── angr.py            # Symbolic execution & CFG
│   ├── capstone.py        # Instruction-level disassembly
│   ├── libmagic.py        # File type identification
│   └── ghidra.py          # Headless decompilation
├── analysis/
│   ├── orchestrator.py    # Multi-stage analysis pipeline
│   └── resource_tree.py   # OFRAK-inspired binary hierarchy
├── compilation/           # Assembly recompilation
│   └── compiler.py        # GCC/Clang wrapper for ARM
├── llm/                   # LLM integration
│   ├── manager.py         # LLMBridge (multi-provider)
│   ├── claude_client.py   # Anthropic SDK wrapper
│   └── openai_client.py   # OpenAI fallback
├── storage/               # SQLite persistence
│   ├── db.py              # Database management
│   ├── models.py          # Domain models
│   ├── dao.py             # Trajectory DAO
│   └── chat.py            # Chat session DAO
└── web/
    ├── app.py             # Flask REST API
    └── server.py          # WSGI server
```

### Frontend (React 18 + TypeScript, Vite)

```
web/frontend/src/
├── App.tsx                # Main application shell with tabs: Results, Chat, Compiler, Logs
├── components/
│   ├── CFGViewer.tsx      # Control flow graph visualization (angr + radare2)
│   ├── CodeEditor.tsx     # C code editor + AsmViewer with syntax highlighting
│   ├── CompilerPanel.tsx  # ARM cross-compiler UI with examples
│   ├── DisassemblyViewer.tsx  # Annotatable disassembly with tooltips
│   ├── ChatPanel.tsx      # AI conversation interface
│   ├── ProgressLog.tsx    # Real-time analysis events (SSE)
│   ├── ResultViewer.tsx   # Analysis results with tabbed view
│   ├── SessionList.tsx    # Session sidebar with new/delete
│   └── SettingsDrawer.tsx # Configuration UI
├── types.ts               # TypeScript interfaces
└── theme.ts               # MUI theme configuration
```

## Key Patterns

### Adapter Pattern
Each analysis tool is wrapped in an adapter implementing:
- `is_available() -> bool` - Check if tool is installed
- `quick_scan(binary) -> dict` - Fast metadata extraction
- `deep_scan(binary) -> dict` - Full analysis

### Resource Tree (OFRAK-inspired)
Binaries are represented as hierarchical resources:
```
BinaryResource
├── FunctionResource (offset, size, blocks)
└── FunctionResource
    └── InstructionResource (address, bytes, mnemonic)
```

### Decompilation Uncertainty
When both radare2 and angr provide analysis, uncertainty is calculated:
- High confidence: Both tools agree on structure
- Medium confidence: Minor differences in block boundaries
- Low confidence: Significant structural disagreement

## Testing Strategy

### Unit Tests (`tests/unit/`)
- Test individual adapters with mocked binaries
- Test resource tree construction
- Test configuration loading
- Run with: `uv run pytest tests/unit/ -v`

### Integration Tests (`tests/integration/`)
- Test full analysis pipeline with real binaries
- Test web API endpoints
- Test compilation workflow
- Run with: `uv run pytest tests/integration/ -v`

### Frontend Tests
- Component tests with Vitest + React Testing Library
- Run with: `cd web/frontend && npm test`

## Adding New Features

### New Adapter
1. Create `src/r2d2/adapters/new_tool.py`
2. Implement `is_available()`, `quick_scan()`, `deep_scan()`
3. Register in `AdapterRegistry` in orchestrator
4. Add tests in `tests/unit/test_adapters.py`

### New API Endpoint
1. Add route in `src/r2d2/web/app.py`
2. Add TypeScript types in `web/frontend/src/types.ts`
3. Add frontend integration tests

### Key API Endpoints
- `POST /api/analyze` - Run analysis on a binary (supports `quick_only`, `enable_angr` flags)
- `POST /api/compile` - Compile C code to ARM binary (uses Docker cross-compiler)
- `GET /api/compile/download/<filename>` - Download compiled binary or assembly
- `POST /api/chats/<id>/messages` - Send a message to Claude about the binary
- `GET /api/chats/<id>/annotations` - List annotations for a session

### New UI Component
1. Create in `web/frontend/src/components/`
2. Add to appropriate parent component
3. Add component tests with Vitest

## Configuration

### Environment Variables
```bash
ANTHROPIC_API_KEY=sk-ant-...   # Claude API key
OPENAI_API_KEY=sk-...          # OpenAI fallback
R2D2_WEB_HOST=127.0.0.1        # Flask host
R2D2_WEB_PORT=5050             # Flask port
GHIDRA_INSTALL_DIR=/opt/ghidra # Ghidra path (optional)
```

### Config Files
- `config/default_config.toml` - Default settings
- `~/.config/r2d2/config.toml` - User overrides

## Sample Binaries

Test ARM binaries are in `samples/`:
```
samples/
├── c/                     # C source files
│   ├── hello.c           # Basic hello world
│   ├── fibonacci.c       # Recursive algorithm
│   ├── syscalls.c        # Direct syscall examples
│   └── vulnerable.c      # Stack overflow demo
└── bin/                   # Compiled ARM binaries
    ├── arm32/            # ARM32 (Thumb) binaries
    └── arm64/            # ARM64 binaries
```

To compile new samples:
```bash
# ARM32
arm-linux-gnueabihf-gcc -o samples/bin/arm32/hello samples/c/hello.c

# ARM64
aarch64-linux-gnu-gcc -o samples/bin/arm64/hello samples/c/hello.c
```

## Common Issues

### radare2 not found
```bash
# macOS
brew install radare2

# Ubuntu/Debian
sudo apt-get install radare2
```

### angr import errors
```bash
uv sync --extra analyzers
```

### Frontend proxy errors
Ensure backend is running on :5050 before starting frontend.

### Ghidra timeouts
Set longer timeout in config: `analysis.ghidra_timeout = 120`

## Code Style

- Python: Ruff for linting, mypy for type checking
- TypeScript: ESLint + Prettier
- Line length: 100 characters
- Use type hints everywhere in Python
- Prefer explicit imports over wildcards
