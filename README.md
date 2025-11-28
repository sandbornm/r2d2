# r2d2

Binary analysis copilot that pairs fast local tooling with LLM insights. Drop in an ELF, stream structured results, replay the trajectory later.

## Why r2d2?
- **Multi-arch first**: radare2, capstone, and angr power both quick and deep stages across x86_64, arm64 (Apple M2, Raspberry Pi), and armv7.
- **Explainable automation**: every adapter emission is persisted to SQLite with a replayable trajectory and linked chat history.
- **LLM resilience**: OpenAI is the primary assistant with automatic Claude fallback when credentials or connectivity are missing.
- **Sleek browser cockpit**: the React dashboard exposes a complexity slider (beginner → expert), progressive UI windows, and an analysis-aware chat panel.
- **Ship-anywhere**: uv-managed Python, pinned Node build, and new Dockerfiles make local dev or container deployment painless.

## Repository layout
- `src/r2d2/` – Python package with CLI, orchestrator, adapters, storage, utilities.
- `config/default_config.toml` – baseline settings (LLM, analysis, cache, Ghidra).
- `scripts/` – unified setup (`setup.sh`) plus backend/frontend installers, diagnostics, and Ghidra bootstrap helpers.
- `ghidra/extensions/r2d2/` – Gradle project + scripts for a minimal R2D2 headless extension.
- `PRD.md` – product requirements source of truth.

## Prerequisites

Install system dependencies before running the Python setup:

```bash
# macOS (Homebrew)
brew install radare2 libmagic

# Ubuntu/Debian
sudo apt-get install radare2 libmagic-dev

# Fedora
sudo dnf install radare2 file-devel
```

## Setup
```bash
# 1. Provide LLM credentials (optional but recommended)
cp .env.example .env && $EDITOR .env

# 2. Install uv once (https://github.com/astral-sh/uv) then bootstrap
scripts/setup.sh

# 2b. Or run individual setup stages when needed
scripts/setup_backend.sh
scripts/setup_frontend.sh

# 3. Sync dependencies with uv (includes analyzer extras)
uv sync --extra analyzers

# 4. Run diagnostics (writes .dry_run_env.json)
scripts/dry_run.sh

# 5. Verify backend wiring + adapters
uv run scripts/check_setup.py

# 6. Run backend unit tests
uv run pytest -q

# 7. (Optional) Run frontend unit tests
cd web/frontend && npm test
```
> **Tip:** place a sample binary at `./sample.bin` to let `scripts/dry_run.sh` exercise the pipeline automatically.

After the checks succeed you can launch the backend with `uv run r2d2-web` and bring up the React UI via `npm run dev` inside `web/frontend` (see [Web UI](#web-ui)).

## Quick start
```bash
# Run a quick analysis on sample.bin
uv run r2d2 analyze sample.bin --quick

# Full analysis (quick + deep stages)
uv run r2d2 analyze path/to/binary

# Emit JSON output
uv run r2d2 analyze sample.bin --quick --json

# Ask the LLM (OpenAI with Claude fallback)
uv run r2d2 analyze path/to/binary --ask "what does this do?"

# Check environment and tool availability
uv run r2d2 env
```

## Commands
- `r2d2 analyze <binary>` – full pipeline (quick + deep)
- `r2d2 analyze <binary> --quick` – skip deep stage (no Ghidra/angr)
- `r2d2 analyze <binary> --json` – emit JSON payload
- `r2d2 analyze <binary> --ask "question"` – run analysis then ask the LLM
- `r2d2 env` – environment diagnostics, including dependency status and Ghidra readiness
- `r2d2 trajectories` – list persisted analysis runs (requires SQLite enabled)

## Core flow
1. **Config** – `config/default_config.toml` merged with `~/.config/r2d2/config.toml`.
2. **Environment check** – verifies uv, radare2, libmagic, angr, optional Ghidra, qemu/frida hints.
3. **Quick scan** – libmagic + radare2 metadata + strings.
4. **Deep scan** – radare2 analysis, capstone disassembly, angr symbolic pivots; Ghidra is opt-in for headless workflows.
5. **Storage** – trajectory + actions persisted to SQLite (optional).
6. **LLM** – on demand, uses OpenAI Chat Completions with structured summary context.

## Ghidra integration
- Gradle project at `ghidra/extensions/r2d2` packaging a minimal headless analyzer.
- `scripts/bootstrap_ghidra_extension.sh` builds the extension and exports `r2d2.zip` ready for drop-in.
- CLI deep stage returns the exact `analyzeHeadless` command so you can dry-run or execute.
- Optional `ghidra_bridge` support: enable by setting `ghidra.use_bridge = true` and installing the `ghidra` extra via uv.
- The default workflow relies on radare2, capstone, and angr; enable Ghidra only when you need heavy decompilation.

## Storage & replay
- SQLite database path configurable via `[storage]` settings.
- `TrajectoryDAO` records ordered actions (`libmagic.quick`, `radare2.deep`, `angr.deep`, ...).
- `ChatDAO` mirrors every trajectory with rich message history, attachments, and LLM responses for auditability.
- Future replay tooling can iterate actions from the DB and reapply against similar binaries.

## Web UI

### Running manually (development mode)

**Terminal 1 – Backend (Flask API on :5050):**
```bash
cd /path/to/r2d2
uv run r2d2-web
```

**Terminal 2 – Frontend (Vite dev server on :5173):**
```bash
cd /path/to/r2d2/web/frontend
npm install   # first time only
npm run dev
```

Open http://localhost:5173 in your browser. Vite proxies `/api` calls to Flask at `http://127.0.0.1:5050`.

### Production bundle
```bash
cd web/frontend && npm run build
uv run r2d2-web  # serves static assets from web/frontend/dist
```
Open http://localhost:5050 directly.

Highlights:
- Complexity slider reveals progressively richer panes—from beginner summaries to expert-level CFG/function dumps.
- Chat panel keeps trajectory-aware conversation history (LLM fallback aware) with analysis snapshots attached to each run.
- Progress log now uses Material UI components with timestamps, adapter chips, and status icons.

## Containerized deployment
Multi-arch Dockerfiles are provided for back-end and front-end workloads.

```bash
# Build and start both services (backend exposes :5050, frontend :5173)
docker-compose up --build

# Tail logs
docker-compose logs -f backend
```

Backend image pulls `radare2`, `libmagic`, and installs Python dependencies via `uv`, making it compatible with amd64, arm64 (Apple Silicon), and armv7 (Raspberry Pi 4). Frontend image runs the Vite dev server; use `npm run build` + backend-only container for a slim production deployment.

## Next steps
- Flesh out adapters with richer parsing + error handling (radare2 JSON, Ghidra artifact ingestion).
- Add textual terminal UI using the `tui` extra (Textual).
- Extend trajectory schema to capture diffable artifacts and caching metadata.
- Integrate angr selectively (per function) once performance budgets are profiled.

## TODO - left off 2025-11-28

- [ ] Improve UI components
- [ ] Add discrete analysis phases
- [ ] Add task description metadata for uploaded binaries
- [ ] Add visuals with angr CFG and disassembly views
- [ ] Highlight CFG/disassembly panels to hand off questions to the AI
- [ ] Record trajectory replay (generate equivalent Python script for each run)
- [ ] Improve logging, performance, and support additional LLM providers
