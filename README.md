# r2d2

Binary analysis copilot that pairs fast local tooling with LLM insights. Drop in an ELF, stream structured results, replay the trajectory later.

## Why r2d2?
- **Fast first impressions**: quick scan via libmagic + radare2 in seconds.
- **Deep automation**: headless Ghidra pipeline ready for scripted decompilation.
- **Explainable**: captures every action in SQLite so you can replay or diff runs.
- **Conversational**: optional OpenAI hook keeps a full context bundle for follow-up questions (defaults to `gpt-5-mini-2025-08-07`).
- **Portable**: uv-managed Python 3.11 environment, optional extras only when you ask for them.

## Repository layout
- `src/r2d2/` – Python package with CLI, orchestrator, adapters, storage, utilities.
- `config/default_config.toml` – baseline settings (LLM, analysis, cache, Ghidra).
- `scripts/` – setup, diagnostics, dry-run recipes, Ghidra bootstrap helper.
- `ghidra/extensions/r2d2/` – Gradle project + scripts for a minimal R2D2 headless extension.
- `PRD.md` – product requirements source of truth.

## Quick start
```bash
# 1. Install uv once (https://github.com/astral-sh/uv)
# 2. Bootstrap the workspace
scripts/setup.sh

# 3. Check your environment (JSON output saved to .dry_run_env.json)
scripts/dry_run.sh

# 3b. Verify web + LLM wiring
uv run scripts/check_setup.py

# 4. Run an analysis (quick mode)
uv run r2d2 path/to/binary --quick

# 5. Ask the LLM for a summary (uses OpenAI's `gpt-5-mini-2025-08-07` model by default)
env OPENAI_API_KEY=... uv run r2d2 path/to/binary --ask "what does this do?"
```
> **Tip:** place a sample binary at `./sample.bin` to let `scripts/dry_run.sh` exercise the pipeline automatically.

## Commands
- `r2d2 <binary>` – full pipeline (quick + deep)
- `r2d2 <binary> --quick` – skip deep stage (no Ghidra/angr)
- `r2d2 <binary> --json` – emit JSON payload
- `r2d2 <binary> --ask "question"` – run analysis then ask the LLM
- `r2d2 env` – environment diagnostics, including dependency status and Ghidra readiness
- `r2d2 trajectories` – list persisted analysis runs (requires SQLite enabled)

## Core flow
1. **Config** – `config/default_config.toml` merged with `~/.config/r2d2/config.toml`.
2. **Environment check** – verifies uv, radare2, libmagic, Ghidra, optional angr.
3. **Quick scan** – libmagic + radare2 metadata + strings.
4. **Deep scan** – radare2 analysis, optional capstone disassembly, Ghidra headless command bundle (dry-run by default).
5. **Storage** – trajectory + actions persisted to SQLite (optional).
6. **LLM** – on demand, uses OpenAI Chat Completions with structured summary context.

## Ghidra integration
- Gradle project at `ghidra/extensions/r2d2` packaging a minimal headless analyzer.
- `scripts/bootstrap_ghidra_extension.sh` builds the extension and exports `r2d2.zip` ready for drop-in.
- CLI deep stage returns the exact `analyzeHeadless` command so you can dry-run or execute.
- Optional `ghidra_bridge` support: enable by setting `ghidra.use_bridge = true` and installing the `ghidra` extra via uv.

## Storage & replay
- SQLite database path configurable via `[storage]` settings.
- `TrajectoryDAO` records ordered actions (`libmagic.quick`, `radare2.deep`, `ghidra.deep`, ...).
- Future replay tooling can iterate actions from the DB and reapply against similar binaries.

## Web UI
- Start the Flask backend: `uv run r2d2-web`
- Install frontend deps: `cd web/frontend && npm install`
- Dev mode: `npm run dev` (Vite proxies `/api` to the Flask server)
- Production build: `npm run build` then reload `r2d2-web` to serve `web/frontend/dist`
- The dashboard streams adapter progress with Server-Sent Events and renders quick/deep payloads once ready.

## Next steps
- Flesh out adapters with richer parsing + error handling (radare2 JSON, Ghidra artifact ingestion).
- Add textual terminal UI using the `tui` extra (Textual).
- Extend trajectory schema to capture diffable artifacts and caching metadata.
- Integrate angr selectively (per function) once performance budgets are profiled.
