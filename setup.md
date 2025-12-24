# Setup Guide

End-to-end recipe for bringing r2d2 online on macOS, Linux, or Raspberry Pi (arm64).

## 0. Prerequisites
- Python 3.11 supported by [uv](https://github.com/astral-sh/uv)
- `radare2` on PATH (`brew install radare2`, `apt install radare2`, or build from source)
- `libmagic` / `file` utilities (`brew install libmagic` or `apt install libmagic`)
- Optional: `docker`, `angr` dependencies (`sudo apt install python3-dev build-essential`) for symbolic execution
- Ghidra ≥ 10.4 extracted locally; set `$GHIDRA_INSTALL_DIR`

## 1. Bootstrap the Python toolchain
```bash
# Install uv once
detect_arch=$(uname -m)
if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi

# Clone repo if you haven't already
git clone https://github.com/your-org/r2d2.git
cd r2d2

# Sync dependencies (base, analyzers, Ghidra extras)
scripts/setup.sh
```
`scripts/setup.sh` will:
- ensure Python 3.11 is available via uv
- install core dependencies + extras (`--extra analyzers`, `--extra ghidra`)
- copy `config/default_config.toml` to `~/.config/r2d2/config.toml`
- run `scripts/detect_env.py` to highlight missing tools

## 2. Configure secrets & preferences
Edit `~/.config/r2d2/config.toml` as needed:
```toml
[llm]
api_key_env = "OPENAI_API_KEY"
model = "gpt-5.1-2025-11-13"

[analysis]
# enable angr after verifying dependencies
enable_angr = false

[storage]
database_path = "~/.local/share/r2d2/r2d2.db"
```
Export your OpenAI key before running LLM commands:
```bash
export OPENAI_API_KEY="sk-..."
```

## 3. Validate the environment
```bash
uv run scripts/detect_env.py            # human readable
uv run scripts/detect_env.py --json     # structured output
uv run r2d2 env                         # rich terminal table
uv run scripts/check_setup.py           # ensures OpenAI key + web app wiring
```
Address reported issues (radare2 missing, ghidra not configured, etc.) before continuing.

## 4. Build the Ghidra extension
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
scripts/bootstrap_ghidra_extension.sh
```
The script packages `r2d2.zip` in `output/ghidra/`. Install it via Ghidra UI (`File → Install Extensions`) or drop into `${GHIDRA_INSTALL_DIR}/Ghidra/Extensions`.

Headless usage (dry-run produced by CLI):
```bash
$(uv run r2d2 /path/to/bin --json | jq -r '.deep_scan.ghidra.command | join(" ")')
```
Remove `"dry_run": true` by re-running with `dry_run=false` in the adapter or invoking the printed command manually.

## 5. Dry run
```bash
scripts/dry_run.sh
```
Outputs:
- `.dry_run_env.json` – snapshot of tool availability
- `.dry_run_analysis.json` – quick analysis payload (if `sample.bin` present)

## 6. Daily workflow
```bash
# Analyze binary
uv run r2d2 suspicious.bin

# Quick mode, JSON output, ask LLM
uv run r2d2 suspicious.bin --quick --json --ask "list persistence mechanisms"

# Review trajectories
uv run r2d2 trajectories
```

## 7. Optional components
1. **ghidra_bridge** (interactive Ghidra RPC)
   ```bash
   uv sync --extra ghidra
   # Update config:
   # [ghidra]
   # use_bridge = true
   # bridge_host = "127.0.0.1"
   # bridge_port = 13100
   ```

2. **Textual TUI** (future work)
   ```bash
   uv sync --extra tui
   ```

3. **Docker images** – integrate later; PRD outlines multi-arch target.

## 8. Web dashboard

Run backend and frontend in separate terminals:

```bash
# Terminal 1 - Backend (Flask API on :5050)
scripts/run_backend.sh

# Terminal 2 - Frontend (Vite dev server on :5173)
scripts/run_frontend.sh
```

Open http://localhost:5173 in your browser.

### Production bundle
```bash
cd web/frontend && npm run build
uv run r2d2-web  # serves static assets from web/frontend/dist
```
The Flask app auto-serves the `dist` folder when present, so a production build exposes the React UI at http://localhost:5050 without additional configuration.

## Troubleshooting
- `radare2 quick scan failed`: ensure `r2pipe` Python module is installed (`uv sync --extra analyzers`).
- `Ghidra headless script missing`: run `scripts/bootstrap_ghidra_extension.sh` and confirm `ghidra/extensions/r2d2/scripts/R2D2Headless.java` is copied into Ghidra's script directory.
- `OpenAIClient` errors: confirm `OPENAI_API_KEY` exported and network access permitted.
- `sqlite3.OperationalError`: remove the DB at `~/.local/share/r2d2/r2d2.db` if schema drift occurred; it will be recreated.
