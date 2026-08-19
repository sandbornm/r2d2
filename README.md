# r2d2

Professional firmware/binary triage bus. Headless first: CLI writes a tagged
record; the web UI is a viewer of the same store. The LLM (local Qwen via
OpenAI-compat, or anything else you point at) gets a sniff card + a region
ask — not an adapter dump.

## Setup

```bash
# Python 3.11+, uv, radare2, file(1)
curl -LsSf https://astral.sh/uv/install.sh | sh
sudo apt-get install -y radare2 file libmagic-dev   # or: brew install radare2 libmagic

git clone git@github.com:sandbornm/r2d2.git
cd r2d2
uv sync --extra analyzers
uv run r2d2 env
```

That is enough for sniff + firmware inventory + radare2. Optional later:

| Piece | When |
|---|---|
| Node 20 + `web/frontend` | you want the UI |
| Ghidra **11.2** at `GHIDRA_INSTALL_DIR` | decompile an ELF (`analyzeHeadless`) |
| angr MCP on `:8770` | extra CFG after you have an ELF |
| OpenAI-compat base URL | `brief --ask` / chat (Z.ai, exo, …) |

This lab keeps Ghidra 11.2. Do not upgrade to 12 unless you need the MCP plugin.

## Headless

Same config for CLI and API. Analysis publishes a **record** (SHA-256 folder)
and a **session** (`analysis_result` attachment). Do not re-upload the blob
to see it in the UI.

```bash
export R2D2_CONFIG=/path/to/config.toml   # optional overlay

uv run r2d2 env --json
uv run r2d2 analyze path/to/httpd --quick --json
uv run r2d2 analyze path/to/httpd --brief --tag httpd
uv run r2d2 brief path/to/httpd --ask --ask-regions 3
uv run r2d2 records list
uv run r2d2 records show HASH
uv run r2d2 insights --tag httpd
```

`--quick` = sniff + firmware + r2 metadata. Full analyze adds listing/CFG.
`--brief` ranks regions by **subject class** (container vs uImage vs ELF).
`--ask` sends those asks to the configured model. An ELF is not a squashfs.

### LLM keys

Never put a secret in a committed toml. The overlay **names** the env var;
the process **reads** it.

```bash
# Z.ai (international GLM) — recommended default for --ask
cp config/z.ai.example.toml config/local.toml   # gitignored
echo 'ZAI_API_KEY=...' >> .env                  # gitignored, auto-loaded
export R2D2_CONFIG="$PWD/config/local.toml"

# Official BigModel / Zhipu (China) — same client, different host
cp config/glm.example.toml config/local.toml
echo 'GLM_API_KEY=...' >> .env                  # or ZHIPUAI_API_KEY
# skip the overlay:  export GLM_API_KEY=... R2D2_LLM_PROVIDER=glm

# Local exo / llama.cpp / vLLM — no cloud key
# openai_base_url = "http://<tailscale-host>:52415/v1"
```

Never put the secret in toml. `uv run r2d2 env` shows provider / model / whether the named key is present.

Pi / SSH box: `config/headless.example.toml` turns off Ghidra, angr, GEF, and Frida. Do not run `analyzeHeadless` on a Raspberry Pi.

`analyze` / `brief` without `--ask` still run no model.

Start the API against the same config, then open the session list:

```bash
uv run r2d2-web          # :5050
# optional:
cd web/frontend && npm install && npm run dev   # :5173, proxies /api → :5050
```

Firmware lab wrapper (prefers `work/<id>/rootfs`, else inventories the blob):

```bash
python3 /path/to/tp_link_firmware/scripts/analyze_with_r2d2.py TL-WR841N_US_V14_250328 --quick --brief
```

## Interfaces

Keep these names stable. The omp Qwen pilot (`scripts/qwen_pilot.py` in the
firmware lab) shells out to the CLI verbs below and degrades a step if they
move.

### CLI

| Command | Role |
|---|---|
| `analyze BIN` | run plan, persist record, publish session |
| `brief BIN` | same, print ranked regions |
| `records list` / `records show ID` | revisit a SHA-256 record |
| `insights [--tag T]` | sibling patterns across records |
| `env [--json]` | tool + LLM key presence (JSON is pipe-safe) |
| `mcp` / `mcp-start` | probe / launch optional MCP |
| `ghidra status` / `ghidra setup` | headless Ghidra install |

Flags that matter: `--config`, `--quick`, `--json`, `--ask`, `--ask-regions`, `--tag`.

### HTTP

Flask `:5050`. Public analysis DTO is `r2d2.analysis_result.v1` (briefing +
record + sniff). Same object on SSE and `GET` attachments.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/health` | model + tool flags |
| `POST` | `/api/analyze` | `{binary, user_goal?, analysis_profile?, require_elf?}` → `{job_id, session_id}` |
| `GET` | `/api/jobs/<id>/stream` | SSE (`analysis_result`, `job_completed`) |
| `GET` | `/api/chats` | sessions |
| `GET` | `/api/chats/<id>/analysis` | latest DTO (UI Results/Map) |
| `GET` | `/api/chats/<id>/briefing` | ranked regions (`?format=markdown`) |
| `GET` | `/api/records` | record index |
| `GET` | `/api/records/<sha256>` | one record |
| `GET` | `/api/insights` | sibling notes |
| `GET` | `/api/tools/status` | do **not** use `?live=1` on the single-thread server |
| `GET` | `/api/chats/<id>/bundle` | export; see [docs/REPORTING.md](docs/REPORTING.md) |

### On disk

```
<artifacts_dir>/records/<aa>/<sha256>/
  record.json   briefing.json   commentary.md   tools/*.json   graphs/cfg/
```

Re-runs merge. Records are the source of truth; chat sessions are a view.

### LLM

OpenAI-compat `POST {base}/v1/chat/completions`. Overlay:

```toml
[llm]
provider = "openai"
model = "PocketAiHub/Qwen3.8-27B-Abliterated-MLX-4bit"
openai_base_url = "http://100.77.31.55:52415/v1"
```

Or `R2D2_LLM_PROVIDER`, `R2D2_LLM_MODEL`, `R2D2_OPENAI_BASE_URL`.

Every turn gets `## User's Goal` (if set) and `## Triage intake` from sniff
(`file`, strings, container, sinks). Ask a region, not the JSON.

### MCP (optional)

[docs/MCP_SERVICES.md](docs/MCP_SERVICES.md). angr on `127.0.0.1:8770/mcp` is
the only one we actually run. GhidraMCP plugin wants 11.3.2+; we stay on 11.2
headless. r2d2 itself is not an MCP — do not Funnel `/api/tools/execute`.

### Who calls whom

| Harness | Job |
|---|---|
| r2d2 | store, sniff, briefing, UI |
| omp | coding agent; Qwen *pilot* plans then execs this CLI |
| Grok | product work on r2d2 / the lab |

## Config

Overlays merge in order: `config/default_config.toml`, `~/.config/r2d2/config.toml`,
`config/local.toml` (gitignored), then `R2D2_CONFIG` / `--config`. Later wins.

```bash
export GHIDRA_INSTALL_DIR=/home/kali/ghidra_11.2_PUBLIC
export R2D2_CONFIG=./config/your.toml
```

Firmware lab overlay: `tp_link_firmware/config/r2d2.exo.toml` (artifacts +
SQLite under that lab's `work/r2d2-artifacts/`).

## Tests

```bash
uv run ruff check src tests
uv run pytest tests/unit tests/integration/test_api.py::TestChatsEndpoint::test_chat_bundle_exports_json_and_markdown
cd web/frontend && npm test && npm run build
```

## License

MIT.
