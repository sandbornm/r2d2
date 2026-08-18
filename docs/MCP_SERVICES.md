# MCP Services

Optional. angr on `:8770` is the only MCP this lab runs. Ghidra decompile is
**headless 11.2**, not the GhidraMCP plugin.

r2d2 expects these services on explicit local ports so the CLI and UI can
probe them before dispatch. Defaults avoid `5000` and `5001`.

## Default Endpoints

| Service | Endpoint | Purpose |
| --- | --- | --- |
| GhidraMCP plugin API | `http://127.0.0.1:8080` | Static Ghidra HTTP API exposed by the Ghidra plugin |
| GhidraMCP GDB API | `http://127.0.0.1:5051` | Docker-backed dynamic analysis, GDB, GEF, Frida, angr helpers |
| angr MCP | `http://127.0.0.1:8770/mcp` | Streamable HTTP MCP server for angr entry/CFG analysis |

## Start Services

From the r2d2 checkout, the default sibling-repo layout is:

```text
../GhidraMCP
../angr_mcp
```

Start the angr MCP streamable HTTP service:

```bash
cd ../angr_mcp
uv run angr-mcp-dev-server --transport streamable-http --host 127.0.0.1 --port 8770
```

Start the GhidraMCP GDB/Docker API:

```bash
cd ../GhidraMCP/docker
docker compose up -d --build
```

Start the GhidraMCP plugin API by opening Ghidra, enabling the GhidraMCP
plugin, loading a target program, and confirming the plugin HTTP server is
listening on `127.0.0.1:8080`.

## Check From r2d2

```bash
uv run r2d2 mcp
uv run r2d2 mcp --json
uv run r2d2 env
```

The dashboard uses `/api/tools/status` (cached). Do not poll `?live=1` on
the single-thread Flask server.

## Launch From r2d2

The same config can be used to start services that provide `start_command`
metadata:

```bash
uv run r2d2 mcp-start --dry-run
uv run r2d2 mcp-start --service angr_mcp
uv run r2d2 mcp-start --service ghidra_gdb
uv run r2d2 mcp-start --json --dry-run
```

`angr_mcp` starts as a background process and writes logs under
`~/.local/state/r2d2/mcp` by default. `ghidra_gdb` runs the configured Docker
Compose command. `ghidra_mcp` is reported as skipped because the plugin API must
be started from inside Ghidra after loading a program.

The dashboard tool status bar exposes the same launcher for unavailable MCP
services with configured `start_command` metadata.

## Reconfigure

Override the defaults in `config/default_config.toml` or a custom config file
under the `[mcp.*]` sections. Each service supports `url`, `fallback_urls`,
`command`, `args`, `start_command`, `working_dir`, and `install_hint` fields.
