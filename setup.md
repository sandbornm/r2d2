# Setup

All of this lives in [README.md](README.md). Short version:

```bash
uv sync --extra analyzers
uv run r2d2 env
uv run r2d2 analyze path/to/bin --quick --brief
```

Optional UI: `uv run r2d2-web` and `cd web/frontend && npm run dev`.

Ghidra, angr MCP, and GEF Docker are optional. See README and
[docs/MCP_SERVICES.md](docs/MCP_SERVICES.md).
