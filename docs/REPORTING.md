# Reporting

r2d2 exports a portable analysis bundle for handoff, release artifacts, and
agent-to-agent context transfer.

## Endpoints

JSON bundle:

```bash
curl -sS http://127.0.0.1:5050/api/chats/<session_id>/bundle \
  -o r2d2-analysis-bundle.json
```

Markdown report:

```bash
curl -sS 'http://127.0.0.1:5050/api/chats/<session_id>/bundle?format=markdown' \
  -o r2d2-analysis-report.md
```

Artifact manifest:

```bash
curl -sS 'http://127.0.0.1:5050/api/chats/<session_id>/bundle?format=manifest' \
  -o r2d2-session-manifest.json
```

ZIP archive:

```bash
curl -sS 'http://127.0.0.1:5050/api/chats/<session_id>/bundle?format=zip' \
  -o r2d2-session.zip
```

Raw adapter payloads are excluded by default to keep exports light. Include them
only when you need a forensic handoff:

```bash
curl -sS 'http://127.0.0.1:5050/api/chats/<session_id>/bundle?include_raw=1' \
  -o r2d2-analysis-bundle-raw.json
```

## Schema

The JSON contract lives at
[`schemas/analysis_bundle.schema.json`](../schemas/analysis_bundle.schema.json).

The top-level schema version is:

```json
"schema_version": "r2d2.analysis_bundle.v1"
```

The bundle joins:

- `session`: chat/session metadata
- `subject`: binary and firmware summary
- `findings`: issues, notes, important graph nodes, and evidence gaps
- `tooling`: tool availability, tool status, and evidence coverage
- `tooling.tool_scorecard`: normalized per-session tool quality, speed, and coverage signals
- `graphs`: analysis and investigation graph payloads
- `journey`: messages and trajectory action summaries
- `context`: compact Markdown used for local model context
- `manifest`: deterministic export and artifact file inventory
- `report_markdown`: deterministic human-readable report text

The ZIP archive includes deterministic JSON/Markdown exports from the bundle and
packages carved firmware artifacts only when they live under r2d2's configured
artifacts directory. Original binaries are not included unless explicitly
requested with `include_binary=1`, and the same artifact allowlist is applied.

## CI Coverage

The Flask integration test
`tests/integration/test_api.py::TestChatsEndpoint::test_chat_bundle_exports_json_and_markdown`
builds a synthetic analysis attachment and verifies JSON, Markdown, manifest,
and ZIP bundle exports. Release workflows should run this test before
publishing.
