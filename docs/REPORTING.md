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
- `graphs`: analysis and investigation graph payloads
- `journey`: messages and trajectory action summaries
- `context`: compact Markdown used for local model context
- `report_markdown`: deterministic human-readable report text

## CI Coverage

The Flask integration test
`tests/integration/test_api.py::TestChatsEndpoint::test_chat_bundle_exports_json_and_markdown`
builds a synthetic analysis attachment and verifies both JSON and Markdown
bundle exports. Release workflows should run this test before publishing.
