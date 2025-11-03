# Agents & Roles

Overview of autonomous components inside r2d2 and how they cooperate to deliver analysis + LLM conversations.

## Analyzer Orchestrator (Python)
- **Entry point**: `r2d2.analysis.orchestrator.AnalysisOrchestrator`
- **Inputs**: file path, analysis plan, environment report, trajectory DAO
- **Responsibilities**:
  - enforce ELF-only analyses (magic header guard) before dispatching any adapter
  - assemble adapter registry (`libmagic`, `radare2`, `capstone`, eager `angr`, optional `ghidra`)
  - execute quick/deep stages, record outputs + issues, and attach results to chat sessions
  - maintain OFRAK-style resource tree for downstream use
  - log every action to the trajectory store (`TrajectoryDAO`)
- **Outputs**: `AnalysisResult` bundle (resource tree, quick/deep payloads, notes, issues)

## Adapter Agents
Each adapter provides a uniform interface (`AnalyzerAdapter` protocol) and can be swapped / extended.

| Adapter | Module | Capability | Notes |
|---------|--------|------------|-------|
| Libmagic | `r2d2.adapters.libmagic` | file identification | minimal dependencies, sanity check |
| Radare2 | `r2d2.adapters.radare2` | metadata, CFG, functions | multi-arch baseline (x86_64/arm64/armv7) via `radare2` + `r2pipe` |
| Capstone | `r2d2.adapters.capstone` | first-chunk disassembly | derives architecture from radare2 quick scan |
| Ghidra | `r2d2.adapters.ghidra` | headless decompilation | opt-in (disabled by default), uses extension scripts |
| angr | `r2d2.adapters.angr` | symbolic execution | enabled by default; heavy but fallbacks gracefully |

Adapters raise `AdapterUnavailable` when prerequisites are missing to keep the orchestrator composable.

## Environment Sentinel
- **Module**: `r2d2.environment.detectors`
- **Purpose**: gather telemetry about installed tools before running expensive stages.
- **Outputs**: `EnvironmentReport` consumed by CLI + orchestrator, plus dedicated Ghidra detection payload.
- **Extensibility**: `_COMMANDS` now includes optional `qemu`/`frida` probes and the detector inspects Anthropic availability when LLM fallback is enabled.

## Trajectory Recorder
- **Storage**: SQLite via `r2d2.storage.Database` and `TrajectoryDAO`
- **Schema**: `trajectories` table + `trajectory_actions` child rows (JSON payload)
- **Usage**:
  - `AnalysisOrchestrator` calls `append_action` after each stage.
  - Replay scripts can iterate actions to reproduce or diff analyses on new binaries.

## Chat Companion (SQLite)
- **Module**: `r2d2.storage.chat` (`ChatDAO`)
- **Purpose**: persist chat sessions keyed by binary/trajectory, attach structured analysis snapshots, and archive LLM answers.
- **Workflow**:
  - Sessions are created/upserted when an analysis job starts.
  - System message with the serialized `AnalysisResult` is appended on completion (attachments tagged `analysis_result`).
  - Web UI/API append user prompts and LLM responses (metadata tracks active provider: OpenAI → Claude fallback).
- **Downstream**: transcripts power replay, progress reports, and LLM context rebuilding.

## LLM Companion
- **Module**: `r2d2.llm.manager.LLMBridge`
- **Role**: orchestrates OpenAI (primary) with Anthropic Claude fallback for chat/summarize workloads.
- **Invocation**: CLI `--ask` option, web chat endpoint (`POST /api/chats/<id>/messages`), and post-analysis summarizers.
- **Extensibility**: add providers by implementing `chat/summarize_analysis` (see `openai_client.py`, `claude_client.py`) and wiring via config.

## Future Agents (placeholders)
- Pattern detector pipeline (`r2d2.analysis.pipelines`) for signature-based hints and heuristics.
- UI agent (Textual) to provide event-loop-driven workspace for interactive triage.
- Replay agent that applies saved trajectories to new binaries and reports divergences.
