# Agents & Roles

Overview of autonomous components inside r2d2 and how they cooperate to deliver analysis + LLM conversations.

## Analyzer Orchestrator (Python)
- **Entry point**: `r2d2.analysis.orchestrator.AnalysisOrchestrator`
- **Inputs**: file path, analysis plan, environment report, trajectory DAO
- **Responsibilities**:
  - assemble adapter registry (`libmagic`, `radare2`, `capstone`, optional `ghidra`, optional `angr`)
  - execute quick scan, deep scan stages, record outputs + issues
  - maintain OFRAK-style resource tree for downstream use
  - log every action to the trajectory store (`TrajectoryDAO`)
- **Outputs**: `AnalysisResult` bundle (resource tree, quick/deep payloads, notes, issues)

## Adapter Agents
Each adapter provides a uniform interface (`AnalyzerAdapter` protocol) and can be swapped / extended.

| Adapter | Module | Capability | Notes |
|---------|--------|------------|-------|
| Libmagic | `r2d2.adapters.libmagic` | file identification | minimal dependencies, sanity check |
| Radare2 | `r2d2.adapters.radare2` | metadata, CFG, functions | requires `radare2` + `r2pipe` |
| Capstone | `r2d2.adapters.capstone` | first-chunk disassembly | needs architecture hint |
| Ghidra | `r2d2.adapters.ghidra` | headless decompilation | dry-run friendly, uses extension scripts |
| angr | `r2d2.adapters.angr` | symbolic execution | heavy optional add-on |

Adapters raise `AdapterUnavailable` when prerequisites are missing to keep the orchestrator composable.

## Environment Sentinel
- **Module**: `r2d2.environment.detectors`
- **Purpose**: gather telemetry about installed tools before running expensive stages.
- **Outputs**: `EnvironmentReport` consumed by CLI + orchestrator, plus dedicated Ghidra detection payload.
- **Extensibility**: add new checks (e.g., `qemu`, `frida`) by extending `_COMMANDS` map and optional imports.

## Trajectory Recorder
- **Storage**: SQLite via `r2d2.storage.Database` and `TrajectoryDAO`
- **Schema**: `trajectories` table + `trajectory_actions` child rows (JSON payload)
- **Usage**:
  - `AnalysisOrchestrator` calls `append_action` after each stage.
  - Replay scripts can iterate actions to reproduce or diff analyses on new binaries.

## LLM Companion
- **Module**: `r2d2.llm.openai_client`
- **Role**: transforms structured analysis results into conversational responses.
- **Invocation**: CLI `--ask` option; further automation can run `OpenAIClient.summarize_analysis()` directly.
- **Extensibility**: swap provider by implementing a sibling client (e.g., `local_client.py`) and wiring via config.

## Future Agents (placeholders)
- Pattern detector pipeline (`r2d2.analysis.pipelines`) for signature-based hints and heuristics.
- UI agent (Textual) to provide event-loop-driven workspace for interactive triage.
- Replay agent that applies saved trajectories to new binaries and reports divergences.
