# Agents & Roles

Overview of autonomous components inside r2d2 and how they cooperate to deliver analysis + LLM conversations.

> **Note**: r2d2 is designed as a production service for learning ARM reverse engineering. All components prioritize beginner-friendly explanations while maintaining technical depth.

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
| Ghidra | `r2d2.adapters.ghidra` | decompilation, types | headless (subprocess) or bridge (RPC) modes |
| angr | `r2d2.adapters.angr` | symbolic execution | enabled by default; heavy but fallbacks gracefully |
| DWARF | `r2d2.adapters.dwarf` | debug symbol parsing | extracts source-level type info from binaries |
| Frida | `r2d2.adapters.frida` | dynamic instrumentation | runtime memory/module inspection |
| GEF | `r2d2.adapters.gef` | execution tracing | Docker-isolated GDB with register snapshots |

Adapters raise `AdapterUnavailable` when prerequisites are missing to keep the orchestrator composable.

### Ghidra Integration Details
The Ghidra adapter supports two modes:

1. **Headless Mode** (default): Runs `analyzeHeadless` subprocess with `R2D2Headless.java` script that outputs JSON containing functions, strings, and decompiled code. Auto-copies script to `~/ghidra_scripts/`.

2. **Bridge Mode** (richer data): Connects to running Ghidra GUI via `ghidra_bridge` RPC. Provides real-time access to decompilation, types, and cross-references.

> ⚠️ **Note**: PyGhidra 3.0.2 has a recursion bug with Python 3.11 in `_GhidraBundleFinder.find_spec()`. r2d2 uses subprocess-based headless mode which works correctly.

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
- **Role**: orchestrates Anthropic Claude (primary) with OpenAI fallback for chat/summarize workloads.
- **Context Management**:
  - Full analysis context (binary info, disassembly, functions) is included in every LLM message
  - Last 15 conversation exchanges are maintained for continuity
  - User goals (e.g., "find C2 callbacks") are persisted and included in system prompt
- **Invocation**: CLI `--ask` option, web chat endpoint (`POST /api/chats/<id>/messages`), auto-analysis on upload, and "Ask Claude" from disassembly selection.
- **ARM Specialization**: When ARM binaries are detected, prompts emphasize ARM instruction explanation and reference official docs.
- **Extensibility**: add providers by implementing `chat/summarize_analysis` (see `openai_client.py`, `claude_client.py`) and wiring via config.

## Annotation Agent
- **Storage**: SQLite via `annotations` table, synced with chat sessions
- **Frontend**: `DisassemblyViewer` component with drag-select and inline annotation popover
- **API Endpoints**:
  - `GET /api/chats/<session_id>/annotations` - list annotations
  - `POST /api/chats/<session_id>/annotations` - create/update annotation
  - `DELETE /api/chats/<session_id>/annotations/<address>` - delete annotation
- **Persistence**: Annotations are saved to both localStorage (client backup) and SQLite (portable/sync)
- **Integration**: Selected code + annotations can be sent directly to Claude for explanation

## CFG Viewer Agent
- **Module**: `web/frontend/src/components/CFGViewer.tsx`
- **Data Sources**: 
  - angr CFG nodes/edges (symbolic execution)
  - radare2 function CFGs with block-level disassembly
- **Debug Features**: When CFG data is missing, displays diagnostic checklist:
  - angr installation status
  - Analysis mode (full vs quick)
  - Binary validity
  - Node/edge/function counts
- **Navigation**: OFRAK-style function list → block navigation → inline disassembly

## ARM Compiler Agent
- **Backend Module**: `r2d2.compilation.compiler`
- **Frontend Module**: `web/frontend/src/components/CompilerPanel.tsx`
- **Capabilities**:
  - Cross-compile C to ARM32/ARM64 via Docker container
  - Auto-detect freestanding (`_start`) vs libc-linked (`main`) code
  - Generate both ELF binary and assembly source
  - Godbolt-style assembly viewer with syntax highlighting
- **Docker Image**: `r2d2-compiler:latest` (built from `Dockerfile.compiler`)
- **Compiler Flags**:
  - Freestanding: `-ffreestanding -nostartfiles -nodefaultlibs -static`
  - Libc (musl): `-static -specs=/musl/<arch>.specs`
- **Example Templates**: Hello World, Fibonacci, Loops, Memory operations
- **Download Artifacts**: Binary and `.s` assembly files downloadable from UI

## ARM Instruction Documentation
- **Reference**: [ARM Developer DUI0489](https://developer.arm.com/documentation/dui0489/h/arm-and-thumb-instructions/instruction-summary)
- **Implementation**: `DisassemblyViewer` provides hover tooltips for ARM32/64 and x86 instructions
- **Coverage**: 100+ instructions with descriptions (MOV, LDR, BL, PUSH, etc.)
- **Fallback**: Search link to ARM Developer site for unknown instructions

## Session Manager
- **Frontend Module**: `web/frontend/src/components/SessionList.tsx` + `App.tsx`
- **Backend**: `r2d2.storage.chat.ChatDAO`
- **Features**:
  - Create new sessions via "+" button in sidebar
  - Switch between active sessions (each linked to a binary)
  - Delete sessions when no longer needed
  - Auto-sync annotations and chat history across sessions
- **Persistence**: All sessions stored in SQLite with full message history

## Future Agents (placeholders)
- Pattern detector pipeline (`r2d2.analysis.pipelines`) for signature-based hints and heuristics.
- UI agent (Textual) to provide event-loop-driven workspace for interactive triage.
- Replay agent that applies saved trajectories to new binaries and reports divergences.
- Recompilation agent for patching and rebuilding binaries.
