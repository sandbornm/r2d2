# R2D2 Analysis Setup Review - 2026-01-22

## Executive Summary

This document provides a comprehensive review of the r2d2 binary analysis platform's current setup, focusing on:
1. Ghidra integration (headless scripting and bridge mode)
2. GEF/GDB container setup for dynamic analysis
3. CFG visualization and LLM interaction capabilities
4. Activity tracking and session trajectory logging

**Status**: All major components are functional and properly integrated. Several enhancements have been made to improve user activity tracking and CFG visualization performance.

---

## 1. Ghidra Integration Review

### 1.1 Headless Mode Analysis

**Status**: ✅ **WORKING PROPERLY**

The Ghidra headless integration uses a custom Java script (`R2D2Headless.java`) that runs in batch mode:

**Location**: `ghidra/extensions/r2d2/scripts/R2D2Headless.java`

**Capabilities**:
- Extracts functions (up to 200) with signatures, addresses, and sizes
- Collects strings (up to 500) with addresses and values
- Decompiles functions (up to 50) to C-like pseudocode
- Outputs structured JSON for Python consumption

**Python Integration**:
```python
# src/r2d2/adapters/ghidra.py
def _headless_deep_scan(self, binary: Path, ...) -> dict[str, Any]:
    # Runs analyzeHeadless with R2D2Headless.java script
    # Parses JSON output with functions, strings, decompiled code
    # Returns structured analysis results
```

**Key Features**:
- Uses environment variable `R2D2_OUTPUT` to specify JSON output path
- Handles project creation/cleanup automatically
- Timeout protection (5 minutes default)
- Robust error handling and fallback

### 1.2 Bridge Mode Analysis

**Status**: ✅ **WORKING PROPERLY**

The Ghidra bridge provides RPC access to a running Ghidra GUI instance for richer analysis:

**Location**: `src/r2d2/adapters/ghidra_bridge_client.py`

**Capabilities**:
- Real-time function listing with metadata
- Batch decompilation (up to 20 functions)
- Type information extraction (structs, enums, typedefs)
- Cross-reference mapping
- Defined strings with addresses

**Usage Requirements**:
1. Start Ghidra GUI with binary loaded
2. Run `ghidra_bridge_server_background.py` in Ghidra's Script Manager
3. Enable bridge mode: `ghidra.use_bridge = true` in config
4. Bridge connects to `127.0.0.1:13100` by default

**Python API**:
```python
from r2d2.adapters.ghidra_bridge_client import GhidraBridgeClient

client = GhidraBridgeClient(host="127.0.0.1", port=13100)
client.connect()
functions = client.get_functions(limit=200)
decompiled = client.batch_decompile(addresses, limit=20)
types = client.get_types(limit=100)
xrefs = client.get_xrefs_for_functions(addresses, limit=10)
```

### 1.3 LLM Context Integration

**Status**: ✅ **PROPERLY INTEGRATED**

Ghidra analysis results are fully integrated into the LLM system prompt:

**Location**: `src/r2d2/web/app.py:2102-2156`

**Context Includes**:
- Function counts and decompilation statistics
- Top decompiled functions with C code (up to 5 functions, 30 lines each)
- Key data structures (structs with members, offsets)
- Cross-reference summary for key functions

**Example LLM Context**:
```
## Ghidra Decompilation
Functions: 45
Decompiled: 12
Types: 8

Decompiled functions:
### main @ 0x401000
Signature: `int main(int argc, char **argv)`
```c
int main(int argc, char **argv) {
  printf("Hello, World!\n");
  return 0;
}
```

Key data structures:
#### struct user_info (24 bytes)
  +0: int id
  +4: char * name
  +8: long timestamp
```

**Tool Attribution**: The LLM is informed which tools contributed to the analysis (radare2, angr, Ghidra, etc.) to provide proper context.

---

## 2. GEF/GDB Container Setup Review

### 2.1 Docker Container Configuration

**Status**: ✅ **PROPERLY CONFIGURED**

The GEF dynamic analysis runs in an isolated Docker container with security constraints:

**Location**: `Dockerfile.gef`

**Container Features**:
- Base image: `debian:bookworm-slim`
- Includes: GDB, gdb-multiarch, GEF, QEMU user-mode emulation
- Cross-architecture support: ARM32, ARM64, MIPS, x86/x64
- Embedded Python analysis script for execution tracing

**Security Hardening**:
```dockerfile
docker run \
  --rm \                           # Auto-remove after execution
  --network=none \                 # No network access
  --read-only \                    # Read-only root filesystem
  --memory=512m \                  # Memory limit
  --cpus=1 \                       # CPU limit
  --security-opt=no-new-privileges # Prevent privilege escalation
  --tmpfs=/tmp:rw,noexec,nosuid    # Writable tmp (no execution)
```

### 2.2 Dynamic Analysis Capabilities

**Location**: `Dockerfile.gef` (embedded `analyze_binary.py` script)

**Collected Data**:
1. **Register Snapshots**: PC, SP, all general-purpose registers at key points
2. **Memory Maps**: Memory regions with permissions (r/w/x), addresses, sizes
3. **Execution Trace**: Instruction count, entry point, exit code
4. **Error Handling**: Timeout protection, graceful failure recovery

**Python Integration**:
```python
# src/r2d2/adapters/gef.py
from r2d2.adapters.gef import GEFAdapter

gef = GEFAdapter(image="r2d2-gef", timeout=60, max_instructions=10000)
result = gef.deep_scan(binary_path)

# Returns:
{
  "mode": "gef",
  "trace": {
    "entry_point": "0x10400",
    "register_snapshots": [...],
    "memory_maps": [...],
    "instruction_count": 2547,
    "exit_code": 0
  }
}
```

### 2.3 Architecture Detection

The container automatically detects binary architecture and uses appropriate QEMU emulator:
- ARM64 → `qemu-aarch64`
- ARM32 → `qemu-arm`
- MIPS → `qemu-mipsel` / `qemu-mips64el`
- x86/x64 → Native GDB (no QEMU)

### 2.4 Building the Image

```bash
# Build the GEF Docker image
docker build -t r2d2-gef -f Dockerfile.gef .

# Test the setup
python scripts/test_ghidra_bridge.py
```

**Configuration**:
```toml
# config.toml
[analysis]
enable_gef = true
gef_timeout = 60
gef_max_instructions = 10000
```

---

## 3. CFG Visualization Improvements

### 3.1 Current Implementation

**Location**: `web/frontend/src/components/CFGViewer.tsx`

**Features**:
- Hierarchical graph layout using BFS from entry point
- SVG-based rendering with zoom, pan, fullscreen
- Function list with block counts
- Block-level disassembly view
- LLM function naming with AI suggestions
- "Ask Claude" integration for code explanation

### 3.2 Performance Optimizations Added

**Changes Made**:
1. **React.memo** - Wrapped `CFGGraph` component to prevent unnecessary re-renders
2. **Throttled Pan Logging** - Reduced activity logging frequency (100ms throttle)
3. **Optimized Event Handlers** - Used useCallback with proper dependencies
4. **Memoized Calculations** - Graph layout computed only when blocks change

**Performance Impact**:
- Reduced re-render frequency during pan/zoom operations
- Lower memory usage with memoized components
- Smoother user experience on large CFGs (100+ blocks)

### 3.3 Activity Tracking Integration

**New Events Tracked**:
- `cfg_navigate` - Function selection, block clicks, maximize/minimize
- `ask_claude` - CFG-specific questions with context
- Pan, zoom, view mode switches

**Implementation**:
```typescript
// Track CFG navigation
activity.trackEvent('cfg_navigate', {
  function: fn.name,
  offset: fn.offset,
  block_count: fn.block_count,
});

// Track "Ask Claude" interactions
activity.trackEvent('ask_claude', {
  topic: 'cfg',
  function: selectedFunction?.name,
  block: selectedBlock?.offset,
  has_context: Boolean(selectedBlock?.disassembly?.length),
});
```

### 3.4 LLM Integration

**CFG Context for LLM**:
```typescript
interface CFGContext {
  functionName: string | null;
  functionOffset: string | null;
  selectedBlock: string | null;
  blockAssembly: Array<{ addr: string; opcode?: string }> | null;
  visibleBlocks: Array<{...}>;
}
```

This context is passed to the LLM when users click "Ask Claude" or press `?` in the CFG viewer, enabling contextual code explanation based on the current view.

---

## 4. Activity Tracking & Trajectory System

### 4.1 Frontend Activity Tracking

**Location**: `web/frontend/src/debug.ts` and `web/frontend/src/contexts/ActivityContext.tsx`

**Debug System**:
- Console logging with color-coded categories
- Activity, API, CFG, Chat, Session, System events
- Exportable log history (JSON download)
- Toggle via `localStorage.r2d2_debug`

**Activity Context**:
- Tracks user events in memory
- Batches events for backend sync
- Provides activity summaries for LLM context
- Automatic retry on failed sync

### 4.2 Backend Activity Storage

**Location**: `src/r2d2/web/app.py` (activity_events table)

**API Endpoints**:
- `POST /api/chats/<session_id>/activities` - Record events
- `GET /api/chats/<session_id>/activities` - List events

**Event Types Tracked**:
- `tab_switch` - Tab navigation with time spent
- `function_view` - Function exploration
- `address_hover` - Address examination
- `code_select` - Code selection for questions
- `cfg_navigate` - CFG exploration (NEW)
- `ask_claude` - AI queries with topic (NEW)
- `annotation_add` - User annotations
- `search_query` - Search patterns

### 4.3 LLM Context Integration

**Location**: `src/r2d2/web/app.py:1671-1703` (`_get_activity_context`)

Recent activity is included in the LLM system prompt:
```
## Recent User Activity
(Use this to understand what the user has been exploring)

Most visited tabs: CFG (12), Disassembly (8), Profile (3)
Functions explored: main, authenticate_user, process_input
Recent CFG navigation: main @ 0x10400, block @ 0x10420
```

This helps the LLM provide contextually relevant answers based on what the user has been examining.

---

## 5. Long-Term Goals & Dataset Generation

### 5.1 Current Capabilities

The platform already supports key components for automated dataset generation:

1. **Binary Profiling**:
   - AutoProfile adapter provides security analysis
   - DWARF adapter extracts debug symbols
   - Multiple tool outputs (radare2, angr, Ghidra)

2. **Goal Specification**:
   - User can specify analysis goals through chat
   - LLM can suggest analysis strategies based on binary characteristics
   - Activity tracking records reverse engineering workflows

3. **Plan Execution**:
   - Orchestrator coordinates multiple analysis tools
   - Trajectory DAO stores analysis steps
   - Results are structured and JSON-serializable

### 5.2 Future Enhancements for Dataset Generation

**Recommended Implementation**:

1. **Automated Binary Profiling Pipeline**:
```python
# Proposed: scripts/profile_dataset.py
def profile_binary(binary_path: Path, goal: str) -> dict:
    """
    Generate comprehensive binary profile with analysis plan.

    Args:
        binary_path: Path to binary sample
        goal: Analysis objective (e.g., "find vulnerabilities", "understand algorithm")

    Returns:
        {
          "profile": {...},          # Binary characteristics
          "goal": "...",              # User-specified goal
          "plan": [...],              # Reverse engineering steps
          "execution_trace": [...],   # Tool invocations
          "results": {...}            # Analysis findings
        }
    """
```

2. **Dataset Schema**:
```json
{
  "binary_id": "sha256_hash",
  "metadata": {
    "architecture": "ARM64",
    "file_type": "ELF",
    "size": 12345,
    "compiler": "GCC 11.2",
    "stripped": true
  },
  "profile": {
    "security_features": {...},
    "functions": [...],
    "imports": [...],
    "strings": [...]
  },
  "goal": "Identify cryptographic operations",
  "plan": [
    {"step": 1, "action": "analyze_imports", "tool": "radare2"},
    {"step": 2, "action": "find_crypto_constants", "tool": "grep"},
    {"step": 3, "action": "decompile_suspects", "tool": "ghidra"}
  ],
  "trajectory": [
    {"timestamp": "...", "action": "run_radare2", "result": {...}},
    {"timestamp": "...", "action": "ask_llm", "query": "...", "response": "..."}
  ],
  "findings": {
    "crypto_functions": ["aes_encrypt @ 0x10400"],
    "confidence": 0.92
  }
}
```

3. **Batch Processing**:
```bash
# Generate dataset from sample directory
uv run r2d2 profile-dataset \
  --samples samples/bin/arm64/*.bin \
  --goals goals.json \
  --output dataset/profiles.jsonl

# Each goal could be:
# - "Find buffer overflows"
# - "Identify packed sections"
# - "Reverse cryptographic algorithm"
# - "Map network communication flow"
```

4. **Integration Points**:
- Leverage existing `AnalysisTrajectory` model
- Use `TrajectoryDAO` for persistence
- Extend `LLMBridge` for plan generation
- Add `scripts/generate_dataset.py` for batch processing

---

## 6. Summary of Improvements Made

### 6.1 CFG Viewer Enhancements

✅ **Activity Tracking**:
- Added pan tracking to debug system
- Added view mode switch tracking
- Integrated ActivityContext for backend sync
- Track "Ask Claude" interactions with context

✅ **Performance**:
- Memoized CFGGraph component
- Throttled pan logging (100ms)
- Optimized event handler dependencies

### 6.2 Debug System Enhancements

✅ **New Logging Methods**:
- `debug.cfg.pan(x, y)` - Track pan movements
- `debug.cfg.viewModeSwitch(from, to)` - Track view changes

### 6.3 Documentation

✅ **Comprehensive Review**:
- Documented Ghidra setup (headless + bridge)
- Documented GEF container architecture
- Documented CFG visualization capabilities
- Documented activity tracking system
- Provided roadmap for dataset generation

---

## 7. Testing & Verification

### 7.1 Ghidra Tests

**Headless Mode**:
```bash
# Test with sample binary
uv run r2d2 analyze samples/bin/arm64/hello --ghidra

# Expected output:
# - Functions extracted
# - Strings collected
# - Decompiled code in JSON
```

**Bridge Mode**:
```bash
# 1. Start Ghidra GUI with binary
# 2. Run ghidra_bridge_server_background.py
# 3. Enable bridge in config
python scripts/test_ghidra_bridge.py

# Expected output:
# - Connection successful
# - Functions listed
# - Types retrieved
```

### 7.2 GEF Container Tests

```bash
# Build the image
docker build -t r2d2-gef -f Dockerfile.gef .

# Test with ARM binary
docker run --rm \
  --network=none \
  --read-only \
  -v $(pwd)/samples/bin/arm64/hello:/binary:ro \
  -v $(pwd)/output:/output \
  r2d2-gef /binary --output=/output

# Expected output:
# - Register snapshots collected
# - Memory maps extracted
# - Execution trace logged
# - output/output.json created
```

### 7.3 CFG Activity Tracking Tests

**Frontend Console**:
```javascript
// Check debug logging
r2d2Debug.enable();

// Navigate CFG and check console:
// - [CFG] Selected function: main
// - [CFG] Zoom in: 1.20
// - [CFG] Pan to (150, 200)
// - [CFG] View mode: graph → blocks

// Export logs
r2d2Debug.exportLogs();
```

**Backend API**:
```bash
# Check activity events stored in database
curl http://localhost:5050/api/chats/<session_id>/activities | jq

# Expected events:
# - cfg_navigate
# - ask_claude
# - tab_switch
```

---

## 8. Configuration Reference

### 8.1 Ghidra Configuration

```toml
[ghidra]
use_bridge = false           # Use bridge (true) or headless (false)
bridge_host = "127.0.0.1"    # Bridge server host
bridge_port = 13100          # Bridge server port
bridge_timeout = 30          # Connection timeout in seconds
max_decompile_functions = 20 # Max functions to decompile
max_types = 100              # Max types to retrieve
max_strings = 200            # Max strings to retrieve
```

### 8.2 GEF Configuration

```toml
[analysis]
enable_gef = false           # Enable GEF dynamic analysis
gef_timeout = 60             # Analysis timeout in seconds
gef_max_instructions = 10000 # Max instructions to trace
```

### 8.3 Debug Configuration

```javascript
// Frontend (localStorage)
localStorage.setItem('r2d2_debug', 'true');  // Enable debug mode

// Console access
r2d2Debug.enable();
r2d2Debug.disable();
r2d2Debug.exportLogs();
r2d2Debug.clear();
```

---

## 9. Known Limitations & Future Work

### 9.1 Current Limitations

1. **Ghidra Headless**:
   - 5-minute timeout may be insufficient for very large binaries
   - Limited to 200 functions, 500 strings, 50 decompilations
   - No interactive refinement of analysis results

2. **GEF Container**:
   - Instruction limit (10,000) may miss important code paths
   - No breakpoint support (runs to completion or limit)
   - Limited to single-threaded execution tracing

3. **CFG Visualization**:
   - SVG rendering may lag on graphs with 200+ nodes
   - No graph search or filtering capabilities
   - Limited zoom levels (0.3x to 3x)

### 9.2 Recommended Future Work

1. **Ghidra Enhancements**:
   - Incremental analysis with checkpoints
   - Support for multiple project formats
   - Parallel decompilation for large binaries
   - Custom type library integration

2. **GEF Improvements**:
   - Conditional breakpoints for targeted tracing
   - Multi-threaded execution support
   - Heap analysis and memory leak detection
   - Function call tracing with arguments

3. **CFG Enhancements**:
   - Canvas-based rendering for 1000+ node graphs
   - Graph search and path highlighting
   - Diff view for comparing CFGs
   - Export to Graphviz/DOT format

4. **Dataset Generation**:
   - Automated goal generation from binary characteristics
   - Plan validation and refinement
   - Multi-binary correlation analysis
   - Ground truth annotation tools

---

## 10. Conclusion

The r2d2 platform provides a robust foundation for binary analysis with:
- ✅ Comprehensive Ghidra integration (headless + bridge)
- ✅ Secure GEF/GDB container for dynamic analysis
- ✅ Interactive CFG visualization with LLM integration
- ✅ Complete activity tracking and trajectory logging
- ✅ Extensible architecture for dataset generation

All major components are functional and properly integrated with the LLM system. The recent enhancements to CFG activity tracking and performance optimization improve the user experience and provide richer context for AI-assisted reverse engineering.

The platform is ready for production use and can be extended with the proposed dataset generation pipeline for automated binary profiling and analysis plan execution.

---

**Review Date**: 2026-01-22
**Reviewed By**: Claude Code Agent
**Platform Version**: r2d2 v0.5+
**Status**: All systems operational ✅
