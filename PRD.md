# Product Requirements Document: r2d2
**Reverse, Replay, Decompile, Disassemble - Your Binary Analysis Copilot**

## Vision
*"Jarvis for binary analysis"* - Drop in a binary, get automated deep analysis, conversational exploration, and AI-guided insights. Zero ceremony, maximum clarity.

---

## Core Principles
1. **Automatic Everything**: Analysis starts on load, no manual orchestration
2. **Transparency**: Clear display of what's happening in real-time
3. **Conversational**: LLM has full context, guides exploration naturally
4. **Accessible**: Works on RPi, no JDK wrestling, minimal setup

---

## Technical Foundation

### Stack
- **Package Manager**: uv (fast, reliable)
- **Python**: 3.11+ (async support for progress, sync OpenAI calls)
- **LLM**: OpenAI API (GPT-4o for code understanding)
- **Containers**: Docker multi-arch (arm64/amd64 for RPi deployments)

### Analysis Engines
```python
# Priority order for operations
1. radare2 → Fast initial analysis, disassembly, CFG
2. Capstone → Detailed instruction analysis
3. Ghidra → Decompilation (headless, automated)
4. angr → On-demand symbolic execution
5. libmagic → File identification
```

### Design Inspiration: OFRAK
- **Unified Resource Model**: Everything is a resource (binary → sections → functions → instructions)
- **Automated Unpacking**: Recursive descent through binary structure
- **Modifier Pattern**: Analysis passes that augment the resource tree
- **GUI Optional**: Rich terminal UI, web UI is future work

---

## Architecture

```
┌──────────────────────────────────────────────┐
│              r2d2 CLI/REPL                   │
├──────────────────────────────────────────────┤
│          Conversational Interface            │
│  - Natural language queries to LLM           │
│  - Context: full analysis artifacts          │
├──────────────────────────────────────────────┤
│         Analysis Orchestrator                │
│  ┌────────────┬─────────────┬─────────────┐ │
│  │ Quick Scan │ Deep Dive   │ On-Demand   │ │
│  │ <2s        │ <30s        │ As needed   │ │
│  ├────────────┼─────────────┼─────────────┤ │
│  │ • Magic    │ • r2 full   │ • Symbolic  │ │
│  │ • Strings  │ • Decompile │ • Diff      │ │
│  │ • Headers  │ • CFG       │ • Patch     │ │
│  │ • Imports  │ • X-refs    │             │ │
│  └────────────┴─────────────┴─────────────┘ │
├──────────────────────────────────────────────┤
│           Resource Tree (OFRAK-style)        │
│   Binary → Segments → Sections → Functions  │
│           → Basic Blocks → Instructions      │
├──────────────────────────────────────────────┤
│              Backend Adapters                │
│   radare2 | Ghidra | angr | Capstone        │
└──────────────────────────────────────────────┘
```

---

## User Flow

### 1. **Initial Drop**
```bash
$ r2d2 suspicious_elf

[*] r2d2 v0.1.0 - Binary Analysis Copilot
[*] Loading: suspicious_elf (4.2 MB)

[▓▓▓▓░░░░░░] Quick Scan (0.8s)
  ✓ ELF 64-bit ARM executable
  ✓ Stripped, dynamically linked
  ✓ 247 strings extracted
  ✓ 18 imported functions (libc, libssl)

[▓▓▓▓▓▓▓▓░░] Deep Analysis (12.3s)
  ✓ 143 functions identified
  ✓ Control flow graphs generated
  ✓ Decompilation complete (Ghidra)
  ✓ Cross-references mapped
  ✓ 3 suspicious patterns detected ⚠️

[✓] Analysis complete! Context loaded into AI.

r2d2> _
```

### 2. **Conversational Exploration**
```
r2d2> what does this binary do?

Analyzing main function and entry points...

This appears to be a backdoor with the following capabilities:
1. Establishes encrypted C2 channel (TLS 1.3) to hardcoded IP
2. Accepts commands: shell execution, file exfiltration, persistence
3. Anti-debugging checks at 0x4018a0 (ptrace detection)
4. XOR-obfuscated strings (key: 0x42)

Key functions:
- setup_c2() @ 0x401200 - Network initialization
- cmd_dispatch() @ 0x401890 - Command handler
- persist() @ 0x402100 - Cron job creation

Would you like me to explain any specific function?

r2d2> explain setup_c2

[Fetching decompiled code...]

<shows decompiled C code with inline commentary>

r2d2> find all crypto operations

Scanning for crypto patterns...

Found 4 cryptographic operations:
1. AES-256-CBC @ 0x403200 (OpenSSL EVP_*)
2. SHA256 hashing @ 0x403890
3. RSA key exchange @ 0x404100
4. Custom XOR @ 0x401450 (string deobfuscation)

r2d2> can you trace execution from main to the network call?

<generates call graph with critical path highlighted>
```

---

## Core Features

### Automatic Analysis Pipeline
```python
class AnalysisPipeline:
    phases = [
        # Quick Scan (<2s)
        PhaseOne([
            MagicIdentifier(),
            StringExtractor(),
            HeaderParser(),
            ImportAnalyzer(),
        ]),
        
        # Deep Dive (<30s)
        PhaseTwo([
            RadareAnalyzer(),      # Auto-analysis, CFG
            GhidraDecompiler(),    # Headless batch mode
            XrefMapper(),
            PatternDetector(),     # Known malware/vuln patterns
        ]),
        
        # Context Assembly for LLM
        PhaseThree([
            ArtifactSerializer(),  # JSON context dump
            EmbeddingGenerator(),  # For semantic search (optional)
        ]),
    ]
```

### LLM Context Management
```python
# Artifacts fed to OpenAI
context = {
    "binary_info": {...},
    "functions": [
        {"name": "main", "addr": "0x401000", 
         "decompiled": "...", "asm": "...", "cfg": "..."},
    ],
    "strings": [...],
    "imports": [...],
    "patterns": [...],
    "xrefs": {...},
}

# Smart truncation for token limits
# Priority: user-requested function > suspicious > main > other
```

### Terminal UI (Rich/Textual)
```
┌─ r2d2: suspicious_elf ───────────────────────────────────────┐
│ Binary: ELF 64-bit ARM, 4.2 MB, stripped                     │
│ SHA256: a3f5...                                              │
├──────────────────────────────────────────────────────────────┤
│ [Functions] [Strings] [Imports] [Graph] [Chat]              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  143 Functions                         ⚠️  3 Suspicious     │
│  ├─ main              0x401000         ├─ anti_debug        │
│  ├─ setup_c2          0x401200         ├─ obfuscated_str   │
│  ├─ cmd_dispatch      0x401890         └─ raw_socket       │
│  └─ ...                                                      │
│                                                              │
├──────────────────────────────────────────────────────────────┤
│ > explain setup_c2                                           │
│                                                              │
│ [AI] This function initializes the command and control...   │
└──────────────────────────────────────────────────────────────┘
```

---

## Docker Setup (RPi Focus)

### Multi-arch Build
```dockerfile
FROM python:3.11-slim as base
ARG TARGETARCH

# Install system deps (radare2, ghidra, etc)
RUN apt-get update && apt-get install -y \
    radare2 openjdk-17-jre-headless wget unzip \
    && rm -rf /var/lib/apt/lists/*

# Ghidra (auto-download correct arch)
RUN wget -O ghidra.zip "https://github.com/NationalSecurityAgency/ghidra/releases/..." \
    && unzip ghidra.zip -d /opt && rm ghidra.zip

# Python dependencies via uv
COPY pyproject.toml uv.lock ./
RUN pip install uv && uv sync --frozen

COPY . /app
WORKDIR /app

ENTRYPOINT ["uv", "run", "r2d2"]
```

### Resource Limits for RPi
```yaml
# docker-compose.yml for training labs
version: '3.8'
services:
  r2d2:
    image: r2d2:latest
    mem_limit: 2g        # RPi 4 has 4-8GB
    cpus: 2
    volumes:
      - ./samples:/samples
      - ./output:/output
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
```

---

## CLI Commands

```bash
# Basic usage
r2d2 <binary>                    # Auto-analyze + REPL
r2d2 <binary> --batch            # Non-interactive, JSON output
r2d2 <binary> --quick            # Skip deep analysis

# Direct queries
r2d2 <binary> --ask "what does this do?"
r2d2 <binary> --function main --decompile
r2d2 <binary> --strings --filter "http"

# Export
r2d2 <binary> --export report.md
r2d2 <binary> --export-json analysis.json

# Advanced
r2d2 <binary> --trace-to 0x401890
r2d2 <binary> --diff <other_binary>
r2d2 <binary> --patch <modifications.json>
```

---

## Configuration

```toml
# ~/.config/r2d2/config.toml
[llm]
provider = "openai"
model = "gpt-4o"
api_key_env = "OPENAI_API_KEY"
max_tokens = 4096
temperature = 0.1

[analysis]
auto_analyze = true
max_binary_size = "5MB"
timeout_quick = 5
timeout_deep = 60
enable_angr = false  # Heavy, opt-in

[output]
format = "terminal"  # terminal, markdown, json
verbosity = "normal"  # quiet, normal, verbose
save_artifacts = true
artifacts_dir = "~/.cache/r2d2"

[performance]
parallel_functions = 4  # Ghidra decompilation threads
cache_results = true
```

---

## Performance Targets (5MB Binary)

| Phase | Target | RPi 4 | M2 Mac |
|-------|--------|-------|--------|
| Quick Scan | <2s | 1.8s | 0.5s |
| Deep Analysis | <30s | 28s | 8s |
| Decompile (100 funcs) | <20s | 18s | 5s |
| LLM Response | <3s | 2.5s | 2s |
| Total (cold start) | <35s | 32s | 11s |

---

## MVP Roadmap

### v0.1 (Week 1-2)
- [ ] Core binary loading (ELF parser, libmagic)
- [ ] radare2 integration (r2pipe)
- [ ] Basic string/import extraction
- [ ] OpenAI integration (sync calls)
- [ ] Simple CLI with progress display

### v0.2 (Week 3-4)
- [ ] Ghidra headless integration
- [ ] Resource tree model (OFRAK-inspired)
- [ ] Rich terminal UI
- [ ] Context assembly for LLM
- [ ] Conversational REPL

### v0.3 (Week 5-6)
- [ ] Docker multi-arch build
- [ ] Pattern detection (malware signatures)
- [ ] Cross-reference analysis
- [ ] Export capabilities (markdown, JSON)
- [ ] RPi testing and optimization

### v0.4+
- [ ] angr symbolic execution (opt-in)
- [ ] Binary diffing
- [ ] Plugin system
- [ ] Web UI (optional)

---

## Open Questions

1. **LLM Costs**: Training environment with 20 students × 10 binaries/day. Budget for OpenAI API? Consider caching strategies?

2. **Offline Mode**: RPi labs might have limited internet. Bundle lightweight local model (Phi-3, Qwen) as fallback?

3. **Collaboration**: Multi-user analysis sessions? Shared artifacts/notes?

4. **Ghidra Licensing**: Headless mode in classroom setting - need verification?

5. **Progress Streaming**: Show real-time Ghidra decompilation progress, or just spinner?

6. **Artifact Storage**: Local cache vs. project-based? How to handle re-analysis?

7. **Security**: Sandboxing for malware samples? Run analysis in isolated containers by default?

Ready to start building! Which component should we tackle first - the analysis orchestrator, radare2 integration, or the CLI framework?