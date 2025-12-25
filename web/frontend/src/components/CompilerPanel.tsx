import React, { useState, useCallback, useEffect, useMemo } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  TextField,
  Collapse,
  IconButton,
  Alert,
  CircularProgress,
  Chip,
  Tooltip,
  Divider,
  SelectChangeEvent,
  Switch,
  FormControlLabel,
  Tab,
  Tabs,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import DownloadIcon from '@mui/icons-material/Download';
import CodeIcon from '@mui/icons-material/Code';
import BugReportIcon from '@mui/icons-material/BugReport';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import CodeEditor, { AsmViewer } from './CodeEditor';

const API_BASE = '';

// Freestanding examples that work without libc
const HELLO_EXAMPLE = `// ARM64 Hello World - Freestanding (no libc)
// Uses direct syscalls to write and exit

static const char msg[] = "Hello from ARM64!\\n";

void _start(void) {
    // syscall: write(1, msg, sizeof(msg)-1)
    register long x0 __asm__("x0") = 1;           // fd = stdout
    register long x1 __asm__("x1") = (long)msg;   // buf
    register long x2 __asm__("x2") = sizeof(msg) - 1;
    register long x8 __asm__("x8") = 64;          // __NR_write
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x1), "r"(x2), "r"(x8));
    
    // syscall: exit(0)
    x0 = 0;
    x8 = 93;  // __NR_exit
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x8));
    __builtin_unreachable();
}
`;

const FIBONACCI_EXAMPLE = `// Fibonacci - Freestanding
// Demonstrates recursion in ARM assembly

int fib(int n) {
    if (n <= 1) return n;
    return fib(n - 1) + fib(n - 2);
}

int fib_iter(int n) {
    if (n <= 1) return n;
    int a = 0, b = 1;
    for (int i = 2; i <= n; i++) {
        int tmp = a + b;
        a = b;
        b = tmp;
    }
    return b;
}

void _start(void) {
    volatile int result = fib(10);      // 55
    volatile int result2 = fib_iter(10);
    
    register long x0 __asm__("x0") = result;
    register long x8 __asm__("x8") = 93;
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x8));
    __builtin_unreachable();
}
`;

const LOOP_EXAMPLE = `// Loop Patterns - Shows ARM branching
// Good for learning cmp, b.lt, b.ne, etc.

int sum_to_n(int n) {
    int sum = 0;
    for (int i = 1; i <= n; i++) {
        sum += i;
    }
    return sum;
}

int countdown(int n) {
    int count = 0;
    while (n > 0) {
        count++;
        n--;
    }
    return count;
}

int array_sum(int* arr, int len) {
    int sum = 0;
    for (int i = 0; i < len; i++) {
        sum += arr[i];
    }
    return sum;
}

void _start(void) {
    volatile int s = sum_to_n(10);   // 55
    volatile int c = countdown(5);    // 5
    
    int data[] = {1, 2, 3, 4, 5};
    volatile int a = array_sum(data, 5); // 15
    
    register long x0 __asm__("x0") = s + c + a;
    register long x8 __asm__("x8") = 93;
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x8));
    __builtin_unreachable();
}
`;

const MEMORY_EXAMPLE = `// Memory Operations - Structs & Pointers
// Shows ldr, str, stack usage

struct Point {
    int x;
    int y;
};

void swap(int* a, int* b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

void init_point(struct Point* p, int x, int y) {
    p->x = x;
    p->y = y;
}

int manhattan(struct Point* a, struct Point* b) {
    int dx = a->x - b->x;
    int dy = a->y - b->y;
    if (dx < 0) dx = -dx;
    if (dy < 0) dy = -dy;
    return dx + dy;
}

void _start(void) {
    struct Point p1, p2;
    init_point(&p1, 3, 4);
    init_point(&p2, 0, 0);
    
    volatile int dist = manhattan(&p1, &p2); // 7
    
    int a = 10, b = 20;
    swap(&a, &b);
    
    register long x0 __asm__("x0") = dist + a;
    register long x8 __asm__("x8") = 93;
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x8));
    __builtin_unreachable();
}
`;

interface CompileResult {
  success: boolean;
  stdout: string;
  stderr: string;
  command: string;
  return_code: number;
  architecture: string;
  compiler: string;
  output_path?: string;
  output_name?: string;
  assembly?: string;
  asm_path?: string;
  asm_name?: string;
}

interface CompilerInfo {
  name: string;
  path: string;
  version: string;
  is_clang: boolean;
}

interface CompilersResponse {
  compilers: Record<string, CompilerInfo[]>;
  available_architectures: string[];
  docker_available?: boolean;
  docker_image_exists?: boolean;
  error?: string;
}

interface CommandPreview {
  command: string;
  uses_docker: boolean;
  compiler: string;
  available: boolean;
  docker_running?: boolean;
  image_exists?: boolean;
}

interface CompilerPanelProps {
  onBinaryCompiled?: (path: string, filename: string) => void;
}

// Tooltip descriptions for each option
const TOOLTIPS = {
  architecture: {
    arm32: 'ARM 32-bit (armhf) - Common in embedded systems, Raspberry Pi 1/Zero, older Android',
    arm64: 'ARM 64-bit (aarch64) - Modern ARM: Apple Silicon (via Docker), RPi 4, newer Android',
  },
  optimization: {
    '-O0': 'No optimization. Best for learning - assembly closely matches source code',
    '-O1': 'Basic optimization. Some code reordering, simple inlining',
    '-O2': 'Standard optimization. Loop unrolling, more inlining, common subexpression elimination',
    '-O3': 'Aggressive optimization. May make assembly harder to read but fastest execution',
    '-Os': 'Optimize for size. Useful for embedded systems with limited memory',
  },
  freestanding: `Freestanding mode compiles without the C standard library (libc).
Required for bare-metal code that runs without an OS.
Adds: -ffreestanding -nostdlib -static
Entry point must be _start instead of main.`,
  outputName: 'Name of the compiled binary (without extension). Defaults to "output".',
};

export default function CompilerPanel({ onBinaryCompiled }: CompilerPanelProps) {
  const [expanded, setExpanded] = useState(false);
  const [code, setCode] = useState(HELLO_EXAMPLE);
  const [architecture, setArchitecture] = useState<'arm32' | 'arm64'>('arm64');
  const [optimization, setOptimization] = useState('-O0');
  const [outputName, setOutputName] = useState('');
  const [freestanding, setFreestanding] = useState(true);
  const [compiling, setCompiling] = useState(false);
  const [result, setResult] = useState<CompileResult | null>(null);
  const [availableArchs, setAvailableArchs] = useState<string[]>([]);
  const [compilerInfo, setCompilerInfo] = useState<Record<string, CompilerInfo[]>>({});
  const [dockerAvailable, setDockerAvailable] = useState(false);
  const [dockerImageExists, setDockerImageExists] = useState(false);
  const [outputTab, setOutputTab] = useState<'asm' | 'errors'>('asm');
  const [commandPreview, setCommandPreview] = useState<CommandPreview | null>(null);

  // Fetch available compilers on mount
  useEffect(() => {
    fetch(`${API_BASE}/api/compilers`)
      .then((res) => res.json())
      .then((data: CompilersResponse) => {
        setAvailableArchs(data.available_architectures || []);
        setCompilerInfo(data.compilers || {});
        setDockerAvailable(data.docker_available ?? false);
        setDockerImageExists(data.docker_image_exists ?? false);
      })
      .catch(() => {
        setAvailableArchs([]);
      });
  }, []);

  // Fetch command preview when options change
  useEffect(() => {
    const fetchPreview = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/compilers/preview`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            architecture,
            optimization,
            freestanding,
            output_name: outputName || 'output',
          }),
        });
        const data: CommandPreview = await response.json();
        setCommandPreview(data);
      } catch {
        setCommandPreview(null);
      }
    };
    fetchPreview();
  }, [architecture, optimization, freestanding, outputName]);

  const handleCompile = useCallback(async () => {
    setCompiling(true);
    setResult(null);

    try {
      const response = await fetch(`${API_BASE}/api/compile`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source: code,
          architecture,
          optimization,
          type: 'c',
          output_name: outputName || undefined,
          freestanding,
          emit_asm: true,
        }),
      });

      const data: CompileResult = await response.json();
      setResult(data);
      
      // Auto-switch to errors tab if failed, asm tab if success
      setOutputTab(data.success && data.assembly ? 'asm' : 'errors');

      if (data.success && data.output_path && data.output_name && onBinaryCompiled) {
        onBinaryCompiled(data.output_path, data.output_name);
      }
    } catch (error) {
      setResult({
        success: false,
        stdout: '',
        stderr: error instanceof Error ? error.message : 'Compilation failed',
        command: '',
        return_code: -1,
        architecture,
        compiler: 'unknown',
      });
      setOutputTab('errors');
    } finally {
      setCompiling(false);
    }
  }, [code, architecture, optimization, outputName, freestanding, onBinaryCompiled]);

  const handleDownloadBinary = useCallback(() => {
    if (result?.output_name) {
      window.open(`${API_BASE}/api/compile/download/${result.output_name}`, '_blank');
    }
  }, [result]);

  const handleDownloadAsm = useCallback(() => {
    if (result?.asm_name) {
      window.open(`${API_BASE}/api/compile/download/${result.asm_name}`, '_blank');
    } else if (result?.assembly) {
      const blob = new Blob([result.assembly], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'output.s';
      a.click();
      URL.revokeObjectURL(url);
    }
  }, [result]);

  const loadExample = useCallback((example: 'hello' | 'fibonacci' | 'loop' | 'memory') => {
    const examples: Record<string, string> = {
      hello: HELLO_EXAMPLE,
      fibonacci: FIBONACCI_EXAMPLE,
      loop: LOOP_EXAMPLE,
      memory: MEMORY_EXAMPLE,
    };
    setCode(examples[example]);
    setFreestanding(true);
    setArchitecture('arm64');
  }, []);

  const currentCompiler = compilerInfo[architecture]?.[0];
  const isDockerCompiler = currentCompiler?.name?.startsWith('docker:') || 
    (commandPreview?.uses_docker ?? false);
  
  // Determine compile button tooltip
  const compileButtonTooltip = useMemo(() => {
    if (!commandPreview) return 'Loading...';
    if (!commandPreview.available) {
      if (commandPreview.uses_docker) {
        if (!dockerAvailable) {
          return 'Docker is not running. Start Docker Desktop to enable ARM compilation.';
        }
        if (!dockerImageExists) {
          return 'Docker image not found. Run: docker build -t r2d2-compiler -f Dockerfile.compiler .';
        }
      }
      return 'No compiler available for this architecture';
    }
    return `Command: ${commandPreview.command}`;
  }, [commandPreview, dockerAvailable, dockerImageExists]);

  // Docker status chip
  const dockerStatusChip = useMemo(() => {
    if (isDockerCompiler || (architecture.startsWith('arm') && !currentCompiler)) {
      if (!dockerAvailable) {
        return <Chip size="small" label="Docker offline" color="error" variant="outlined" />;
      }
      if (!dockerImageExists) {
        return <Chip size="small" label="Image missing" color="warning" variant="outlined" />;
      }
      return <Chip size="small" label="Docker" color="info" variant="outlined" />;
    }
    if (currentCompiler) {
      return <Chip size="small" label="Native" color="success" variant="outlined" />;
    }
    return <Chip size="small" label="No compiler" color="warning" variant="outlined" />;
  }, [architecture, currentCompiler, dockerAvailable, dockerImageExists, isDockerCompiler]);

  return (
    <Paper
      elevation={2}
      sx={{
        mb: 2,
        overflow: 'hidden',
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: 2,
      }}
    >
      {/* Header */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          px: 2,
          py: 1.5,
          bgcolor: expanded ? 'action.selected' : 'background.paper',
          cursor: 'pointer',
          '&:hover': { bgcolor: 'action.hover' },
        }}
        onClick={() => setExpanded(!expanded)}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <CodeIcon color="primary" />
          <Typography variant="subtitle1" fontWeight={600}>
            ARM Compiler
          </Typography>
          {dockerStatusChip}
        </Box>
        <IconButton size="small" onClick={(e) => { e.stopPropagation(); setExpanded(!expanded); }}>
          {expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        </IconButton>
      </Box>

      <Collapse in={expanded}>
        <Divider />
        <Box sx={{ p: 2 }}>
          {/* Toolbar */}
          <Box sx={{ display: 'flex', gap: 2, mb: 2, flexWrap: 'wrap', alignItems: 'center' }}>
            <Tooltip title={TOOLTIPS.architecture[architecture]} arrow placement="top">
              <FormControl size="small" sx={{ minWidth: 160 }}>
                <InputLabel>Architecture</InputLabel>
                <Select
                  value={architecture}
                  label="Architecture"
                  onChange={(e: SelectChangeEvent) =>
                    setArchitecture(e.target.value as 'arm32' | 'arm64')
                  }
                >
                  <MenuItem value="arm32">
                    <Tooltip title={TOOLTIPS.architecture.arm32} placement="right">
                      <Box component="span">ARM32 (armhf)</Box>
                    </Tooltip>
                  </MenuItem>
                  <MenuItem value="arm64">
                    <Tooltip title={TOOLTIPS.architecture.arm64} placement="right">
                      <Box component="span">ARM64 (aarch64)</Box>
                    </Tooltip>
                  </MenuItem>
                </Select>
              </FormControl>
            </Tooltip>

            <Tooltip 
              title={TOOLTIPS.optimization[optimization as keyof typeof TOOLTIPS.optimization]} 
              arrow 
              placement="top"
            >
              <FormControl size="small" sx={{ minWidth: 130 }}>
                <InputLabel>Optimization</InputLabel>
                <Select
                  value={optimization}
                  label="Optimization"
                  onChange={(e: SelectChangeEvent) => setOptimization(e.target.value)}
                >
                  <MenuItem value="-O0">-O0 (debug)</MenuItem>
                  <MenuItem value="-O1">-O1</MenuItem>
                  <MenuItem value="-O2">-O2</MenuItem>
                  <MenuItem value="-O3">-O3 (fast)</MenuItem>
                  <MenuItem value="-Os">-Os (size)</MenuItem>
                </Select>
              </FormControl>
            </Tooltip>

            <Tooltip title={TOOLTIPS.outputName} arrow placement="top">
              <TextField
                size="small"
                label="Output name"
                placeholder="output"
                value={outputName}
                onChange={(e) => setOutputName(e.target.value)}
                sx={{ width: 120 }}
              />
            </Tooltip>

            <Tooltip title={TOOLTIPS.freestanding} arrow placement="top">
              <FormControlLabel
                control={
                  <Switch
                    size="small"
                    checked={freestanding}
                    onChange={(e) => setFreestanding(e.target.checked)}
                  />
                }
                label={
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                    <Typography variant="caption" color="text.secondary">
                      Freestanding
                    </Typography>
                    <InfoOutlinedIcon sx={{ fontSize: 14, color: 'text.disabled' }} />
                  </Box>
                }
              />
            </Tooltip>

            <Box sx={{ flexGrow: 1 }} />

            {/* Example buttons */}
            <Box sx={{ display: 'flex', gap: 0.5 }}>
              <Tooltip title="Hello World using ARM syscalls - great starting point">
                <Button size="small" variant="text" onClick={() => loadExample('hello')}>
                  Hello
                </Button>
              </Tooltip>
              <Tooltip title="Recursive & iterative Fibonacci - see function calls in assembly">
                <Button size="small" variant="text" onClick={() => loadExample('fibonacci')}>
                  Fib
                </Button>
              </Tooltip>
              <Tooltip title="Loop patterns - learn cmp, b.lt, b.ne branching">
                <Button size="small" variant="text" onClick={() => loadExample('loop')}>
                  Loops
                </Button>
              </Tooltip>
              <Tooltip title="Structs & pointers - see ldr/str memory operations">
                <Button size="small" variant="text" onClick={() => loadExample('memory')}>
                  Memory
                </Button>
              </Tooltip>
            </Box>
          </Box>

          {/* CodeMirror Editor */}
          <Box sx={{ mb: 2 }}>
            <CodeEditor
              value={code}
              onChange={setCode}
              language="c"
              height={350}
            />
          </Box>

          {/* Actions */}
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', mb: 2 }}>
            <Tooltip 
              title={
                <Box sx={{ maxWidth: 400 }}>
                  <Typography variant="caption" component="div" sx={{ fontFamily: 'monospace', mb: 1 }}>
                    {commandPreview?.command || 'Loading...'}
                  </Typography>
                  {commandPreview?.uses_docker && (
                    <Typography variant="caption" color="info.light">
                      🐳 Uses Docker container for ARM cross-compilation
                    </Typography>
                  )}
                  {commandPreview && !commandPreview.available && (
                    <Typography variant="caption" color="error.light">
                      ⚠️ {!dockerAvailable ? 'Docker not running' : 'Docker image not built'}
                    </Typography>
                  )}
                </Box>
              } 
              arrow 
              placement="top"
            >
              <span>
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={compiling ? <CircularProgress size={18} /> : <PlayArrowIcon />}
                  onClick={handleCompile}
                  disabled={compiling || !code.trim() || (commandPreview ? !commandPreview.available : false)}
                >
                  {compiling ? 'Compiling...' : 'Compile'}
                </Button>
              </span>
            </Tooltip>

            {result?.success && result.output_name && (
              <Tooltip title="Download the compiled ELF binary">
                <Button
                  variant="outlined"
                  color="success"
                  startIcon={<DownloadIcon />}
                  onClick={handleDownloadBinary}
                >
                  Binary (.elf)
                </Button>
              </Tooltip>
            )}

            {result?.assembly && (
              <Tooltip title="Download the generated assembly source">
                <Button
                  variant="outlined"
                  color="info"
                  startIcon={<DownloadIcon />}
                  onClick={handleDownloadAsm}
                >
                  Assembly (.s)
                </Button>
              </Tooltip>
            )}

            {result?.success && result.output_path && onBinaryCompiled && (
              <Tooltip title="Open this binary in the r2d2 analyzer">
                <Button
                  variant="outlined"
                  color="secondary"
                  startIcon={<BugReportIcon />}
                  onClick={() => onBinaryCompiled(result.output_path!, result.output_name!)}
                >
                  Analyze
                </Button>
              </Tooltip>
            )}

            <Box sx={{ flexGrow: 1 }} />

            {/* Compiler info */}
            <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
              {commandPreview?.uses_docker ? '🐳 Docker' : currentCompiler?.name || 'none'}
            </Typography>
          </Box>

          {/* Output area */}
          {result && (
            <Box>
              {result.success ? (
                <Alert severity="success" sx={{ mb: 1 }}>
                  ✓ Compiled successfully! {result.output_name && `Binary: ${result.output_name}`}
                </Alert>
              ) : (
                <Alert severity="error" sx={{ mb: 1 }}>
                  ✗ Compilation failed (exit code {result.return_code})
                </Alert>
              )}

              {/* Tabs for ASM / Errors */}
              <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 1 }}>
                <Tabs
                  value={outputTab}
                  onChange={(_, v) => setOutputTab(v)}
                  sx={{ minHeight: 36 }}
                >
                  <Tab
                    value="asm"
                    label={`Assembly${result.assembly ? ` (${result.assembly.split('\n').length} lines)` : ''}`}
                    sx={{ minHeight: 36, py: 0 }}
                    disabled={!result.assembly}
                  />
                  <Tab
                    value="errors"
                    label="Output"
                    sx={{ minHeight: 36, py: 0 }}
                  />
                </Tabs>
              </Box>

              {/* Assembly output with CodeMirror */}
              {outputTab === 'asm' && result.assembly && (
                <AsmViewer value={result.assembly} height={300} />
              )}

              {/* Compiler output */}
              {outputTab === 'errors' && (
                <Paper
                  variant="outlined"
                  sx={{
                    p: 1.5,
                    bgcolor: 'background.default',
                    maxHeight: 200,
                    overflow: 'auto',
                  }}
                >
                  <Typography
                    variant="caption"
                    component="pre"
                    sx={{
                      fontFamily: '"JetBrains Mono", monospace',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                      m: 0,
                      color: result.success ? 'text.secondary' : 'error.main',
                    }}
                  >
                    {result.stderr || result.stdout || 'No output'}
                  </Typography>
                </Paper>
              )}

              {/* Command used */}
              {result.command && (
                <Tooltip title="The exact command that was executed">
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{ 
                      display: 'block', 
                      mt: 1, 
                      fontFamily: 'monospace', 
                      fontSize: '0.7rem',
                      cursor: 'help',
                    }}
                  >
                    $ {result.command}
                  </Typography>
                </Tooltip>
              )}
            </Box>
          )}

          {/* Setup instructions if Docker not available */}
          {(!dockerAvailable || !dockerImageExists) && architecture.startsWith('arm') && (
            <Alert severity="info" sx={{ mt: 2 }}>
              <Typography variant="body2" fontWeight={500} gutterBottom>
                {!dockerAvailable ? '🐳 Docker not running' : '🐳 Docker image not found'}
              </Typography>
              {!dockerAvailable ? (
                <Typography variant="caption" component="div">
                  Start Docker Desktop to enable ARM cross-compilation on this machine.
                </Typography>
              ) : (
                <>
                  <Typography variant="caption" component="div">
                    Build the Docker image for ARM compilation:
                  </Typography>
                  <Typography
                    component="pre"
                    variant="caption"
                    sx={{ fontFamily: 'monospace', mt: 0.5, mb: 1, bgcolor: 'action.hover', p: 1, borderRadius: 1 }}
                  >
                    docker build -t r2d2-compiler -f Dockerfile.compiler .
                  </Typography>
                </>
              )}
            </Alert>
          )}
        </Box>
      </Collapse>
    </Paper>
  );
}
