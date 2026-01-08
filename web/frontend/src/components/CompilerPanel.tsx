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
  Alert,
  CircularProgress,
  Chip,
  Tooltip,
  SelectChangeEvent,
  Switch,
  FormControlLabel,
  Stack,
} from '@mui/material';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import DownloadIcon from '@mui/icons-material/Download';
import BugReportIcon from '@mui/icons-material/BugReport';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import ChatBubbleOutlineIcon from '@mui/icons-material/ChatBubbleOutline';
import CodeIcon from '@mui/icons-material/Code';
import MemoryIcon from '@mui/icons-material/Memory';
import DataObjectIcon from '@mui/icons-material/DataObject';
import CodeEditor, { AsmViewer } from './CodeEditor';
import ListingView from './ListingView';
import PanelLayout, { PanelSelector, PanelConfig } from './PanelLayout';

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
  onAnalyzeAndChat?: (path: string, filename: string) => void;
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
Adds: -ffreestanding -nostartfiles -nodefaultlibs -static
Entry point must be _start (not main) with inline syscalls.`,
  outputName: 'Name of the compiled binary (without extension). Defaults to "output".',
};

export default function CompilerPanel({ onBinaryCompiled, onAnalyzeAndChat }: CompilerPanelProps) {
  const [code, setCode] = useState(HELLO_EXAMPLE);
  const [architecture, setArchitecture] = useState<'arm32' | 'arm64'>('arm64');
  const [optimization, setOptimization] = useState('-O0');
  const [outputName, setOutputName] = useState('');
  const [freestanding, setFreestanding] = useState(true);
  const [compiling, setCompiling] = useState(false);
  const [result, setResult] = useState<CompileResult | null>(null);
  const [, setAvailableArchs] = useState<string[]>([]);
  const [compilerInfo, setCompilerInfo] = useState<Record<string, CompilerInfo[]>>({});
  const [dockerAvailable, setDockerAvailable] = useState(false);
  const [dockerImageExists, setDockerImageExists] = useState(false);
  const [commandPreview, setCommandPreview] = useState<CommandPreview | null>(null);
  const [activePanels, setActivePanels] = useState<string[]>(['source', 'asm']);

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
      
      // Auto-show asm panel if success
      if (data.success && data.assembly) {
        setActivePanels((prev) => prev.includes('asm') ? prev : [...prev, 'asm']);
      }

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

  // Toggle panel visibility
  const handlePanelToggle = useCallback((id: string) => {
    setActivePanels((prev) =>
      prev.includes(id) ? prev.filter((p) => p !== id) : [...prev, id]
    );
  }, []);

  const handlePanelClose = useCallback((id: string) => {
    setActivePanels((prev) => prev.filter((p) => p !== id));
  }, []);

  // Panel configurations
  const panelConfigs: PanelConfig[] = useMemo(() => [
    {
      id: 'source',
      title: 'C Source',
      icon: <CodeIcon sx={{ fontSize: 14 }} />,
      minWidth: 250,
      defaultWidth: 1,
      content: (
        <CodeEditor
          value={code}
          onChange={setCode}
          language="c"
          height="100%"
        />
      ),
    },
    {
      id: 'asm',
      title: `Assembly${result?.assembly ? ` (${result.assembly.split('\n').length})` : ''}`,
      icon: <MemoryIcon sx={{ fontSize: 14 }} />,
      minWidth: 250,
      defaultWidth: 1,
      content: result?.assembly ? (
        <AsmViewer value={result.assembly} height="100%" />
      ) : (
        <Box sx={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'text.disabled' }}>
          <Typography variant="body2">Compile to see assembly</Typography>
        </Box>
      ),
    },
    {
      id: 'listing',
      title: 'Listing',
      icon: <DataObjectIcon sx={{ fontSize: 14 }} />,
      minWidth: 300,
      defaultWidth: 1,
      content: (
        <ListingView binaryName={result?.output_name || null} />
      ),
    },
  ], [code, result?.assembly, result?.output_name]);

  // Panel selector items
  const panelItems = useMemo(() => [
    { id: 'source', title: 'Source', icon: <CodeIcon sx={{ fontSize: 14 }} /> },
    { id: 'asm', title: 'Assembly', icon: <MemoryIcon sx={{ fontSize: 14 }} /> },
    { id: 'listing', title: 'Listing', icon: <DataObjectIcon sx={{ fontSize: 14 }} /> },
  ], []);

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Toolbar Row 1: Settings */}
      <Paper variant="outlined" sx={{ p: 1, mb: 1, flexShrink: 0 }}>
        <Stack direction="row" spacing={1.5} alignItems="center" flexWrap="wrap" useFlexGap>
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
                <MenuItem value="arm32">ARM32 (armhf)</MenuItem>
                <MenuItem value="arm64">ARM64 (aarch64)</MenuItem>
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
          <Stack direction="row" spacing={0.5}>
            <Tooltip title="Hello World using ARM syscalls - great starting point">
              <Chip label="Hello" size="small" onClick={() => loadExample('hello')} clickable />
            </Tooltip>
            <Tooltip title="Recursive & iterative Fibonacci - see function calls in assembly">
              <Chip label="Fib" size="small" onClick={() => loadExample('fibonacci')} clickable />
            </Tooltip>
            <Tooltip title="Loop patterns - learn cmp, b.lt, b.ne branching">
              <Chip label="Loops" size="small" onClick={() => loadExample('loop')} clickable />
            </Tooltip>
            <Tooltip title="Structs & pointers - see ldr/str memory operations">
              <Chip label="Memory" size="small" onClick={() => loadExample('memory')} clickable />
            </Tooltip>
          </Stack>

          {dockerStatusChip}
        </Stack>
      </Paper>

      {/* Toolbar Row 2: Panel selector + Actions */}
      <Paper variant="outlined" sx={{ p: 1, mb: 1, flexShrink: 0 }}>
        <Stack direction="row" spacing={2} alignItems="center" justifyContent="space-between">
          {/* Panel toggles */}
          <PanelSelector panels={panelItems} activePanels={activePanels} onToggle={handlePanelToggle} />

          {/* Compile button + status */}
          <Stack direction="row" spacing={1} alignItems="center">
            {result && (
              <Chip 
                size="small" 
                label={result.success ? 'Success' : 'Failed'} 
                color={result.success ? 'success' : 'error'}
                sx={{ height: 20, fontSize: '0.65rem' }}
              />
            )}

            {/* Download buttons */}
            {result?.success && result.output_name && (
              <Tooltip title="Download compiled ELF binary">
                <Button
                  size="small"
                  variant="outlined"
                  color="success"
                  startIcon={<DownloadIcon sx={{ fontSize: 14 }} />}
                  onClick={handleDownloadBinary}
                  sx={{ minWidth: 'auto', px: 1, height: 28 }}
                >
                  ELF
                </Button>
              </Tooltip>
            )}
            {result?.assembly && (
              <Tooltip title="Download assembly source">
                <Button
                  size="small"
                  variant="outlined"
                  color="info"
                  startIcon={<DownloadIcon sx={{ fontSize: 14 }} />}
                  onClick={handleDownloadAsm}
                  sx={{ minWidth: 'auto', px: 1, height: 28 }}
                >
                  .s
                </Button>
              </Tooltip>
            )}
            {result?.success && result.output_path && onBinaryCompiled && (
              <Tooltip title="Open in analyzer">
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<BugReportIcon sx={{ fontSize: 14 }} />}
                  onClick={() => onBinaryCompiled(result.output_path!, result.output_name!)}
                  sx={{ minWidth: 'auto', px: 1, height: 28 }}
                >
                  Analyze
                </Button>
              </Tooltip>
            )}
            {result?.success && result.output_path && onAnalyzeAndChat && (
              <Tooltip title="Analyze and chat with Claude">
                <Button
                  size="small"
                  variant="contained"
                  color="secondary"
                  startIcon={<ChatBubbleOutlineIcon sx={{ fontSize: 14 }} />}
                  onClick={() => onAnalyzeAndChat(result.output_path!, result.output_name!)}
                  sx={{ minWidth: 'auto', px: 1, height: 28 }}
                >
                  Chat
                </Button>
              </Tooltip>
            )}

            <Tooltip 
              title={
                commandPreview ? (
                  <Box sx={{ maxWidth: 400 }}>
                    <Typography variant="caption" component="div" sx={{ fontFamily: 'monospace', mb: 0.5 }}>
                      {commandPreview.command}
                    </Typography>
                    {commandPreview.uses_docker && (
                      <Typography variant="caption" color="info.light">
                        🐳 Docker cross-compilation
                      </Typography>
                    )}
                  </Box>
                ) : 'Loading...'
              } 
              arrow 
              placement="top"
            >
              <span>
                <Button
                  variant="contained"
                  color="primary"
                  size="small"
                  startIcon={compiling ? <CircularProgress size={14} color="inherit" /> : <PlayArrowIcon />}
                  onClick={handleCompile}
                  disabled={compiling || !code.trim() || (commandPreview ? !commandPreview.available : false)}
                  sx={{ height: 28 }}
                >
                  {compiling ? 'Compiling...' : 'Compile'}
                </Button>
              </span>
            </Tooltip>
          </Stack>
        </Stack>
      </Paper>

      {/* Compiler output message (if error) */}
      {result && !result.success && (
        <Alert 
          severity="error" 
          sx={{ mb: 1, flexShrink: 0, py: 0.5 }}
          action={
            <Typography variant="caption" sx={{ fontFamily: 'monospace', opacity: 0.7 }}>
              exit {result.return_code}
            </Typography>
          }
        >
          <Typography variant="caption" component="pre" sx={{ m: 0, whiteSpace: 'pre-wrap', maxHeight: 60, overflow: 'auto' }}>
            {result.stderr || 'Compilation failed'}
          </Typography>
        </Alert>
      )}

      {/* Main content: Resizable panels */}
      <Box sx={{ flex: 1, overflow: 'hidden', minHeight: 0 }}>
        <PanelLayout
          panels={panelConfigs}
          activePanels={activePanels}
          onPanelClose={handlePanelClose}
          height="100%"
        />
      </Box>

      {/* Docker setup instructions */}
      {(!dockerAvailable || !dockerImageExists) && architecture.startsWith('arm') && !result && (
        <Alert severity="info" sx={{ mt: 1.5, flexShrink: 0 }}>
          <Typography variant="body2" fontWeight={500}>
            {!dockerAvailable ? '🐳 Start Docker Desktop' : '🐳 Build Docker image'}
          </Typography>
          <Typography variant="caption" component="div">
            {!dockerAvailable 
              ? 'Docker is required for ARM cross-compilation on this machine.'
              : 'Run: docker build -t r2d2-compiler -f Dockerfile.compiler .'
            }
          </Typography>
        </Alert>
      )}
    </Box>
  );
}
