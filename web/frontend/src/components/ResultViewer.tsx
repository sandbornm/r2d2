import AccountTreeIcon from '@mui/icons-material/AccountTree';
import CodeIcon from '@mui/icons-material/Code';
import FunctionsIcon from '@mui/icons-material/Functions';
import InfoIcon from '@mui/icons-material/Info';
import MemoryIcon from '@mui/icons-material/Memory';
import TextSnippetIcon from '@mui/icons-material/TextSnippet';
import {
  Box,
  Chip,
  Grid,
  Paper,
  Stack,
  Tab,
  Tabs,
  Typography,
  useTheme,
} from '@mui/material';
import { FC, useCallback, useEffect, useMemo, useState } from 'react';
import type { AnalysisResultPayload, AssemblyAnnotation } from '../types';
import CFGViewer from './CFGViewer';
import DisassemblyViewer from './DisassemblyViewer';

// Local storage key for annotations
const ANNOTATIONS_STORAGE_KEY = 'r2d2-annotations';

interface ResultViewerProps {
  result: AnalysisResultPayload | null;
  sessionId?: string | null;
  onAskAboutCode?: (code: string) => void;
}

type ViewTab = 'summary' | 'functions' | 'strings' | 'disasm' | 'cfg';

const formatHex = (value: number | string | null | undefined, fallback = '?') => {
  if (value === null || value === undefined) return fallback;
  const num = typeof value === 'string' ? Number(value) : value;
  if (Number.isNaN(num)) return fallback;
  return `0x${num.toString(16)}`;
};

// Load annotations from localStorage
const loadAnnotations = (binaryPath: string): AssemblyAnnotation[] => {
  try {
    const stored = localStorage.getItem(ANNOTATIONS_STORAGE_KEY);
    if (!stored) return [];
    const all = JSON.parse(stored) as Record<string, AssemblyAnnotation[]>;
    return all[binaryPath] || [];
  } catch {
    return [];
  }
};

// Save annotations to localStorage
const saveAnnotations = (binaryPath: string, annotations: AssemblyAnnotation[]) => {
  try {
    const stored = localStorage.getItem(ANNOTATIONS_STORAGE_KEY);
    const all = stored ? JSON.parse(stored) : {};
    all[binaryPath] = annotations;
    localStorage.setItem(ANNOTATIONS_STORAGE_KEY, JSON.stringify(all));
  } catch {
    // Ignore storage errors
  }
};

const ResultViewer: FC<ResultViewerProps> = ({ result, sessionId, onAskAboutCode }) => {
  const theme = useTheme();
  const [view, setView] = useState<ViewTab>('summary');
  const [annotations, setAnnotations] = useState<AssemblyAnnotation[]>([]);

  // Load annotations when result or session changes
  useEffect(() => {
    const loadFromServer = async () => {
      if (sessionId) {
        try {
          const response = await fetch(`/api/chats/${sessionId}/annotations`);
          if (response.ok) {
            const data = await response.json();
            setAnnotations(data.annotations || []);
            return;
          }
        } catch {
          // Fall back to localStorage
        }
      }
      // Fallback to localStorage
      if (result?.binary) {
        setAnnotations(loadAnnotations(result.binary));
      } else {
        setAnnotations([]);
      }
    };
    loadFromServer();
  }, [result?.binary, sessionId]);

  // Handle annotation updates (save to server if session available, else localStorage)
  const handleAnnotate = useCallback(async (address: string, note: string) => {
    if (!result?.binary) return;
    
    // Optimistically update local state
    setAnnotations((prev) => {
      const filtered = prev.filter((a) => a.address !== address);
      if (note.trim()) {
        return [...filtered, { address, note: note.trim(), createdAt: new Date().toISOString() }];
      }
      return filtered;
    });
    
    // Try to save to server if we have a session
    if (sessionId) {
      try {
        await fetch(`/api/chats/${sessionId}/annotations`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ address, note: note.trim() }),
        });
      } catch {
        // Silently fall back to local storage
      }
    }
    
    // Always save to localStorage as backup
    setAnnotations((current) => {
      saveAnnotations(result.binary, current);
      return current;
    });
  }, [result?.binary, sessionId]);

  if (!result) {
    return (
      <Box
        sx={{
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'text.secondary',
        }}
      >
        <MemoryIcon sx={{ fontSize: 40, mb: 1.5, opacity: 0.4 }} />
        <Typography variant="body2">No analysis yet</Typography>
        <Typography variant="caption" color="text.secondary">
          Drop a binary to get started
        </Typography>
      </Box>
    );
  }

  const quickScan = result.quick_scan ?? {};
  const deepScan = result.deep_scan ?? {};

  // Extract data from radare2
  const r2Quick = (quickScan.radare2 ?? {}) as Record<string, any>;
  const r2Deep = (deepScan.radare2 ?? {}) as Record<string, any>;
  const angrDeep = (deepScan.angr ?? {}) as Record<string, any>;

  // Binary metadata
  const binInfo = (r2Quick.info?.bin ?? {}) as Record<string, any>;
  const coreInfo = (r2Quick.info?.core ?? {}) as Record<string, any>;
  const rawArch = binInfo.arch ?? 'unknown';
  const bits = binInfo.bits ?? null;
  const machine = binInfo.machine ?? '';
  const os = binInfo.os ?? 'unknown';
  const binType = binInfo.bintype ?? binInfo.class ?? 'unknown';
  const compiler = binInfo.compiler ?? '';
  const format = coreInfo.format ?? 'unknown';

  // Compute a more readable architecture string
  // For ARM: bits=16 means Thumb mode (still 32-bit architecture)
  // bits=32 means ARM mode, bits=64 means AArch64
  const getArchDisplay = (): { short: string; full: string } => {
    const lowerArch = rawArch.toLowerCase();
    const lowerMachine = machine.toLowerCase();
    
    if (lowerArch === 'arm') {
      if (bits === 64) {
        return { short: 'arm64', full: 'ARM64 (AArch64)' };
      }
      if (bits === 16) {
        // Thumb mode - check machine for more context
        if (lowerMachine.includes('v7') || lowerMachine.includes('cortex')) {
          return { short: 'arm32', full: 'ARM32 (Thumb)' };
        }
        return { short: 'arm32', full: 'ARM32 (Thumb mode)' };
      }
      if (bits === 32) {
        return { short: 'arm32', full: 'ARM32' };
      }
      return { short: 'arm', full: `ARM (${bits ?? '?'}-bit)` };
    }
    
    if (lowerArch === 'x86') {
      if (bits === 64) {
        return { short: 'x86_64', full: 'x86-64 (AMD64)' };
      }
      if (bits === 32) {
        return { short: 'x86', full: 'x86 (i386)' };
      }
      return { short: 'x86', full: `x86 (${bits ?? '?'}-bit)` };
    }
    
    if (lowerArch === 'mips') {
      return { short: bits === 64 ? 'mips64' : 'mips32', full: `MIPS (${bits ?? '?'}-bit)` };
    }
    
    if (lowerArch === 'ppc') {
      return { short: bits === 64 ? 'ppc64' : 'ppc32', full: `PowerPC (${bits ?? '?'}-bit)` };
    }
    
    // Fallback
    return { short: rawArch, full: bits ? `${rawArch} (${bits}-bit)` : rawArch };
  };

  const archDisplay = getArchDisplay();

  // Counts
  const functions = Array.isArray(r2Deep.functions) ? r2Deep.functions : [];
  const strings = Array.isArray(r2Quick.strings) ? r2Quick.strings : [];
  const imports = Array.isArray(r2Quick.imports) ? r2Quick.imports : [];
  const functionCfgs = Array.isArray(r2Deep.function_cfgs) ? r2Deep.function_cfgs : [];
  
  // angr data
  const angrCfg = (angrDeep.cfg ?? {}) as Record<string, any>;
  const angrNodes = Array.isArray(angrCfg.nodes) ? angrCfg.nodes : [];
  const angrEdges = Array.isArray(angrCfg.edges) ? angrCfg.edges : [];

  // Disassembly
  const entryDisasm = typeof r2Deep.entry_disassembly === 'string' ? r2Deep.entry_disassembly : null;
  const generalDisasm = typeof r2Deep.disassembly === 'string' ? r2Deep.disassembly : null;
  const disasmText = entryDisasm || generalDisasm || 'No disassembly available';

  // Top functions sorted by size
  const topFunctions = useMemo(() => {
    return functions
      .filter((fn: any) => typeof fn.offset === 'number')
      .sort((a: any, b: any) => (b.size || 0) - (a.size || 0))
      .slice(0, 15)
      .map((fn: any) => ({
        name: fn.name || `sub_${fn.offset.toString(16)}`,
        offset: fn.offset,
        size: fn.size || 0,
      }));
  }, [functions]);

  // Interesting strings
  const interestingStrings = useMemo(() => {
    const seen = new Set<string>();
    return strings
      .map((s: any) => s.string ?? '')
      .filter((s: string) => s.length >= 4 && s.length <= 100)
      .filter((s: string) => {
        if (seen.has(s)) return false;
        seen.add(s);
        return true;
      })
      .slice(0, 30);
  }, [strings]);

  // Top imports
  const topImports = useMemo(() => {
    return imports
      .slice(0, 15)
      .map((imp: any) => imp.name || 'unknown');
  }, [imports]);

  const fileName = result.binary.split('/').pop() || result.binary;

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <Paper variant="outlined" sx={{ p: 1.5, mb: 1.5 }}>
        <Stack direction="row" alignItems="center" spacing={2}>
          <MemoryIcon sx={{ color: 'primary.main' }} />
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography variant="body2" fontWeight={600}>
              {fileName}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {format} · {archDisplay.short} · {os}
            </Typography>
          </Box>
          <Stack direction="row" spacing={0.5}>
            <Chip size="small" label={`${functions.length} fn`} variant="outlined" />
            <Chip size="small" label={`${imports.length} imp`} variant="outlined" />
            <Chip size="small" label={`${strings.length} str`} variant="outlined" />
          </Stack>
        </Stack>
      </Paper>

      {/* Tabs */}
      <Tabs
        value={view}
        onChange={(_, v) => setView(v)}
        sx={{ borderBottom: 1, borderColor: 'divider', minHeight: 36 }}
      >
        <Tab value="summary" label="Summary" icon={<InfoIcon sx={{ fontSize: 16 }} />} iconPosition="start" sx={{ minHeight: 36, py: 0 }} />
        <Tab value="functions" label="Functions" icon={<FunctionsIcon sx={{ fontSize: 16 }} />} iconPosition="start" sx={{ minHeight: 36, py: 0 }} />
        <Tab value="strings" label="Strings" icon={<TextSnippetIcon sx={{ fontSize: 16 }} />} iconPosition="start" sx={{ minHeight: 36, py: 0 }} />
        <Tab value="disasm" label="Disasm" icon={<CodeIcon sx={{ fontSize: 16 }} />} iconPosition="start" sx={{ minHeight: 36, py: 0 }} />
        <Tab value="cfg" label="CFG" icon={<AccountTreeIcon sx={{ fontSize: 16 }} />} iconPosition="start" sx={{ minHeight: 36, py: 0 }} />
      </Tabs>

      {/* Content */}
      <Box sx={{ flex: 1, overflow: 'auto', mt: 1.5 }}>
        {view === 'summary' && (
          <Grid container spacing={1.5}>
            {/* Binary Info */}
            <Grid item xs={12} md={4}>
              <Paper variant="outlined" sx={{ p: 1.5, height: '100%' }}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  Binary Info
                </Typography>
                <Box sx={{ mt: 1 }}>
                  {[
                    ['Format', format],
                    ['Architecture', archDisplay.full],
                    ['OS', os],
                    ['Type', binType],
                    compiler && ['Compiler', compiler],
                  ].filter(Boolean).map(([label, value]) => (
                    <Box key={label as string} sx={{ display: 'flex', justifyContent: 'space-between', py: 0.25 }}>
                      <Typography variant="caption" color="text.secondary">{label}</Typography>
                      <Typography variant="caption">{value}</Typography>
                    </Box>
                  ))}
                </Box>
              </Paper>
            </Grid>

            {/* Top Functions */}
            <Grid item xs={12} md={4}>
              <Paper variant="outlined" sx={{ p: 1.5, height: '100%' }}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  Top Functions
                </Typography>
                <Box sx={{ mt: 1 }}>
                  {topFunctions.slice(0, 6).map((fn, i) => (
                    <Typography key={i} variant="caption" sx={{ display: 'block', py: 0.15, fontFamily: 'monospace' }}>
                      {fn.name}
                    </Typography>
                  ))}
                  {topFunctions.length === 0 && (
                    <Typography variant="caption" color="text.secondary">No functions found</Typography>
                  )}
                </Box>
              </Paper>
            </Grid>

            {/* Top Imports */}
            <Grid item xs={12} md={4}>
              <Paper variant="outlined" sx={{ p: 1.5, height: '100%' }}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  Imports
                </Typography>
                <Box sx={{ mt: 1 }}>
                  {topImports.slice(0, 6).map((name, i) => (
                    <Typography key={i} variant="caption" sx={{ display: 'block', py: 0.15, fontFamily: 'monospace' }}>
                      {name}
                    </Typography>
                  ))}
                  {topImports.length === 0 && (
                    <Typography variant="caption" color="text.secondary">No imports found</Typography>
                  )}
                </Box>
              </Paper>
            </Grid>

            {/* Sample Strings */}
            <Grid item xs={12}>
              <Paper variant="outlined" sx={{ p: 1.5 }}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  Strings (sample)
                </Typography>
                <Box sx={{ mt: 1, display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {interestingStrings.slice(0, 12).map((s, i) => (
                    <Chip
                      key={i}
                      label={s.length > 30 ? s.slice(0, 30) + '…' : s}
                      size="small"
                      variant="outlined"
                      sx={{ fontFamily: 'monospace', fontSize: '0.65rem' }}
                    />
                  ))}
                  {interestingStrings.length === 0 && (
                    <Typography variant="caption" color="text.secondary">No interesting strings</Typography>
                  )}
                </Box>
              </Paper>
            </Grid>
          </Grid>
        )}

        {view === 'functions' && (
          <Paper variant="outlined" sx={{ p: 1.5 }}>
            {topFunctions.length > 0 ? (
              <Box component="table" sx={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                <thead>
                  <tr>
                    <th style={{ textAlign: 'left', padding: '4px 8px', borderBottom: `1px solid ${theme.palette.divider}` }}>Name</th>
                    <th style={{ textAlign: 'left', padding: '4px 8px', borderBottom: `1px solid ${theme.palette.divider}` }}>Address</th>
                    <th style={{ textAlign: 'right', padding: '4px 8px', borderBottom: `1px solid ${theme.palette.divider}` }}>Size</th>
                  </tr>
                </thead>
                <tbody>
                  {topFunctions.map((fn, i) => (
                    <tr key={i}>
                      <td style={{ padding: '4px 8px' }}>{fn.name}</td>
                      <td style={{ padding: '4px 8px', color: theme.palette.text.secondary }}>{formatHex(fn.offset)}</td>
                      <td style={{ padding: '4px 8px', textAlign: 'right' }}>{fn.size}</td>
                    </tr>
                  ))}
                </tbody>
              </Box>
            ) : (
              <Typography variant="body2" color="text.secondary">No functions discovered</Typography>
            )}
          </Paper>
        )}

        {view === 'strings' && (
          <Paper variant="outlined" sx={{ p: 1.5 }}>
            {interestingStrings.length > 0 ? (
              <Box sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                {interestingStrings.map((s, i) => (
                  <Box key={i} sx={{ py: 0.25, borderBottom: `1px solid ${theme.palette.divider}` }}>
                    {s}
                  </Box>
                ))}
              </Box>
            ) : (
              <Typography variant="body2" color="text.secondary">No interesting strings found</Typography>
            )}
          </Paper>
        )}

        {view === 'disasm' && (
          <Paper variant="outlined" sx={{ p: 1.5 }}>
            <DisassemblyViewer 
              disassembly={disasmText} 
              arch={archDisplay.short}
              annotations={annotations}
              onAnnotate={handleAnnotate}
              onAskAbout={onAskAboutCode}
            />
          </Paper>
        )}

        {view === 'cfg' && (
          <Box sx={{ height: 500 }}>
            <CFGViewer
              nodes={angrNodes}
              edges={angrEdges}
              functions={functionCfgs}
              radareFunctions={functions}
              angrActive={angrDeep.active}
              angrFound={angrDeep.found}
            />
          </Box>
        )}
      </Box>
    </Box>
  );
};

export default ResultViewer;
