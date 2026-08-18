import AccountTreeIcon from '@mui/icons-material/AccountTree';
import CodeIcon from '@mui/icons-material/Code';
import DownloadIcon from '@mui/icons-material/Download';
import InfoIcon from '@mui/icons-material/Info';
import MemoryIcon from '@mui/icons-material/Memory';
import TerminalIcon from '@mui/icons-material/Terminal';
import {
  Box,
  Button,
  Chip,
  CircularProgress,
  Paper,
  Stack,
  Tab,
  Tabs,
  Typography,
  useTheme,
} from '@mui/material';
import { FC, Suspense, lazy, memo, useCallback, useEffect, useMemo, useState } from 'react';
import type {
  AnalysisBundleResponse,
  AnalysisResultPayload,
  AssemblyAnnotation,
  DWARFData,
  EvidenceCoverage,
  GEFData,
  GhidraData,
  RuntimeRequirements,
  ToolScorecardEntry,
  ToolStatusSummary,
} from '../types';
import { rankFunctions, resolveGoal } from '../utils/rank';
import AnalysisSteer from './AnalysisSteer';
import ArtifactSheet from './ArtifactSheet';
import BriefingPanel from './BriefingPanel';
import InsightsPanel from './InsightsPanel';
import DisassemblyViewer from './DisassemblyViewer';

// Lazy load heavy components for better initial load performance
const CFGViewer = lazy(() => import('./CFGViewer'));
const DecompilerPanel = lazy(() => import('./DecompilerPanel'));
const DWARFPanel = lazy(() => import('./DWARFPanel'));
const GEFPanel = lazy(() => import('./GEFPanel'));
const GhidraScriptingPanel = lazy(() => import('./GhidraScriptingPanel'));

// Import and re-export CFGContext type for consumers
import type { CFGContext } from './CFGViewer';
export type { CFGContext };

// Loading fallback for lazy components
const ComponentLoader = () => (
  <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 300 }}>
    <CircularProgress size={32} />
  </Box>
);

// Local storage key for annotations
const ANNOTATIONS_STORAGE_KEY = 'r2d2-annotations';

interface ResultViewerProps {
  result: AnalysisResultPayload | null;
  sessionId?: string | null;
  toolsInfo?: Record<string, { available: boolean; install_hint?: string }>;
  onAskAboutCode?: (code: string) => void;
  onAskAboutCFG?: (context: CFGContext) => void;
  userGoal?: string;
}

type ViewTab = 'overview' | 'code' | 'analysis' | 'tools';

const formatHex = (value: number | string | null | undefined, fallback = '?') => {
  if (value === null || value === undefined) return fallback;
  const num = typeof value === 'string' ? Number(value) : value;
  if (Number.isNaN(num)) return fallback;
  return `0x${num.toString(16)}`;
};

const deriveToolScorecard = (toolStatus: Record<string, ToolStatusSummary>): Record<string, ToolScorecardEntry> => {
  const speedFor = (name: string) => {
    if (['firmware', 'binwalk', 'autoprofile', 'libmagic', 'capstone', 'dwarf'].includes(name)) return 'fast';
    if (['radare2', 'angr_mcp', 'ghidra_mcp'].includes(name)) return 'medium';
    if (['angr', 'ghidra', 'ghidra_gdb', 'gef', 'frida', 'gdb'].includes(name)) return 'slow';
    return 'unknown';
  };
  return Object.fromEntries(
    Object.entries(toolStatus).map(([name, status]) => {
      const quality = status.status === 'completed' ? 'good' : status.status === 'partial' ? 'usable' : status.status === 'skipped' ? 'limited' : 'unavailable';
      const score = status.status === 'completed' ? 88 : status.status === 'partial' ? 68 : status.status === 'skipped' ? 45 : 15;
      return [name, {
        state: status.status,
        quality,
        score,
        speed: speedFor(name),
        duration_ms: status.duration_ms,
        error: status.error,
        warnings: status.warnings ?? [],
      }];
    }),
  );
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

const downloadBlob = (body: BlobPart, filename: string, type: string) => {
  const blob = new Blob([body], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
};

const ResultViewer: FC<ResultViewerProps> = memo(({ result, sessionId, onAskAboutCode, onAskAboutCFG, userGoal }) => {
  const theme = useTheme();
  const [view, setView] = useState<ViewTab>('overview');
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

  const handleExportBundle = useCallback(async (format: 'json' | 'markdown' | 'zip') => {
    if (!sessionId || !result?.binary) return;
    const response = await fetch(`/api/chats/${sessionId}/bundle${format === 'markdown' ? '?format=markdown' : format === 'zip' ? '?format=zip' : ''}`);
    if (!response.ok) return;
    const baseName = (result.binary.split('/').pop() || 'analysis').replace(/[^\w.-]+/g, '_');
    if (format === 'markdown') {
      const text = await response.text();
      downloadBlob(text, `${baseName}-r2d2-report.md`, 'text/markdown');
      return;
    }
    if (format === 'zip') {
      const blob = await response.blob();
      downloadBlob(blob, `${baseName}-r2d2-session.zip`, 'application/zip');
      return;
    }
    const data = await response.json() as AnalysisBundleResponse;
    downloadBlob(JSON.stringify(data, null, 2), `${baseName}-r2d2-bundle.json`, 'application/json');
  }, [result?.binary, sessionId]);

  const hasResult = Boolean(result);
  const quickScan = result?.quick_scan ?? {};
  const deepScan = result?.deep_scan ?? {};

  // Extract data from radare2
  const r2Quick = (quickScan.radare2 ?? {}) as Record<string, unknown>;
  const r2Deep = (deepScan.radare2 ?? {}) as Record<string, unknown>;
  const angrDeep = (deepScan.angr ?? {}) as Record<string, unknown>;
  const dwarfDeep = (deepScan.dwarf ?? null) as DWARFData | null;
  const ghidraDeep = (deepScan.ghidra ?? null) as GhidraData | null;
  const gefDeep = (deepScan.gef ?? null) as GEFData | null;
  const firmwareQuick = (quickScan.firmware ?? null) as Record<string, unknown> | null;
  const sniffQuick = (quickScan.sniff ?? null) as Record<string, unknown> | null;
  const runtimeRequirements = (quickScan.runtime ?? null) as RuntimeRequirements | null;
  const toolStatus = (result?.tool_status ?? {}) as Record<string, ToolStatusSummary>;
  const toolScorecard = useMemo(
    () => Object.keys(result?.tool_scorecard ?? {}).length
      ? (result?.tool_scorecard ?? {}) as Record<string, ToolScorecardEntry>
      : deriveToolScorecard(toolStatus),
    [result?.tool_scorecard, toolStatus],
  );
  const evidenceCoverage = (result?.evidence_coverage ?? null) as EvidenceCoverage | null;

  // Binary metadata
  const r2QuickInfo = r2Quick.info as Record<string, unknown> | undefined;
  const binInfo = (r2QuickInfo?.bin ?? {}) as Record<string, unknown>;
  const coreInfo = (r2QuickInfo?.core ?? {}) as Record<string, unknown>;
  const rawArch = (binInfo.arch as string | undefined) ?? 'unknown';
  const bits = (binInfo.bits as number | undefined) ?? null;
  const machine = (binInfo.machine as string | undefined) ?? '';
  const os = (binInfo.os as string | undefined) ?? 'unknown';
  const binType = (binInfo.bintype as string | undefined) ?? (binInfo.class as string | undefined) ?? 'unknown';
  const compiler = (binInfo.compiler as string | undefined) ?? '';
  const format = (coreInfo.format as string | undefined) ?? 'unknown';
  const firmwareFormat = (firmwareQuick?.top_level_format as string | undefined) ?? null;
  const firmwareContainer = (firmwareQuick?.container_type as string | undefined) ?? null;
  const formatDisplay = format !== 'unknown' ? format : (firmwareFormat ?? format);
  const osDisplay = os !== 'unknown' ? os : (firmwareContainer ?? os);

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
  const firmwareArtifacts = Array.isArray(firmwareQuick?.embedded_artifacts) ? firmwareQuick.embedded_artifacts : [];
  const firmwareTargets = Array.isArray(firmwareQuick?.recommended_targets) ? firmwareQuick.recommended_targets : [];
  
  // angr data - properly extract CFG nodes, edges, and stats
  const angrCfg = (angrDeep.cfg ?? {}) as Record<string, unknown>;
  const angrNodes = Array.isArray(angrCfg.nodes) ? angrCfg.nodes : [];
  const angrEdges = Array.isArray(angrCfg.edges) ? angrCfg.edges : [];
  const angrActive = typeof angrDeep.active === 'number' ? angrDeep.active : 0;
  const angrFound = typeof angrDeep.found === 'number' ? angrDeep.found : 0;

  // Disassembly
  const entryDisasm = typeof r2Deep.entry_disassembly === 'string' ? r2Deep.entry_disassembly : null;
  const generalDisasm = typeof r2Deep.disassembly === 'string' ? r2Deep.disassembly : null;
  const disasmText = entryDisasm || generalDisasm || 'No disassembly available';

  const rankedGoal = useMemo(
    () => resolveGoal(
      userGoal,
      result?.briefing?.inferred_goal,
      result?.briefing?.ranking_tags || [],
      result?.record?.tags || [],
      {
        ...(result?.briefing?.subject || {}),
        name: result?.binary ? (result.binary.split('/').pop() || result.binary) : '',
      },
    ),
    [userGoal, result?.briefing, result?.record?.tags, result?.binary],
  );

  // Functions matching the thesis — size rank is fool's gold
  const topFunctions = useMemo(() => {
    const mapped = functions
      .filter((fn: Record<string, unknown>) => typeof fn.offset === 'number')
      .map((fn: Record<string, unknown>) => ({
        name: (fn.name as string) || `sub_${(fn.offset as number).toString(16)}`,
        offset: fn.offset as number,
        size: (fn.size as number) || 0,
      }));
    return rankFunctions(mapped, rankedGoal.lenses, rankedGoal.goal);
  }, [functions, rankedGoal]);

  // Interesting strings
  const interestingStrings = useMemo(() => {
    const seen = new Set<string>();
    return strings
      .map((s: Record<string, unknown>) => (s.string as string) ?? '')
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
      .map((imp: Record<string, unknown>) => (imp.name as string) || 'unknown');
  }, [imports]);

  const fileName = result?.binary ? (result.binary.split('/').pop() || result.binary) : 'unknown';

  return (
    !hasResult ? (
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
    ) : (
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
              {formatDisplay} · {archDisplay.short} · {osDisplay}
              {result?.record?.record_id ? ` · rec ${result.record.record_id.slice(0, 12)} r${result.record.revision ?? 1}` : ''}
            </Typography>
            {!!result?.record?.tags?.length && (
              <Stack direction="row" spacing={0.5} sx={{ mt: 0.5, flexWrap: 'wrap', gap: 0.5 }}>
                {result.record.tags.slice(0, 8).map((tag) => (
                  <Chip key={tag} size="small" label={tag} variant="outlined" />
                ))}
              </Stack>
            )}
          </Box>
          <Stack direction="row" spacing={0.5}>
            <Chip size="small" label={`${functions.length} fn`} variant="outlined" />
            <Chip size="small" label={`${imports.length} imp`} variant="outlined" />
            <Chip size="small" label={`${strings.length} str`} variant="outlined" />
            {firmwareArtifacts.length > 0 && <Chip size="small" label={`${firmwareArtifacts.length} art`} variant="outlined" />}
            {firmwareTargets.length > 0 && <Chip size="small" label={`${firmwareTargets.length} tgt`} variant="outlined" />}
            {sessionId && (
              <>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<DownloadIcon sx={{ fontSize: 14 }} />}
                  onClick={() => handleExportBundle('json')}
                  sx={{ minHeight: 24, py: 0, px: 1 }}
                >
                  JSON
                </Button>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<DownloadIcon sx={{ fontSize: 14 }} />}
                  onClick={() => handleExportBundle('markdown')}
                  sx={{ minHeight: 24, py: 0, px: 1 }}
                >
                  Report
                </Button>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<DownloadIcon sx={{ fontSize: 14 }} />}
                  onClick={() => handleExportBundle('zip')}
                  sx={{ minHeight: 24, py: 0, px: 1 }}
                >
                  Archive
                </Button>
              </>
            )}
          </Stack>
        </Stack>
      </Paper>

      {/* Simplified 4-Tab Structure */}
      <Tabs
        value={view}
        onChange={(_, v) => setView(v)}
        sx={{ borderBottom: 1, borderColor: 'divider', minHeight: 36 }}
      >
        <Tab value="overview" label="Overview" icon={<InfoIcon sx={{ fontSize: 16 }} />} iconPosition="start" sx={{ minHeight: 36, py: 0 }} />
        <Tab value="code" label="Code" icon={<CodeIcon sx={{ fontSize: 16 }} />} iconPosition="start" sx={{ minHeight: 36, py: 0 }} />
        <Tab value="analysis" label="Analysis" icon={<AccountTreeIcon sx={{ fontSize: 16 }} />} iconPosition="start" sx={{ minHeight: 36, py: 0 }} />
        <Tab value="tools" label="Tools" icon={<TerminalIcon sx={{ fontSize: 16 }} />} iconPosition="start" sx={{ minHeight: 36, py: 0 }} />
      </Tabs>

      {/* Content */}
      <Box sx={{ flex: 1, overflow: 'auto', mt: 1.5 }}>
        {/* OVERVIEW TAB - Binary info, Profile, Tool attribution */}
        {view === 'overview' && (
          <Stack spacing={1.5}>
            {result?.briefing && (
              <BriefingPanel
                briefing={result.briefing}
                compact
                userGoal={userGoal}
                recordTags={result.record?.tags}
              />
            )}
            <ArtifactSheet
              fileName={fileName}
              format={formatDisplay}
              arch={archDisplay.full}
              os={osDisplay}
              binType={binType}
              compiler={compiler}
              firmware={firmwareQuick}
              sniff={sniffQuick}
              runtime={runtimeRequirements as Record<string, unknown> | null}
              briefingSubject={(result?.briefing?.subject as Record<string, unknown> | undefined) ?? null}
              toolStatus={toolStatus}
              toolScorecard={toolScorecard}
              evidenceCoverage={evidenceCoverage}
              functionCount={functions.length}
              importCount={imports.length}
              stringCount={strings.length}
              sha256={result?.record?.sha256 ?? null}
            />
          </Stack>
        )}

        {/* CODE TAB - Disassembly, Decompiler, DWARF */}
        {view === 'code' && (
          <Stack spacing={1.5}>
            {/* Disassembly */}
            <Paper variant="outlined" sx={{ p: 1.5 }}>
              <Typography variant="caption" color="text.secondary" fontWeight={600} sx={{ mb: 1, display: 'block' }}>
                Disassembly
              </Typography>
              <DisassemblyViewer
                disassembly={disasmText}
                arch={archDisplay.short}
                annotations={annotations}
                onAnnotate={handleAnnotate}
                onAskAbout={onAskAboutCode}
              />
            </Paper>

            {/* Decompiler (if available) */}
            {ghidraDeep && ghidraDeep.decompiled_count > 0 && (
              <Paper variant="outlined" sx={{ height: 400, overflow: 'hidden' }}>
                <Suspense fallback={<ComponentLoader />}>
                  <DecompilerPanel
                    data={ghidraDeep}
                    onAskClaude={(question) => onAskAboutCode?.(question)}
                  />
                </Suspense>
              </Paper>
            )}

            {dwarfDeep && (
              <Paper variant="outlined" sx={{ height: 300, overflow: 'hidden' }}>
                <Suspense fallback={<ComponentLoader />}>
                  <DWARFPanel
                    data={dwarfDeep}
                    onAskClaude={(question) => onAskAboutCode?.(question)}
                  />
                </Suspense>
              </Paper>
            )}
          </Stack>
        )}

        {/* ANALYSIS TAB - Functions, Strings, CFG */}
        {view === 'analysis' && (
          <Stack spacing={1.5}>
            {result?.briefing && (
              <BriefingPanel
                briefing={result.briefing}
                onAsk={onAskAboutCode}
                userGoal={userGoal}
                recordTags={result.record?.tags}
              />
            )}
            <AnalysisSteer
              binary={result?.binary || fileName}
              firmware={firmwareQuick}
              imports={topImports}
              lenses={rankedGoal.lenses}
              goal={rankedGoal.goal}
              sniffStrings={
                Array.isArray(sniffQuick?.strings)
                  ? sniffQuick.strings
                    .map((item) => (typeof item === 'string' ? item : String((item as { value?: string }).value || '')))
                    .filter(Boolean)
                  : interestingStrings
              }
            />
            <InsightsPanel recordId={result?.record?.record_id} />
            {topFunctions.length > 0 && (
              <Paper variant="outlined" sx={{ p: 1.5, maxHeight: 280, overflow: 'auto' }}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  Functions ({topFunctions.length})
                </Typography>
                <Box component="table" sx={{ width: '100%', borderCollapse: 'collapse', fontFamily: 'monospace', fontSize: '0.75rem', mt: 1 }}>
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
              </Paper>
            )}
            {(angrNodes.length > 0 || functionCfgs.length > 0) && (
              <Paper variant="outlined" sx={{ height: 420 }}>
                <Suspense fallback={<ComponentLoader />}>
                  <CFGViewer
                    nodes={angrNodes}
                    edges={angrEdges}
                    functions={functionCfgs}
                    angrActive={angrActive}
                    angrFound={angrFound}
                    onAskAboutCFG={onAskAboutCFG}
                    sessionId={sessionId}
                  />
                </Suspense>
              </Paper>
            )}
          </Stack>
        )}

        {/* TOOLS TAB - Scripting, Dynamic analysis */}
        {view === 'tools' && (
          <Stack spacing={1.5}>
            {/* Scripting Panel */}
            <Paper variant="outlined" sx={{ height: 400, overflow: 'hidden' }}>
              <Suspense fallback={<ComponentLoader />}>
                <GhidraScriptingPanel
                  sessionId={sessionId}
                  binaryPath={result?.binary}
                />
              </Suspense>
            </Paper>

            {/* Dynamic Analysis (GEF) if available */}
            {gefDeep && gefDeep.trace && (
              <Paper variant="outlined" sx={{ height: 400, overflow: 'hidden' }}>
                <Suspense fallback={<ComponentLoader />}>
                  <GEFPanel data={gefDeep} />
                </Suspense>
              </Paper>
            )}
          </Stack>
        )}
      </Box>
    </Box>
    )
  );
});

ResultViewer.displayName = 'ResultViewer';

export default ResultViewer;
