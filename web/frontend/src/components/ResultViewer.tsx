import AutoGraphIcon from '@mui/icons-material/AutoGraph';
import BugReportIcon from '@mui/icons-material/BugReport';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import InsightsIcon from '@mui/icons-material/Insights';
import MemoryIcon from '@mui/icons-material/Memory';
import PsychologyIcon from '@mui/icons-material/Psychology';
import RadarIcon from '@mui/icons-material/Radar';
import TextSnippetIcon from '@mui/icons-material/TextSnippet';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import {
  alpha,
  Badge,
  Box,
  Chip,
  Grid,
  IconButton,
  List,
  ListItem,
  ListItemText,
  Paper,
  Stack,
  Tab,
  Tabs,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import { FC, useMemo, useState } from 'react';
import type { AnalysisResultPayload } from '../types';

interface ResultViewerProps {
  result: AnalysisResultPayload | null;
}

type ViewTab = 'overview' | 'functions' | 'strings' | 'disassembly' | 'graphs';

const formatHex = (value: number | string | null | undefined, fallback = '?') => {
  if (value === null || value === undefined) return fallback;
  const num = typeof value === 'string' ? Number(value) : value;
  if (Number.isNaN(num)) return fallback;
  return `0x${num.toString(16)}`;
};

const CopyButton: FC<{ text: string }> = ({ text }) => (
  <Tooltip title="Copy to clipboard">
    <IconButton size="small" onClick={() => navigator.clipboard.writeText(text)}>
      <ContentCopyIcon sx={{ fontSize: 16 }} />
    </IconButton>
  </Tooltip>
);

const ResultViewer: FC<ResultViewerProps> = ({ result }) => {
  const theme = useTheme();
  const [view, setView] = useState<ViewTab>('overview');

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
        <MemoryIcon sx={{ fontSize: 48, mb: 2, opacity: 0.5 }} />
        <Typography variant="body1" fontWeight={500}>
          No analysis results
        </Typography>
        <Typography variant="body2" sx={{ mt: 0.5 }}>
          Drop a binary and run analysis to see insights.
        </Typography>
      </Box>
    );
  }

  const quickScan = result.quick_scan ?? {};
  const deepScan = result.deep_scan ?? {};

  const radareQuick = (quickScan.radare2 ?? {}) as Record<string, any>;
  const radareDeep = (deepScan.radare2 ?? {}) as Record<string, any>;
  const capstoneDeep = (deepScan.capstone ?? {}) as Record<string, any>;
  const angrDeep = (deepScan.angr ?? {}) as Record<string, any>;

  const binInfo = (radareQuick.info?.bin ?? {}) as Record<string, any>;
  const arch = binInfo.arch ?? 'unknown';
  const bits = binInfo.bits ?? '?';
  const os = binInfo.os ?? 'unknown';
  const binType = binInfo.bintype ?? 'unknown';
  const compiler = binInfo.compiler ?? '-';
  const entryAddr = binInfo.entry ?? binInfo.pentry ?? binInfo.baddr ?? null;
  const baseAddr = binInfo.baddr ?? null;

  const capstoneInstructions = Array.isArray(capstoneDeep.instructions) ? capstoneDeep.instructions : [];
  const radareFunctions = Array.isArray(radareDeep.functions) ? radareDeep.functions : [];
  const radareStrings = Array.isArray(radareQuick.strings) ? radareQuick.strings : [];
  const radareImports = Array.isArray(radareQuick.imports) ? radareQuick.imports : [];
  const radareCfg = Array.isArray(radareDeep.cfg) ? radareDeep.cfg : [];
  const radareXrefs = Array.isArray(radareDeep.xrefs) ? radareDeep.xrefs : [];
  const radareDisassembly: string | null =
    typeof radareDeep.entry_disassembly === 'string'
      ? radareDeep.entry_disassembly
      : typeof radareDeep.disassembly === 'string'
      ? radareDeep.disassembly
      : null;

  const angrCfg = ((angrDeep.cfg ?? {}) as Record<string, any>) || {};
  const angrNodes = Array.isArray(angrCfg.nodes) ? angrCfg.nodes : [];
  const angrEdges = Array.isArray(angrCfg.edges) ? angrCfg.edges : [];
  const angrNodeAddrSet = useMemo(
    () =>
      new Set(
        angrNodes
          .map((node: Record<string, any>) => {
            const addr = node.addr ?? node.address ?? node.addr_hex;
            if (!addr) return null;
            if (typeof addr === 'number') return addr;
            const parsed = Number(addr);
            if (!Number.isNaN(parsed)) return parsed;
            return parseInt(String(addr).replace(/^0x/, ''), 16);
          })
          .filter((value): value is number => value !== null && !Number.isNaN(value)),
      ),
    [angrNodes],
  );

  const xrefCountByDest = useMemo(() => {
    const counts = new Map<number, number>();
    radareXrefs.forEach((xref: Record<string, any>) => {
      const dest = xref.to;
      if (typeof dest === 'number') {
        counts.set(dest, (counts.get(dest) ?? 0) + 1);
      }
    });
    return counts;
  }, [radareXrefs]);

  const combinedFunctions = useMemo(() => {
    const functions = radareFunctions
      .filter((fn) => typeof fn.offset === 'number')
      .map((fn) => ({
        name: fn.name ?? 'func',
        offset: fn.offset as number,
        size: fn.size ?? 0,
        callers: xrefCountByDest.get(fn.offset as number) ?? 0,
        hasAngrCoverage: angrNodeAddrSet.has(fn.offset as number),
      }))
      .sort((a, b) => b.size - a.size);
    return {
      list: functions,
      top: functions.slice(0, 20),
      angrCoverage: functions.filter((fn) => fn.hasAngrCoverage).length,
    };
  }, [radareFunctions, xrefCountByDest, angrNodeAddrSet]);

  const interestingStrings = useMemo(() => {
    const seen = new Set<string>();
    return radareStrings
      .map((str) => str.string ?? '')
      .filter((value) => typeof value === 'string' && value.length >= 4)
      .filter((value) => {
        if (seen.has(value)) return false;
        seen.add(value);
        return true;
      })
      .slice(0, 80);
  }, [radareStrings]);

  const radareGraphSummary = useMemo(() => {
    return radareCfg
      .filter((graph) => graph && typeof graph === 'object')
      .map((graph: Record<string, any>) => {
        const blocks = Array.isArray(graph.blocks) ? graph.blocks : [];
        return {
          name: graph.name ?? 'graph',
          blocks: blocks.length,
          edges: Array.isArray(graph.edges) ? graph.edges.length : 0,
        };
      })
      .slice(0, 12);
  }, [radareCfg]);

  const angrGraphPreview = useMemo(() => {
    const edgesBySource = new Map<string, string[]>();
    angrEdges.forEach((edge: Record<string, any>) => {
      const source = edge.source ?? edge.src;
      const target = edge.target ?? edge.dst;
      if (!source || !target) return;
      const list = edgesBySource.get(source) ?? [];
      list.push(target);
      edgesBySource.set(source, list);
    });

    return angrNodes.slice(0, 20).map((node: Record<string, any>) => {
      const id = node.addr ?? node.address ?? node.addr_hex ?? '?';
      const outgoing = edgesBySource.get(node.addr ?? node.address ?? node.addr_hex) ?? [];
      return {
        addr: typeof id === 'string' ? id : formatHex(id),
        function: node.function ?? node.function_name ?? formatHex(node.function ?? node.function_address),
        size: node.size ?? node.block_size ?? '-',
        out: outgoing.slice(0, 3),
      };
    });
  }, [angrNodes, angrEdges]);

  const capstonePreview = capstoneInstructions.slice(0, 12);

  const headerCards = [
    { label: 'Architecture', value: `${arch}/${bits}-bit` },
    { label: 'Entry', value: formatHex(entryAddr) },
    { label: 'Base Address', value: formatHex(baseAddr) },
    { label: 'OS / Type', value: `${os} • ${binType}` },
    { label: 'Compiler', value: compiler },
  ];

  const statsChips = [
    { label: `${radareFunctions.length} functions`, color: 'primary' as const },
    { label: `${radareImports.length} imports`, color: 'secondary' as const },
    { label: `${radareStrings.length} strings`, color: 'default' as const },
    {
      label: `angr coverage ${combinedFunctions.angrCoverage}/${radareFunctions.length || 0}`,
      color: 'info' as const,
    },
  ];

  const overviewInsights = [
    `Quick stage identified ${radareImports.length} imports and ${radareStrings.length} printable strings.`,
    combinedFunctions.top.length
      ? `Deep stage carved out ${combinedFunctions.top.length} of the largest functions (top result: ${combinedFunctions.top[0].name}, ${combinedFunctions.top[0].size} bytes).`
      : 'Deep stage completed but no functions were returned.',
    angrNodes.length
      ? `angr built a CFG with ${angrNodes.length} nodes and ${angrEdges.length} edges; symbolic paths: active ${angrDeep.active ?? 0}, found ${angrDeep.found ?? 0}.`
      : 'angr did not produce a CFG (possibly disabled or failed).',
  ];

  const disassemblySections = [
    {
      title: 'Entry function disassembly',
      body: radareDeep.entry_disassembly ?? 'No entry disassembly captured.',
    },
    {
      title: 'Binary slice (pd 256)',
      body: radareDisassembly ?? 'No disassembly snippet available.',
    },
    {
      title: 'Capstone sample',
      body:
        capstonePreview.length > 0
          ? capstonePreview.map(
              (insn: Record<string, any>) =>
                `${formatHex(insn.address ?? 0)}  ${insn.mnemonic ?? ''} ${insn.op_str ?? ''}`,
            ).join('\n')
          : 'Capstone did not return any instructions.',
    },
  ];

  return (
    <Stack spacing={2} className="fade-in" sx={{ height: '100%' }}>
      <Paper
        variant="outlined"
        sx={{
          p: 2.5,
          bgcolor: alpha(theme.palette.background.paper, 0.85),
          borderColor: alpha(theme.palette.primary.main, 0.2),
        }}
      >
        <Stack direction="row" alignItems="center" spacing={2}>
          <Box
            sx={{
              width: 54,
              height: 54,
              borderRadius: 2.5,
              bgcolor: alpha(theme.palette.primary.main, 0.18),
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <MemoryIcon sx={{ color: 'primary.main', fontSize: 28 }} />
          </Box>
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography
              variant='h6'
              fontWeight={700}
              sx={{ fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
            >
              {result.binary.split('/').pop() ?? result.binary}
            </Typography>
            <Typography variant='body2' color='text.secondary' sx={{ fontFamily: 'monospace' }}>
              {result.binary}
            </Typography>
          </Box>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            {statsChips.map((chip) => (
              <Chip key={chip.label} label={chip.label} color={chip.color} variant="outlined" size="small" />
            ))}
          </Stack>
        </Stack>

        <Grid container spacing={2} sx={{ mt: 2 }}>
          {headerCards.map((card) => (
            <Grid item xs={12} sm={6} md={4} key={card.label}>
              <Paper
                variant="outlined"
                sx={{
                  p: 1.5,
                  height: '100%',
                  bgcolor: alpha(theme.palette.background.default, 0.6),
                  borderColor: alpha(theme.palette.primary.main, 0.15),
                }}
              >
                <Typography variant="caption" color="text.secondary">
                  {card.label}
                </Typography>
                <Typography variant="body1" fontWeight={600} sx={{ mt: 0.5 }}>
                  {card.value}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Paper>

      {(result.issues.length > 0 || result.notes.length > 0) && (
        <Paper
          variant="outlined"
          sx={{
            p: 2,
            borderLeft: `4px solid ${theme.palette.warning.main}`,
            bgcolor: alpha(theme.palette.warning.main, 0.1),
          }}
        >
          <Stack spacing={1.5}>
            {result.issues.map((issue, index) => (
              <Stack direction="row" spacing={1.5} key={`issue-${index}`} alignItems="flex-start">
                <WarningAmberIcon sx={{ color: 'error.main', fontSize: 20, mt: 0.25 }} />
                <Typography variant="body2">{issue}</Typography>
              </Stack>
            ))}
            {result.notes.map((note, index) => (
              <Stack direction="row" spacing={1.5} key={`note-${index}`} alignItems="flex-start">
                <InsightsIcon sx={{ color: 'info.main', fontSize: 20, mt: 0.25 }} />
                <Typography variant="body2">{note}</Typography>
              </Stack>
            ))}
          </Stack>
        </Paper>
      )}

      <Paper
        variant="outlined"
        sx={{
          px: 2,
          borderColor: alpha(theme.palette.primary.main, 0.2),
          bgcolor: alpha(theme.palette.background.paper, 0.85),
        }}
      >
        <Tabs
          value={view}
          onChange={(_, newValue) => setView(newValue)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{ minHeight: 48 }}
        >
          <Tab value="overview" icon={<InsightsIcon />} iconPosition="start" label="Overview" />
          <Tab value="functions" icon={<BugReportIcon />} iconPosition="start" label="Functions" />
          <Tab value="strings" icon={<TextSnippetIcon />} iconPosition="start" label="Strings" />
          <Tab value="disassembly" icon={<RadarIcon />} iconPosition="start" label="Objdump" />
          <Tab
            value="graphs"
            icon={
              <Badge badgeContent={angrNodes.length || null} color="info">
                <AutoGraphIcon />
              </Badge>
            }
            iconPosition="start"
            label="CFG"
          />
        </Tabs>
      </Paper>

      <Box sx={{ flex: 1, minHeight: 0, overflow: 'hidden' }}>
        {view === 'overview' && (
          <Paper
            variant="outlined"
            sx={{
              p: 2,
              height: '100%',
              overflow: 'auto',
              bgcolor: alpha(theme.palette.background.paper, 0.75),
            }}
          >
            <Stack spacing={2}>
              <Typography variant="subtitle2" color="text.secondary">
                Pipeline summary
              </Typography>
              <List dense>
                {overviewInsights.map((line, index) => (
                  <ListItem key={`insight-${index}`} disableGutters>
                    <ListItemText primary={line} />
                  </ListItem>
                ))}
              </List>

              {capstonePreview.length > 0 && (
                <Box>
                  <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>
                    Capstone quick glance
                  </Typography>
                  <Paper
                    variant="outlined"
                    sx={{
                      p: 1.5,
                      fontFamily: 'monospace',
                      fontSize: '0.8rem',
                      bgcolor: alpha(theme.palette.background.default, 0.7),
                      overflowX: 'auto',
                    }}
                  >
                    {capstonePreview.map((insn: Record<string, any>) => (
                      <Typography key={insn.address} variant="body2" sx={{ fontFamily: 'inherit' }}>
                        {formatHex(insn.address)}  {insn.mnemonic} {insn.op_str}
                      </Typography>
                    ))}
                  </Paper>
                </Box>
              )}
            </Stack>
          </Paper>
        )}

        {view === 'functions' && (
          <Paper
            variant="outlined"
            sx={{
              p: 0,
              height: '100%',
              overflow: 'auto',
              bgcolor: alpha(theme.palette.background.paper, 0.8),
            }}
          >
            <List dense disablePadding>
              {combinedFunctions.top.map((fn) => (
                <ListItem
                  key={`fn-${fn.offset}`}
                  sx={{
                    px: 2,
                    py: 1,
                    borderBottom: `1px solid ${alpha(theme.palette.primary.main, 0.1)}`,
                    '&:hover': { bgcolor: alpha(theme.palette.primary.main, 0.08) },
                  }}
                  secondaryAction={
                    fn.hasAngrCoverage ? (
                      <Chip size="small" color="info" label="angr-covered" variant="outlined" />
                    ) : undefined
                  }
                >
                  <ListItemText
                    primary={
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography variant="body2" fontWeight={600}>
                          {fn.name}
                        </Typography>
                        <Chip
                          size="small"
                          label={`${fn.size} bytes`}
                          sx={{ background: alpha(theme.palette.secondary.main, 0.12) }}
                        />
                        <Chip
                          size="small"
                          label={`${fn.callers} callers`}
                          sx={{ background: alpha(theme.palette.primary.main, 0.12) }}
                        />
                      </Stack>
                    }
                    secondary={
                      <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                        {formatHex(fn.offset)}
                      </Typography>
                    }
                  />
                </ListItem>
              ))}
            </List>
            {combinedFunctions.list.length > combinedFunctions.top.length && (
              <Box sx={{ p: 1.5, textAlign: 'center', color: 'text.secondary' }}>
                Showing top {combinedFunctions.top.length} functions out of {combinedFunctions.list.length}.
              </Box>
            )}
          </Paper>
        )}

        {view === 'strings' && (
          <Paper
            variant="outlined"
            sx={{
              p: 2,
              height: '100%',
              overflow: 'auto',
              bgcolor: alpha(theme.palette.background.paper, 0.82),
            }}
          >
            <Grid container spacing={1}>
              {interestingStrings.map((str, index) => (
                <Grid item xs={12} sm={6} md={4} key={`str-${index}`}>
                  <Paper
                    variant="outlined"
                    sx={{
                      px: 1.5,
                      py: 0.75,
                      fontFamily: 'monospace',
                      fontSize: '0.8rem',
                      bgcolor: alpha(theme.palette.background.default, 0.7),
                    }}
                  >
                    {str}
                  </Paper>
                </Grid>
              ))}
            </Grid>
            {interestingStrings.length === 0 && (
              <Typography variant="body2" color="text.secondary">
                No printable strings were extracted.
              </Typography>
            )}
          </Paper>
        )}

        {view === 'disassembly' && (
          <Paper
            variant="outlined"
            sx={{
              p: 2,
              height: '100%',
              overflow: 'auto',
              bgcolor: alpha(theme.palette.background.paper, 0.82),
            }}
          >
            <Stack spacing={2}>
              {disassemblySections.map((section) => (
                <Box key={section.title}>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                    <Typography variant="subtitle2">{section.title}</Typography>
                    {section.body && section.body !== 'No disassembly snippet available.' && (
                      <CopyButton text={section.body} />
                    )}
                  </Stack>
                  <Paper
                    variant="outlined"
                    sx={{
                      p: 1.5,
                      fontFamily: 'monospace',
                      fontSize: '0.8rem',
                      bgcolor: alpha(theme.palette.background.default, 0.7),
                      whiteSpace: 'pre-wrap',
                      overflowX: 'auto',
                    }}
                  >
                    {section.body}
                  </Paper>
                </Box>
              ))}
            </Stack>
          </Paper>
        )}

        {view === 'graphs' && (
          <Grid container spacing={2} sx={{ height: '100%' }}>
            <Grid item xs={12} md={6} sx={{ height: { xs: 'auto', md: '100%' } }}>
              <Paper
                variant="outlined"
                sx={{
                  p: 2,
                  height: '100%',
                  bgcolor: alpha(theme.palette.background.paper, 0.8),
                  overflow: 'auto',
                }}
              >
                <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5 }}>
                  <RadarIcon fontSize="small" />
                  <Typography variant="subtitle2">radare2 CFG (agj)</Typography>
                </Stack>
                <List dense>
                  {radareGraphSummary.map((graph, index) => (
                    <ListItem key={`radare-cfg-${index}`} disableGutters>
                      <ListItemText
                        primary={
                          <Stack direction="row" spacing={1}>
                            <Typography variant="body2" fontWeight={600}>
                              {graph.name}
                            </Typography>
                            <Chip size="small" variant="outlined" label={`${graph.blocks} blocks`} />
                            <Chip size="small" variant="outlined" label={`${graph.edges} edges`} />
                          </Stack>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
                {radareGraphSummary.length === 0 && (
                  <Typography variant="body2" color="text.secondary">
                    radare2 did not return CFG metadata.
                  </Typography>
                )}
              </Paper>
            </Grid>
            <Grid item xs={12} md={6} sx={{ height: { xs: 'auto', md: '100%' } }}>
              <Paper
                variant="outlined"
                sx={{
                  p: 2,
                  height: '100%',
                  bgcolor: alpha(theme.palette.background.paper, 0.8),
                  overflow: 'auto',
                }}
              >
                <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5 }}>
                  <PsychologyIcon fontSize="small" />
                  <Typography variant="subtitle2">angr CFG preview</Typography>
                </Stack>
                <Typography variant="caption" color="text.secondary">
                  Nodes: {angrNodes.length} • Edges: {angrEdges.length} • Active paths: {angrDeep.active ?? 0} •
                  Found paths: {angrDeep.found ?? 0}
                </Typography>
                <List dense sx={{ mt: 1 }}>
                  {angrGraphPreview.map((node, index) => (
                    <ListItem key={`angr-node-${index}`} disableGutters>
                      <ListItemText
                        primary={
                          <Stack direction="row" spacing={1}>
                            <Typography variant="body2" fontWeight={600}>
                              {node.addr}
                            </Typography>
                            <Chip size="small" variant="outlined" label={`size ${node.size}`} />
                          </Stack>
                        }
                        secondary={
                          <Typography variant="caption" color="text.secondary">
                            → {node.out.join(', ') || 'terminal'}
                          </Typography>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
                {angrGraphPreview.length === 0 && (
                  <Typography variant="body2" color="text.secondary">
                    angr graph data not available. Ensure angr is installed and enabled.
                  </Typography>
                )}
              </Paper>
            </Grid>
          </Grid>
        )}
      </Box>

      <Paper
        variant="outlined"
        sx={{
          p: 1.5,
          bgcolor: alpha(theme.palette.background.paper, 0.78),
        }}
      >
        <Typography variant="caption" color="text.secondary">
          Raw JSON snapshot (quick + deep scans)
        </Typography>
        <Paper
          variant="outlined"
          sx={{
            mt: 1,
            p: 1,
            maxHeight: 200,
            overflow: 'auto',
            fontFamily: 'monospace',
            fontSize: '0.7rem',
            bgcolor: alpha(theme.palette.background.default, 0.75),
          }}
        >
          {JSON.stringify({ quick_scan: quickScan, deep_scan: deepScan }, null, 2)}
        </Paper>
      </Paper>
    </Stack>
  );
};

export default ResultViewer;
