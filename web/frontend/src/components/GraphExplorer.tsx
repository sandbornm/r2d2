import AccountTreeIcon from '@mui/icons-material/AccountTree';
import CenterFocusStrongIcon from '@mui/icons-material/CenterFocusStrong';
import ExploreIcon from '@mui/icons-material/Explore';
import FilterAltIcon from '@mui/icons-material/FilterAlt';
import HubIcon from '@mui/icons-material/Hub';
import LayersIcon from '@mui/icons-material/Layers';
import MapIcon from '@mui/icons-material/Map';
import MyLocationIcon from '@mui/icons-material/MyLocation';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import PsychologyIcon from '@mui/icons-material/Psychology';
import QuestionAnswerIcon from '@mui/icons-material/QuestionAnswer';
import SearchIcon from '@mui/icons-material/Search';
import ZoomInIcon from '@mui/icons-material/ZoomIn';
import ZoomOutIcon from '@mui/icons-material/ZoomOut';
import {
  alpha,
  Box,
  Button,
  Chip,
  Divider,
  IconButton,
  InputAdornment,
  Paper,
  Stack,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import {
  FC,
  PointerEvent as ReactPointerEvent,
  WheelEvent as ReactWheelEvent,
  memo,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import type {
  AnalysisGraphPayload,
  ExplorerGraphEdge,
  ExplorerGraphNode,
  InvestigationGraphPayload,
  SessionGraphsResponse,
} from '../types';
import { CacheKeys, getFromCache, setInCache } from '../utils/cache';

type GraphMode = 'findings' | 'journey';
type GraphLens = 'overview' | 'segment' | 'all';
type MapDensity = 'calm' | 'linked' | 'dense';
type DetailLevel = 'compact' | 'summary' | 'full';

interface GraphExplorerProps {
  sessionId?: string | null;
  analysisGraph?: AnalysisGraphPayload | null;
  onAskAboutNode?: (node: ExplorerGraphNode, mode: GraphMode) => void;
  onNavigateToAddress?: (address: string) => void;
}

interface PositionedNode extends ExplorerGraphNode {
  x: number;
  y: number;
  width: number;
  height: number;
  lane: number;
  laneLabel: string;
  laneColor: string;
}

interface ViewState {
  x: number;
  y: number;
  scale: number;
}

interface GraphSegment {
  key: string;
  label: string;
  color: string;
  order: number;
  kinds: Set<string>;
  nodeIds: Set<string>;
  nodeCount: number;
  edgeCount: number;
  sampleLabels: string[];
  importantCount: number;
}

interface MapSignal {
  node: ExplorerGraphNode;
  score: number;
  reason: string;
}

const NODE_W = 176;
const NODE_H = 64;
const LANE_H = 128;
const COL_W = 250;
const SEGMENT_W = 278;
const SEGMENT_H = 126;
const MINIMAP_W = 190;
const MINIMAP_H = 118;
const MINIMAP_PAD = 8;
const TRIAGE_SIGNAL_LIMIT = 8;

const FINDINGS_REGION_POSITIONS: Record<string, { x: number; y: number }> = {
  subject: { x: 60, y: 230 },
  artifacts: { x: 390, y: 64 },
  code: { x: 720, y: 228 },
  behavior: { x: 390, y: 392 },
  findings: { x: 1048, y: 80 },
  tools: { x: 1048, y: 386 },
};

const JOURNEY_REGION_POSITIONS: Record<string, { x: number; y: number }> = {
  subject: { x: 60, y: 230 },
  actors: { x: 390, y: 76 },
  actions: { x: 700, y: 230 },
  artifacts: { x: 1010, y: 76 },
  tools: { x: 1010, y: 384 },
};

const FINDING_ORDER = [
  'binary',
  'profile',
  'tool',
  'embedded_artifact_group',
  'artifact_analysis_group',
  'artifact_group',
  'graph_artifact_group',
  'embedded_artifact',
  'artifact_analysis',
  'artifact',
  'graph_artifact',
  'section_group',
  'section',
  'string_group',
  'import_group',
  'function_group',
  'function',
  'basic_block_group',
  'basic_block',
  'import',
  'string',
  'decompilation',
  'type',
  'issue',
];

const JOURNEY_ORDER = [
  'session',
  'subject',
  'actor',
  'tool_action',
  'human_action',
  'message',
  'artifact',
  'graph_artifact',
  'tool',
  'address',
];

const colorForKind = (kind: string): string => {
  const colors: Record<string, string> = {
    binary: '#3b82f6',
    subject: '#3b82f6',
    session: '#14b8a6',
    function: '#22c55e',
    basic_block: '#84cc16',
    import: '#f59e0b',
    string: '#ec4899',
    decompilation: '#8b5cf6',
    type: '#a855f7',
    issue: '#ef4444',
    segment: '#14b8a6',
    artifact_group: '#0ea5e9',
    embedded_artifact_group: '#0ea5e9',
    artifact_analysis_group: '#0ea5e9',
    graph_artifact_group: '#6366f1',
    string_group: '#ec4899',
    import_group: '#f59e0b',
    function_group: '#22c55e',
    basic_block_group: '#84cc16',
    section_group: '#94a3b8',
    tool: '#64748b',
    profile: '#06b6d4',
    actor: '#f97316',
    tool_action: '#64748b',
    human_action: '#22c55e',
    message: '#8b5cf6',
    artifact: '#0ea5e9',
    graph_artifact: '#6366f1',
    address: '#f59e0b',
    section: '#94a3b8',
  };
  return colors[kind] ?? '#64748b';
};

const truncate = (value: string, max = 34) => value.length > max ? `${value.slice(0, max - 1)}...` : value;

const graphTitle = (mode: GraphMode) => mode === 'findings' ? 'Findings Map' : 'Journey Map';

const lensTitle = (lens: GraphLens) => {
  if (lens === 'overview') return 'Overview';
  if (lens === 'segment') return 'Segment';
  return 'All';
};

const densityTitle = (density: MapDensity) => {
  if (density === 'calm') return 'Calm';
  if (density === 'linked') return 'Linked';
  return 'Dense';
};

const GraphExplorer: FC<GraphExplorerProps> = memo(function GraphExplorer({
  sessionId,
  analysisGraph,
  onAskAboutNode,
  onNavigateToAddress,
}) {
  const theme = useTheme();
  const [mode, setMode] = useState<GraphMode>('findings');
  const [graphs, setGraphs] = useState<SessionGraphsResponse | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [lens, setLens] = useState<GraphLens>('overview');
  const [density, setDensity] = useState<MapDensity>('calm');
  const [segmentKey, setSegmentKey] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refreshGraphs = useCallback(async () => {
    if (!sessionId) return;
    setLoading(true);
    try {
      const response = await fetch(`/api/chats/${sessionId}/graphs`);
      if (!response.ok) throw new Error('Failed to load graph maps');
      const data: SessionGraphsResponse = await response.json();
      const merged = {
        ...data,
        analysis_graph: data.analysis_graph ?? analysisGraph ?? null,
      };
      setGraphs(merged);
      setInCache(CacheKeys.graphs(sessionId), merged);
    } catch (error) {
      const cached = getFromCache<SessionGraphsResponse>(CacheKeys.graphs(sessionId));
      if (cached) {
        setGraphs(cached);
      } else if (analysisGraph) {
        setGraphs({ analysis_graph: analysisGraph, investigation_graph: null });
      }
    } finally {
      setLoading(false);
    }
  }, [analysisGraph, sessionId]);

  useEffect(() => {
    if (!sessionId) {
      setGraphs(analysisGraph ? { analysis_graph: analysisGraph, investigation_graph: null } : null);
      return;
    }
    const cached = getFromCache<SessionGraphsResponse>(CacheKeys.graphs(sessionId));
    if (cached) setGraphs(cached);
    refreshGraphs().catch(console.error);
  }, [analysisGraph, refreshGraphs, sessionId]);

  const activeGraph = mode === 'findings'
    ? (analysisGraph ?? graphs?.analysis_graph ?? null)
    : (graphs?.investigation_graph ?? null);

  const segments = useMemo(() => activeGraph ? buildSegments(activeGraph, mode) : [], [activeGraph, mode]);

  const visibleGraph = useMemo(() => {
    if (!activeGraph) return null;
    if (lens === 'overview') return buildOverviewGraph(activeGraph, segments, mode, density);
    if (lens === 'segment') return buildSegmentGraph(activeGraph, segments, segmentKey);
    return activeGraph;
  }, [activeGraph, density, lens, mode, segmentKey, segments]);

  const filteredGraph = useMemo(() => {
    if (!visibleGraph) return null;
    if (!query.trim()) return visibleGraph;
    const needle = query.trim().toLowerCase();
    const nodes = visibleGraph.nodes.filter((node) => {
      const searchable = `${node.kind} ${node.label} ${node.address ?? ''} ${node.source ?? ''} ${node.actor ?? ''}`.toLowerCase();
      return searchable.includes(needle);
    });
    const ids = new Set(nodes.map((node) => node.id));
    const edges = visibleGraph.edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target));
    return { ...visibleGraph, nodes, edges };
  }, [query, visibleGraph]);

  const selectedNode = filteredGraph?.nodes.find((node) => node.id === selectedId)
    ?? visibleGraph?.nodes.find((node) => node.id === selectedId)
    ?? null;

  const summary = activeGraph?.summary ?? {};
  const nodeCount = Number(summary.node_count ?? activeGraph?.nodes.length ?? 0);
  const edgeCount = Number(summary.edge_count ?? activeGraph?.edges.length ?? 0);
  const visibleNodeCount = filteredGraph?.nodes.length ?? 0;
  const signalCount = segments.reduce((count, segment) => count + segment.importantCount, 0);
  const omittedNodeCount = Number(visibleGraph?.summary?.omitted_nodes ?? filteredGraph?.summary?.omitted_nodes ?? 0);
  const groupedNodeCount = Number(visibleGraph?.summary?.grouped_node_count ?? filteredGraph?.summary?.grouped_node_count ?? 0);
  const activeSegment = segments.find((segment) => segment.key === segmentKey) ?? null;

  const handleSegmentSelect = useCallback((nextSegmentKey: string) => {
    setSegmentKey(nextSegmentKey);
    setSelectedId(null);
    setLens('segment');
  }, []);

  return (
    <Box
      sx={{
        height: '100%',
        minHeight: 560,
        display: 'grid',
        gridTemplateColumns: { xs: '1fr', lg: 'minmax(0, 1fr) 320px' },
        gap: 1.5,
      }}
    >
      <Paper
        variant="outlined"
        sx={{
          minWidth: 0,
          overflow: 'hidden',
          borderRadius: 1,
          bgcolor: alpha(theme.palette.background.paper, 0.92),
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        <Stack
          direction="row"
          alignItems="center"
          spacing={1}
          sx={{ p: 1, borderBottom: 1, borderColor: 'divider', flexWrap: 'wrap', rowGap: 0.75 }}
        >
          <MapIcon sx={{ fontSize: 18, color: 'primary.main' }} />
          <Typography variant="body2" fontWeight={700}>
            {graphTitle(mode)}
          </Typography>
          <Chip size="small" label={`${nodeCount} nodes`} variant="outlined" sx={{ height: 22 }} />
          <Chip size="small" label={`${edgeCount} links`} variant="outlined" sx={{ height: 22 }} />
          {segments.length > 0 && <Chip size="small" label={`${segments.length} areas`} variant="outlined" sx={{ height: 22 }} />}
          {signalCount > 0 && <Chip size="small" label={`${signalCount} signal`} color="warning" variant="outlined" sx={{ height: 22 }} />}
          {lens !== 'all' && <Chip size="small" label={`${visibleNodeCount} visible`} variant="outlined" sx={{ height: 22 }} />}
          {groupedNodeCount > 0 && <Chip size="small" label={`${groupedNodeCount} grouped`} variant="outlined" sx={{ height: 22 }} />}
          {omittedNodeCount > 0 && <Chip size="small" label={`${omittedNodeCount} omitted`} variant="outlined" sx={{ height: 22 }} />}
          {loading && <Chip size="small" label="refreshing" color="info" variant="outlined" sx={{ height: 22 }} />}

          <Box sx={{ flex: 1 }} />

          <ToggleButtonGroup
            exclusive
            size="small"
            value={lens}
            onChange={(_, value: GraphLens | null) => {
              if (!value) return;
              setLens(value);
              setSelectedId(null);
              if (value === 'overview') setSegmentKey(null);
            }}
          >
            <ToggleButton value="overview">
              <Tooltip title="Segment overview">
                <LayersIcon sx={{ fontSize: 16 }} />
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="segment" disabled={!segmentKey}>
              <Tooltip title="Focused segment">
                <FilterAltIcon sx={{ fontSize: 16 }} />
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="all">
              <Tooltip title="Full graph">
                <AccountTreeIcon sx={{ fontSize: 16 }} />
              </Tooltip>
            </ToggleButton>
          </ToggleButtonGroup>

          <ToggleButtonGroup
            exclusive
            size="small"
            value={density}
            onChange={(_, value: MapDensity | null) => {
              if (value) setDensity(value);
            }}
            aria-label="Map density"
          >
            <ToggleButton value="calm" aria-label="Calm map density">
              <Tooltip title="Calm overview">
                <LayersIcon sx={{ fontSize: 16 }} />
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="linked" aria-label="Linked map density">
              <Tooltip title="Show strongest routes">
                <HubIcon sx={{ fontSize: 16 }} />
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="dense" aria-label="Dense map density">
              <Tooltip title="Show more relationships">
                <AccountTreeIcon sx={{ fontSize: 16 }} />
              </Tooltip>
            </ToggleButton>
          </ToggleButtonGroup>

          <TextField
            size="small"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search map"
            sx={{ width: { xs: 160, sm: 220 } }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon sx={{ fontSize: 16 }} />
                </InputAdornment>
              ),
            }}
          />

          <ToggleButtonGroup
            exclusive
            size="small"
            value={mode}
            onChange={(_, value: GraphMode | null) => {
              if (value) {
                setMode(value);
                setSelectedId(null);
                setSegmentKey(null);
                setLens('overview');
              }
            }}
          >
            <ToggleButton value="findings">
              <Tooltip title="Subject-under-test findings">
                <HubIcon sx={{ fontSize: 16 }} />
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="journey">
              <Tooltip title="Investigation journey">
                <ExploreIcon sx={{ fontSize: 16 }} />
              </Tooltip>
            </ToggleButton>
          </ToggleButtonGroup>
        </Stack>

        {segments.length > 0 && (
          <SegmentRail
            segments={segments}
            lens={lens}
            selectedKey={segmentKey}
            onSelect={handleSegmentSelect}
            onOverview={() => {
              setLens('overview');
              setSegmentKey(null);
              setSelectedId(null);
            }}
          />
        )}

        <Box sx={{ flex: 1, minHeight: 0 }}>
          {filteredGraph && filteredGraph.nodes.length > 0 ? (
            <GraphCanvas
              graph={filteredGraph}
              mode={mode}
              lens={lens}
              density={density}
              selectedId={selectedId}
              onSelect={setSelectedId}
              onSegmentSelect={handleSegmentSelect}
            />
          ) : (
            <Box sx={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'text.secondary' }}>
              <Stack alignItems="center" spacing={1}>
                <MapIcon sx={{ fontSize: 42, opacity: 0.4 }} />
                <Typography variant="body2">No graph data yet</Typography>
                <Typography variant="caption">Run an analysis, then use the map to explore findings and journey steps.</Typography>
              </Stack>
            </Box>
          )}
        </Box>
      </Paper>

      <GraphInspector
        mode={mode}
        lens={lens}
        segments={segments}
        segment={activeSegment}
        graph={filteredGraph ?? visibleGraph}
        node={selectedNode}
        summary={summary}
        selectedId={selectedId}
        onAskAboutNode={onAskAboutNode}
        onNavigateToAddress={onNavigateToAddress}
        onRefresh={refreshGraphs}
        onSegmentSelect={handleSegmentSelect}
        onNodeSelect={setSelectedId}
      />
    </Box>
  );
});

interface SegmentRailProps {
  segments: GraphSegment[];
  lens: GraphLens;
  selectedKey: string | null;
  onSelect: (key: string) => void;
  onOverview: () => void;
}

const SegmentRail: FC<SegmentRailProps> = ({ segments, lens, selectedKey, onSelect, onOverview }) => {
  const theme = useTheme();
  return (
    <Stack
      direction="row"
      spacing={0.75}
      sx={{
        px: 1,
        py: 0.75,
        borderBottom: 1,
        borderColor: 'divider',
        overflowX: 'auto',
        bgcolor: alpha(theme.palette.background.default, 0.48),
      }}
    >
      <Chip
        size="small"
        label={lensTitle(lens)}
        color={lens === 'overview' ? 'primary' : 'default'}
        variant={lens === 'overview' ? 'filled' : 'outlined'}
        onClick={onOverview}
        sx={{ height: 24, flexShrink: 0 }}
      />
      {segments.map((segment) => {
        const selected = lens === 'segment' && selectedKey === segment.key;
        const signalLabel = segment.importantCount === 1 ? 'signal' : 'signals';
        return (
          <Chip
            key={segment.key}
            size="small"
            label={`${segment.label} ${segment.nodeCount}${segment.importantCount ? ` / ${segment.importantCount} ${signalLabel}` : ''}`}
            onClick={() => onSelect(segment.key)}
            variant={selected ? 'filled' : 'outlined'}
            sx={{
              height: 24,
              flexShrink: 0,
              bgcolor: selected ? alpha(segment.color, 0.18) : undefined,
              borderColor: alpha(segment.color, selected ? 0.5 : 0.28),
              color: selected ? segment.color : 'text.secondary',
              '& .MuiChip-label': { px: 0.75 },
            }}
          />
        );
      })}
    </Stack>
  );
};

interface GraphCanvasProps {
  graph: AnalysisGraphPayload | InvestigationGraphPayload;
  mode: GraphMode;
  lens: GraphLens;
  density: MapDensity;
  selectedId: string | null;
  onSelect: (id: string | null) => void;
  onSegmentSelect: (key: string) => void;
}

const GraphCanvas: FC<GraphCanvasProps> = ({ graph, mode, lens, density, selectedId, onSelect, onSegmentSelect }) => {
  const theme = useTheme();
  const svgRef = useRef<SVGSVGElement | null>(null);
  const dragRef = useRef<{ x: number; y: number; view: ViewState } | null>(null);
  const [view, setView] = useState<ViewState>({ x: -40, y: -40, scale: 1 });

  const { nodes, edges, bounds } = useMemo(() => layoutGraph(graph, mode, lens), [graph, lens, mode]);
  const nodeMap = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  const laneBands = useMemo(() => buildLaneBands(nodes), [nodes]);
  const minimap = useMemo(() => {
    const safeWidth = Math.max(bounds.width, 1);
    const safeHeight = Math.max(bounds.height, 1);
    const scale = Math.min((MINIMAP_W - MINIMAP_PAD * 2) / safeWidth, (MINIMAP_H - MINIMAP_PAD * 2) / safeHeight);
    const contentWidth = safeWidth * scale;
    const contentHeight = safeHeight * scale;
    return {
      scale,
      offsetX: (MINIMAP_W - contentWidth) / 2,
      offsetY: (MINIMAP_H - contentHeight) / 2,
    };
  }, [bounds]);

  const fit = useCallback(() => {
    const horizontalPad = lens === 'overview' ? 110 : 150;
    const verticalPad = lens === 'overview' ? 120 : 150;
    const fitScale = Math.min(
      1100 / Math.max(bounds.width + horizontalPad, 1),
      720 / Math.max(bounds.height + verticalPad, 1),
    );
    const minScale = lens === 'all' ? 0.28 : 0.34;
    const maxScale = lens === 'overview' ? (density === 'calm' ? 0.82 : 0.9) : lens === 'segment' ? 0.88 : 0.78;
    const scale = Math.min(maxScale, Math.max(minScale, fitScale));
    const viewportWidth = 1100 / scale;
    const viewportHeight = 720 / scale;
    setView({
      x: bounds.minX - Math.max(48, (viewportWidth - bounds.width) / 2),
      y: bounds.minY - Math.max(48, (viewportHeight - bounds.height) / 2),
      scale,
    });
  }, [bounds, density, lens]);

  useEffect(() => {
    fit();
  }, [fit, graph.schema_version, lens, mode]);

  const viewBox = `${view.x} ${view.y} ${1100 / view.scale} ${720 / view.scale}`;
  const showEdgeLabels = lens !== 'overview' && view.scale > 1.05 && edges.length <= 80;
  const viewportWidth = 1100 / view.scale;
  const viewportHeight = 720 / view.scale;
  const detailLevel: DetailLevel = lens === 'overview' || view.scale >= 0.82 ? 'full' : view.scale >= 0.55 ? 'summary' : 'compact';
  const groupedNodeCount = Number(graph.summary?.grouped_node_count ?? 0);
  const omittedNodeCount = Number(graph.summary?.omitted_nodes ?? 0);

  const centerMiniMapAt = useCallback((event: ReactPointerEvent<SVGSVGElement>) => {
    event.stopPropagation();
    const rect = event.currentTarget.getBoundingClientRect();
    const localX = event.clientX - rect.left - minimap.offsetX;
    const localY = event.clientY - rect.top - minimap.offsetY;
    const worldX = bounds.minX + localX / minimap.scale;
    const worldY = bounds.minY + localY / minimap.scale;
    setView((prev) => ({
      ...prev,
      x: worldX - (1100 / prev.scale) / 2,
      y: worldY - (720 / prev.scale) / 2,
    }));
  }, [bounds.minX, bounds.minY, minimap.offsetX, minimap.offsetY, minimap.scale]);

  const handleMiniMapMove = useCallback((event: ReactPointerEvent<SVGSVGElement>) => {
    if (event.buttons !== 1) return;
    centerMiniMapAt(event);
  }, [centerMiniMapAt]);

  const handlePointerDown = (event: ReactPointerEvent<SVGSVGElement>) => {
    if ((event.target as Element).closest('[data-node="true"]')) return;
    dragRef.current = { x: event.clientX, y: event.clientY, view };
    svgRef.current?.setPointerCapture(event.pointerId);
  };

  const handlePointerMove = (event: ReactPointerEvent<SVGSVGElement>) => {
    if (!dragRef.current) return;
    const dx = (event.clientX - dragRef.current.x) / view.scale;
    const dy = (event.clientY - dragRef.current.y) / view.scale;
    setView({
      ...dragRef.current.view,
      x: dragRef.current.view.x - dx,
      y: dragRef.current.view.y - dy,
    });
  };

  const handlePointerUp = (event: ReactPointerEvent<SVGSVGElement>) => {
    dragRef.current = null;
    svgRef.current?.releasePointerCapture(event.pointerId);
  };

  const handleWheel = (event: ReactWheelEvent<SVGSVGElement>) => {
    event.preventDefault();
    const nextScale = Math.min(2.4, Math.max(0.35, view.scale * (event.deltaY > 0 ? 0.9 : 1.1)));
    setView({ ...view, scale: nextScale });
  };

  return (
    <Box sx={{ position: 'relative', height: '100%', bgcolor: theme.palette.mode === 'dark' ? '#080b12' : '#f8fafc' }}>
      <svg
        ref={svgRef}
        viewBox={viewBox}
        width="100%"
        height="100%"
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onWheel={handleWheel}
        style={{ display: 'block', touchAction: 'none', cursor: dragRef.current ? 'grabbing' : 'grab' }}
      >
        <defs>
          <pattern id="map-grid" width="48" height="48" patternUnits="userSpaceOnUse">
            <path d="M 48 0 L 0 0 0 48" fill="none" stroke={alpha(theme.palette.text.primary, 0.08)} strokeWidth="1" />
          </pattern>
          <marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L9,3 z" fill={alpha(theme.palette.text.primary, 0.42)} />
          </marker>
        </defs>

        <rect x={view.x - 1200} y={view.y - 1200} width="4000" height="4000" fill="url(#map-grid)" onClick={() => onSelect(null)} />

        {lens !== 'overview' && laneBands.map((band) => (
          <g key={`lane:${band.lane}`}>
            <rect
              x={bounds.minX}
              y={band.y - 18}
              width={bounds.width}
              height={band.height + 36}
              rx="12"
              fill={alpha(band.color, theme.palette.mode === 'dark' ? 0.08 : 0.06)}
              stroke={alpha(band.color, 0.12)}
              strokeWidth="1"
            />
            <text
              x={bounds.minX + 18}
              y={band.y - 2}
              fill={alpha(theme.palette.text.primary, 0.48)}
              fontSize="10"
              fontWeight="800"
              letterSpacing="0"
            >
              {band.label.toUpperCase()}
            </text>
          </g>
        ))}

        {edges.map((edge) => {
          const source = nodeMap.get(edge.source);
          const target = nodeMap.get(edge.target);
          if (!source || !target) return null;
          const sx = source.x + source.width;
          const sy = source.y + source.height / 2;
          const tx = target.x;
          const ty = target.y + target.height / 2;
          const mid = Math.max(42, Math.abs(tx - sx) * 0.45);
          const path = `M ${sx} ${sy} C ${sx + mid} ${sy}, ${tx - mid} ${ty}, ${tx} ${ty}`;
          const routeWeight = typeof edge.properties.edge_count === 'number' ? edge.properties.edge_count : 1;
          const sourceColor = typeof source.properties.color === 'string' ? source.properties.color : colorForKind(source.kind);
          const isGuideRoute = edge.properties.guide === true;
          return (
            <g key={edge.id}>
              <path
                d={path}
                fill="none"
                stroke={lens === 'overview' ? alpha(sourceColor, isGuideRoute ? 0.18 : 0.42) : alpha(theme.palette.text.primary, detailLevel === 'compact' ? 0.14 : 0.24)}
                strokeWidth={lens === 'overview' ? Math.min(7, 2 + Math.log2(routeWeight + 1)) : edge.kind === 'then' ? 3 : 1.6}
                strokeDasharray={isGuideRoute ? '8 8' : undefined}
                markerEnd={isGuideRoute ? undefined : 'url(#arrow)'}
              />
              {showEdgeLabels && (
                <text
                  x={(sx + tx) / 2}
                  y={(sy + ty) / 2 - 6}
                  fill={alpha(theme.palette.text.primary, 0.45)}
                  fontSize="10"
                  textAnchor="middle"
                  style={{ pointerEvents: 'none' }}
                >
                  {truncate(edge.kind, 18)}
                </text>
              )}
            </g>
          );
        })}

        {nodes.map((node) => {
          const selected = node.id === selectedId;
          const color = typeof node.properties.color === 'string' ? node.properties.color : colorForKind(node.kind);
          const important = isImportantNode(node) || Number(node.properties.important_count ?? 0) > 0;
          const context = node.properties.map_context === true;
          const isSegment = node.kind === 'segment';
          const isAggregate = isAggregateNode(node);
          const nodeDetailLevel: DetailLevel = selected ? 'full' : detailLevel;
          return (
            <g
              key={node.id}
              transform={`translate(${node.x}, ${node.y})`}
              data-node="true"
              onClick={(event) => {
                event.stopPropagation();
                const segmentKey = typeof node.properties.segment_key === 'string' ? node.properties.segment_key : null;
                if (node.kind === 'segment' && segmentKey) {
                  onSegmentSelect(segmentKey);
                  return;
                }
                onSelect(node.id);
              }}
              opacity={context ? 0.58 : 1}
              style={{ cursor: 'pointer' }}
            >
              <title>{`${node.kind}: ${node.label}`}</title>
              {important && (
                <rect
                  x={-5}
                  y={-5}
                  width={node.width + 10}
                  height={node.height + 10}
                  rx="11"
                  fill="none"
                  stroke={alpha(theme.palette.warning.main, isSegment ? 0.42 : 0.5)}
                  strokeWidth={isSegment ? 2.2 : 1.8}
                  strokeDasharray={isSegment ? undefined : '5 5'}
                />
              )}
              <rect
                width={node.width}
                height={node.height}
                rx="8"
                fill={isSegment || isAggregate
                  ? alpha(color, theme.palette.mode === 'dark' ? 0.16 : 0.08)
                  : theme.palette.mode === 'dark' ? alpha('#111827', 0.96) : alpha('#ffffff', 0.96)}
                stroke={selected ? color : alpha(color, isSegment || isAggregate ? 0.78 : context ? 0.36 : 0.62)}
                strokeWidth={selected ? 3 : isSegment || isAggregate ? 2 : 1.5}
                filter={selected ? undefined : undefined}
              />
              <rect width="5" height={node.height} rx="2" fill={color} />
              {isSegment ? (
                <>
                  <text x="16" y="24" fill={theme.palette.text.primary} fontSize="15" fontWeight="800">
                    {truncate(node.label, 24)}
                  </text>
                  <text x={node.width - 16} y="24" fill={theme.palette.text.secondary} fontSize="11" fontWeight="700" textAnchor="end">
                    {String(node.properties.node_count ?? 0)} nodes
                  </text>
                  {nodeDetailLevel !== 'compact' && (
                    <>
                      <rect x="16" y="38" width="96" height="22" rx="11" fill={alpha(color, 0.16)} />
                      <text x="30" y="53" fill={color} fontSize="11" fontWeight="800">
                        {String(node.properties.edge_count ?? 0)} links
                      </text>
                      {Number(node.properties.important_count ?? 0) > 0 && (
                        <>
                          <rect x="120" y="38" width="94" height="22" rx="11" fill={alpha(theme.palette.warning.main, 0.16)} />
                          <text x="134" y="53" fill={theme.palette.warning.main} fontSize="11" fontWeight="800">
                            {String(node.properties.important_count)} signal
                          </text>
                        </>
                      )}
                    </>
                  )}
                  {nodeDetailLevel === 'full' && Array.isArray(node.properties.samples) && node.properties.samples.slice(0, 2).map((sample, index) => (
                    <text key={`${node.id}:sample:${index}`} x="16" y={82 + index * 16} fill={alpha(theme.palette.text.primary, 0.76)} fontSize="11">
                      {truncate(String(sample), 36)}
                    </text>
                  ))}
                  {nodeDetailLevel === 'full' && (
                    <text x="16" y="116" fill={theme.palette.text.secondary} fontSize="10">
                      {truncate(String(node.properties.kinds ?? ''), 42)}
                    </text>
                  )}
                </>
              ) : isAggregate ? (
                <>
                  <text x="16" y="20" fill={theme.palette.text.secondary} fontSize="10" fontWeight="800">
                    {nodeDetailLevel === 'compact' ? 'GROUP' : `${String(node.properties.grouped_kind ?? 'group').toUpperCase()} GROUP`}
                  </text>
                  <text x={node.width - 16} y="20" fill={color} fontSize="11" fontWeight="900" textAnchor="end">
                    {String(node.properties.group_count ?? 0)} items
                  </text>
                  <text x="16" y="44" fill={theme.palette.text.primary} fontSize="13" fontWeight="800">
                    {truncate(node.label, nodeDetailLevel === 'compact' ? 20 : 28)}
                  </text>
                  {nodeDetailLevel !== 'compact' && Number(node.properties.important_count ?? 0) > 0 && (
                    <text x={node.width - 16} y="44" fill={theme.palette.warning.main} fontSize="10" fontWeight="800" textAnchor="end">
                      {String(node.properties.important_count)} signal
                    </text>
                  )}
                  {nodeDetailLevel === 'full' && Array.isArray(node.properties.samples) && node.properties.samples.slice(0, 2).map((sample, index) => (
                    <text key={`${node.id}:aggregate-sample:${index}`} x="16" y={64 + index * 14} fill={alpha(theme.palette.text.primary, 0.72)} fontSize="10">
                      {truncate(String(sample), 34)}
                    </text>
                  ))}
                </>
              ) : (
                <>
                  <circle cx="22" cy="20" r="7" fill={alpha(color, 0.22)} stroke={color} strokeWidth="1.5" />
                  {nodeDetailLevel !== 'compact' && (
                    <text x="38" y="18" fill={theme.palette.text.secondary} fontSize="10" fontWeight="700">
                      {context ? 'CONTEXT' : node.kind.toUpperCase()}
                    </text>
                  )}
                  <text x="14" y={nodeDetailLevel === 'compact' ? 44 : 42} fill={theme.palette.text.primary} fontSize={nodeDetailLevel === 'compact' ? '12' : '13'} fontWeight="700">
                    {truncate(node.label, nodeDetailLevel === 'compact' ? 18 : 26)}
                  </text>
                  {nodeDetailLevel === 'full' && (node.address || node.source || node.actor) && (
                    <text x="14" y="57" fill={theme.palette.text.secondary} fontSize="10">
                      {truncate(String(node.address ?? node.source ?? node.actor), 30)}
                    </text>
                  )}
                </>
              )}
            </g>
          );
        })}
      </svg>

      <Stack direction="row" spacing={0.5} sx={{ position: 'absolute', left: 12, bottom: 12 }}>
        <Tooltip title="Zoom in">
          <IconButton size="small" aria-label="Zoom in" onClick={() => setView((prev) => ({ ...prev, scale: Math.min(2.4, prev.scale * 1.15) }))}>
            <ZoomInIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>
        <Tooltip title="Zoom out">
          <IconButton size="small" aria-label="Zoom out" onClick={() => setView((prev) => ({ ...prev, scale: Math.max(0.35, prev.scale * 0.85) }))}>
            <ZoomOutIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>
        <Tooltip title="Fit map">
          <IconButton size="small" aria-label="Fit map" onClick={fit}>
            <CenterFocusStrongIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>
      </Stack>

      <Stack
        direction="row"
        spacing={0.75}
        sx={{
          position: 'absolute',
          left: 12,
          top: 12,
          alignItems: 'center',
          flexWrap: 'wrap',
          maxWidth: 'calc(100% - 260px)',
        }}
      >
        <Chip size="small" label={`${nodes.length} shown`} sx={{ height: 22, bgcolor: alpha(theme.palette.background.paper, 0.86) }} />
        {lens === 'overview' && (
          <Chip size="small" label={`${densityTitle(density)} density`} sx={{ height: 22, bgcolor: alpha(theme.palette.background.paper, 0.86) }} />
        )}
        {groupedNodeCount > 0 && (
          <Chip size="small" label={`${groupedNodeCount} grouped`} sx={{ height: 22, bgcolor: alpha(theme.palette.background.paper, 0.86) }} />
        )}
        {omittedNodeCount > 0 && (
          <Chip size="small" label={`${omittedNodeCount} hidden`} sx={{ height: 22, bgcolor: alpha(theme.palette.background.paper, 0.86) }} />
        )}
        <Chip
          size="small"
          label={detailLevel === 'full' ? 'detail' : detailLevel}
          sx={{ height: 22, bgcolor: alpha(theme.palette.background.paper, 0.86), color: 'text.secondary' }}
        />
      </Stack>

      <Box
        sx={{
          position: 'absolute',
          right: 12,
          bottom: 12,
          width: MINIMAP_W,
          height: MINIMAP_H,
          borderRadius: 1,
          overflow: 'hidden',
          border: 1,
          borderColor: alpha(theme.palette.text.primary, 0.16),
          bgcolor: alpha(theme.palette.background.paper, 0.88),
          boxShadow: theme.shadows[2],
        }}
      >
        <svg
          width={MINIMAP_W}
          height={MINIMAP_H}
          viewBox={`0 0 ${MINIMAP_W} ${MINIMAP_H}`}
          onPointerDown={centerMiniMapAt}
          onPointerMove={handleMiniMapMove}
          style={{ display: 'block', cursor: 'crosshair', touchAction: 'none' }}
        >
          <rect width={MINIMAP_W} height={MINIMAP_H} fill={alpha(theme.palette.background.paper, 0.65)} />
          {nodes.map((node) => {
            const color = typeof node.properties.color === 'string' ? node.properties.color : colorForKind(node.kind);
            const important = isImportantNode(node) || Number(node.properties.important_count ?? 0) > 0;
            return (
              <rect
                key={`mini:${node.id}`}
                x={minimap.offsetX + (node.x - bounds.minX) * minimap.scale}
                y={minimap.offsetY + (node.y - bounds.minY) * minimap.scale}
                width={Math.max(3, node.width * minimap.scale)}
                height={Math.max(3, node.height * minimap.scale)}
                rx="1.5"
                fill={alpha(color, important ? 0.72 : 0.42)}
                stroke={important ? theme.palette.warning.main : 'none'}
                strokeWidth={important ? 1 : 0}
              />
            );
          })}
          <rect
            x={minimap.offsetX + (view.x - bounds.minX) * minimap.scale}
            y={minimap.offsetY + (view.y - bounds.minY) * minimap.scale}
            width={Math.max(8, viewportWidth * minimap.scale)}
            height={Math.max(8, viewportHeight * minimap.scale)}
            fill="none"
            stroke={theme.palette.primary.main}
            strokeWidth="1.8"
          />
        </svg>
      </Box>
    </Box>
  );
};

interface GraphInspectorProps {
  mode: GraphMode;
  lens: GraphLens;
  segments: GraphSegment[];
  segment: GraphSegment | null;
  graph: AnalysisGraphPayload | InvestigationGraphPayload | null;
  node: ExplorerGraphNode | null;
  summary: Record<string, unknown>;
  selectedId: string | null;
  onAskAboutNode?: (node: ExplorerGraphNode, mode: GraphMode) => void;
  onNavigateToAddress?: (address: string) => void;
  onRefresh: () => void;
  onSegmentSelect: (key: string) => void;
  onNodeSelect: (id: string | null) => void;
}

const GraphInspector: FC<GraphInspectorProps> = ({
  mode,
  lens,
  segments,
  segment,
  graph,
  node,
  summary,
  selectedId,
  onAskAboutNode,
  onNavigateToAddress,
  onRefresh,
  onSegmentSelect,
  onNodeSelect,
}) => {
  const theme = useTheme();
  const nodeKinds = summary.node_kinds as Record<string, number> | undefined;
  const triageSignals = useMemo(
    () => collectMapSignals(graph?.nodes ?? []).filter((signal) => signal.node.id !== selectedId).slice(0, TRIAGE_SIGNAL_LIMIT),
    [graph?.nodes, selectedId],
  );
  const prioritySegments = segments
    .slice()
    .sort((a, b) => b.importantCount - a.importantCount || b.nodeCount - a.nodeCount || a.order - b.order)
    .slice(0, 6);

  return (
    <Paper
      variant="outlined"
      sx={{
        minWidth: 0,
        overflow: 'hidden',
        borderRadius: 1,
        display: 'flex',
        flexDirection: 'column',
        bgcolor: alpha(theme.palette.background.paper, 0.94),
      }}
    >
      <Stack spacing={1.2} sx={{ p: 1.5, borderBottom: 1, borderColor: 'divider' }}>
        <Stack direction="row" alignItems="center" spacing={1}>
          {mode === 'findings' ? <AccountTreeIcon sx={{ fontSize: 18 }} /> : <MyLocationIcon sx={{ fontSize: 18 }} />}
          <Typography variant="body2" fontWeight={700}>
            {segment && lens === 'segment' ? segment.label : 'Inspector'}
          </Typography>
          <Box sx={{ flex: 1 }} />
          <Tooltip title="Refresh maps">
            <IconButton size="small" aria-label="Refresh maps" onClick={onRefresh}>
              <OpenInNewIcon sx={{ fontSize: 16 }} />
            </IconButton>
          </Tooltip>
        </Stack>
        <Typography variant="caption" color="text.secondary">
          {segment && lens === 'segment'
            ? `${segment.nodeCount} nodes and ${segment.edgeCount} links in this segment.`
            : mode === 'findings'
            ? 'Artifacts, code structure, evidence, and setup gaps found in the binary.'
            : 'Human, model, agent, and tool actions across this investigation.'}
        </Typography>
      </Stack>

      <Box sx={{ flex: 1, overflow: 'auto', p: 1.5 }}>
        {node ? (
          <Stack spacing={1.5}>
            <Box>
              <Chip size="small" label={node.kind} sx={{ bgcolor: alpha(colorForKind(node.kind), 0.16), color: colorForKind(node.kind), mb: 1 }} />
              <Typography variant="body2" fontWeight={700} sx={{ wordBreak: 'break-word' }}>
                {node.label}
              </Typography>
              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5, wordBreak: 'break-all' }}>
                {node.id}
              </Typography>
            </Box>

            {(node.address || node.source || node.actor || node.timestamp) && (
              <Stack spacing={0.5}>
                {node.address && <InfoLine label="Address" value={node.address} />}
                {node.source && <InfoLine label="Source" value={node.source} />}
                {node.actor && <InfoLine label="Actor" value={node.actor} />}
                {node.timestamp && <InfoLine label="Time" value={node.timestamp} />}
              </Stack>
            )}

            {isAggregateNode(node) && (
              <Stack spacing={1}>
                <Stack direction="row" flexWrap="wrap" gap={0.75}>
                  <Chip size="small" label={`${String(node.properties.group_count ?? 0)} items`} variant="outlined" sx={{ height: 22 }} />
                  {Number(node.properties.important_count ?? 0) > 0 && (
                    <Chip size="small" label={`${String(node.properties.important_count)} signal`} color="warning" variant="outlined" sx={{ height: 22 }} />
                  )}
                  {node.properties.grouped_kind && (
                    <Chip size="small" label={String(node.properties.grouped_kind)} variant="outlined" sx={{ height: 22 }} />
                  )}
                </Stack>
                {Array.isArray(node.properties.samples) && (
                  <Stack spacing={0.4}>
                    {node.properties.samples.slice(0, 6).map((sample, index) => (
                      <Typography key={`${node.id}:inspector-sample:${index}`} variant="caption" color="text.secondary" sx={{ wordBreak: 'break-word' }}>
                        {String(sample)}
                      </Typography>
                    ))}
                  </Stack>
                )}
              </Stack>
            )}

            <Stack direction="row" spacing={1}>
              {node.address && onNavigateToAddress && (
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<MyLocationIcon />}
                  onClick={() => onNavigateToAddress(node.address!)}
                >
                  Go
                </Button>
              )}
              {onAskAboutNode && (
                <Button
                  size="small"
                  variant="contained"
                  startIcon={<QuestionAnswerIcon />}
                  onClick={() => onAskAboutNode(node, mode)}
                >
                  Ask
                </Button>
              )}
            </Stack>

            <Divider />
            <Typography variant="caption" color="text.secondary" fontWeight={700}>
              Properties
            </Typography>
            <Box
              component="pre"
              sx={{
                m: 0,
                p: 1,
                borderRadius: 1,
                bgcolor: alpha(theme.palette.text.primary, 0.06),
                color: 'text.secondary',
                fontSize: '0.68rem',
                overflow: 'auto',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
              }}
            >
              {JSON.stringify(node.properties ?? {}, null, 2)}
            </Box>
          </Stack>
        ) : (
          <Stack spacing={1.5}>
            <Box sx={{ py: 3, textAlign: 'center', color: 'text.secondary' }}>
              <PsychologyIcon sx={{ fontSize: 36, opacity: 0.45, mb: 1 }} />
              <Typography variant="body2">Select a node</Typography>
              <Typography variant="caption">Click anything on the map to inspect evidence or journey context.</Typography>
            </Box>
            {segment && lens === 'segment' && (
              <>
                <Divider />
                <Typography variant="caption" color="text.secondary" fontWeight={700}>
                  Segment Snapshot
                </Typography>
                <Stack direction="row" flexWrap="wrap" gap={0.75}>
                  <Chip size="small" label={`${segment.nodeCount} nodes`} variant="outlined" sx={{ height: 22 }} />
                  <Chip size="small" label={`${segment.edgeCount} links`} variant="outlined" sx={{ height: 22 }} />
                  {segment.importantCount > 0 && (
                    <Chip size="small" label={`${segment.importantCount} signal`} color="warning" variant="outlined" sx={{ height: 22 }} />
                  )}
                </Stack>
                {segment.sampleLabels.length > 0 && (
                  <Stack spacing={0.5}>
                    {segment.sampleLabels.slice(0, 4).map((label, index) => (
                      <Typography key={`${segment.key}:${index}:${label}`} variant="caption" color="text.secondary" sx={{ wordBreak: 'break-word' }}>
                        {label}
                      </Typography>
                    ))}
                  </Stack>
                )}
              </>
            )}
            {triageSignals.length > 0 && (
              <>
                <Divider />
                <Typography variant="caption" color="text.secondary" fontWeight={700}>
                  Triage Queue
                </Typography>
                <Stack spacing={0.75}>
                  {triageSignals.map((signal) => {
                    const color = colorForKind(signal.node.kind);
                    return (
                      <Button
                        key={signal.node.id}
                        size="small"
                        variant="outlined"
                        onClick={() => onNodeSelect(signal.node.id)}
                        sx={{
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          gap: 1,
                          minHeight: 42,
                          borderColor: alpha(color, 0.3),
                          color: 'text.primary',
                        }}
                      >
                        <Box component="span" sx={{ minWidth: 0, textAlign: 'left' }}>
                          <Typography component="span" variant="caption" fontWeight={700} sx={{ display: 'block', lineHeight: 1.2 }}>
                            {signal.node.label}
                          </Typography>
                          <Typography component="span" variant="caption" color="text.secondary" sx={{ display: 'block', lineHeight: 1.2 }}>
                            {signal.reason}
                          </Typography>
                        </Box>
                        <Chip
                          size="small"
                          label={signal.node.kind.replace(/_group$/, '')}
                          sx={{
                            height: 20,
                            maxWidth: 84,
                            bgcolor: alpha(color, 0.14),
                            color,
                            '& .MuiChip-label': { px: 0.6, overflow: 'hidden', textOverflow: 'ellipsis' },
                          }}
                        />
                      </Button>
                    );
                  })}
                </Stack>
              </>
            )}
            {prioritySegments.length > 0 && (
              <>
                <Divider />
                <Typography variant="caption" color="text.secondary" fontWeight={700}>
                  Priority Areas
                </Typography>
                <Stack spacing={0.75}>
                  {prioritySegments.map((candidate) => (
                    <Button
                      key={candidate.key}
                      size="small"
                      variant={segment?.key === candidate.key && lens === 'segment' ? 'contained' : 'outlined'}
                      onClick={() => onSegmentSelect(candidate.key)}
                      sx={{
                        justifyContent: 'space-between',
                        gap: 1,
                        minHeight: 38,
                        borderColor: alpha(candidate.color, 0.32),
                        color: segment?.key === candidate.key && lens === 'segment' ? undefined : 'text.primary',
                      }}
                    >
                      <Box component="span" sx={{ minWidth: 0, textAlign: 'left' }}>
                        <Typography component="span" variant="caption" fontWeight={700} sx={{ display: 'block' }}>
                          {candidate.label}
                        </Typography>
                        <Typography component="span" variant="caption" color="text.secondary" sx={{ display: 'block' }}>
                          {candidate.nodeCount} nodes / {candidate.edgeCount} links
                        </Typography>
                      </Box>
                      {candidate.importantCount > 0 && (
                        <Chip
                          size="small"
                          label={`${candidate.importantCount}`}
                          sx={{
                            height: 20,
                            minWidth: 26,
                            bgcolor: alpha(theme.palette.warning.main, 0.14),
                            color: theme.palette.warning.main,
                          }}
                        />
                      )}
                    </Button>
                  ))}
                </Stack>
              </>
            )}
            {nodeKinds && (
              <>
                <Divider />
                <Typography variant="caption" color="text.secondary" fontWeight={700}>
                  Map Contents
                </Typography>
                <Stack direction="row" flexWrap="wrap" gap={0.75}>
                  {Object.entries(nodeKinds).map(([kind, count]) => (
                    <Chip key={kind} size="small" label={`${kind} ${count}`} variant="outlined" sx={{ height: 22 }} />
                  ))}
                </Stack>
              </>
            )}
          </Stack>
        )}
      </Box>
    </Paper>
  );
};

const InfoLine: FC<{ label: string; value: string }> = ({ label, value }) => (
  <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 1 }}>
    <Typography variant="caption" color="text.secondary">{label}</Typography>
    <Typography variant="caption" sx={{ textAlign: 'right', wordBreak: 'break-all' }}>{value}</Typography>
  </Box>
);

function layoutGraph(
  graph: AnalysisGraphPayload | InvestigationGraphPayload,
  mode: GraphMode,
  lens: GraphLens,
): { nodes: PositionedNode[]; edges: ExplorerGraphEdge[]; bounds: { minX: number; minY: number; width: number; height: number } } {
  if (lens === 'overview' && graph.nodes.every((node) => node.kind === 'segment')) {
    return layoutOverviewRegions(graph, mode);
  }

  const order = mode === 'findings' ? FINDING_ORDER : JOURNEY_ORDER;
  const lanes = new Map<string, ExplorerGraphNode[]>();

  const cappedNodes = graph.nodes.slice(0, 220);
  for (const node of cappedNodes) {
    const contextPrefix = node.properties.map_context === true ? 'context:' : '';
    const key = node.kind === 'segment' ? String(node.properties.segment_key ?? node.label) : `${contextPrefix}${node.kind}`;
    const lane = lanes.get(key) ?? [];
    lane.push(node);
    lanes.set(key, lane);
  }

  const laneKeys = Array.from(lanes.keys()).sort((a, b) => {
    const aKind = a.replace(/^context:/, '');
    const bKind = b.replace(/^context:/, '');
    const ai = order.indexOf(aKind);
    const bi = order.indexOf(bKind);
    const contextDelta = Number(a.startsWith('context:')) - Number(b.startsWith('context:'));
    if (contextDelta !== 0) return contextDelta;
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi) || a.localeCompare(b);
  });

  const positioned: PositionedNode[] = [];
  laneKeys.forEach((kind, laneIndex) => {
    const lane = lanes.get(kind) ?? [];
    const laneKind = kind.replace(/^context:/, '');
    const laneLabel = kind.startsWith('context:') ? `Context / ${titleCase(laneKind)}` : titleCase(laneKind);
    const laneColor = kind.startsWith('context:') ? '#94a3b8' : colorForKind(laneKind);
    lane
      .slice()
      .sort((a, b) => {
        const at = a.timestamp ?? a.address ?? a.label;
        const bt = b.timestamp ?? b.address ?? b.label;
        return String(at).localeCompare(String(bt));
      })
      .forEach((node, index) => {
        const isSegment = node.kind === 'segment';
        const isAggregate = isAggregateNode(node);
        const nodeWidth = isSegment ? SEGMENT_W : isAggregate ? 214 : NODE_W;
        const nodeHeight = isSegment ? SEGMENT_H : isAggregate ? 92 : NODE_H;
        const wrap = isSegment ? 3 : isAggregate ? 5 : mode === 'findings' ? 7 : 9;
        const row = Math.floor(index / wrap);
        const col = index % wrap;
        positioned.push({
          ...node,
          width: nodeWidth,
          height: nodeHeight,
          x: 40 + col * (isSegment ? SEGMENT_W + 64 : isAggregate ? 246 : COL_W) + (row % 2) * (isSegment || isAggregate ? 0 : 48),
          y: 36 + laneIndex * (isSegment ? SEGMENT_H + 34 : isAggregate ? 150 : LANE_H) + row * (nodeHeight + 22),
          lane: laneIndex,
          laneLabel,
          laneColor,
        });
      });
  });

  const nodeIds = new Set(positioned.map((node) => node.id));
  const edges = graph.edges.filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target)).slice(0, 500);
  const maxX = positioned.reduce((value, node) => Math.max(value, node.x + node.width), 900);
  const maxY = positioned.reduce((value, node) => Math.max(value, node.y + node.height), 520);

  return {
    nodes: positioned,
    edges,
    bounds: {
      minX: 0,
      minY: 0,
      width: maxX + 80,
      height: maxY + 80,
    },
  };
}

function layoutOverviewRegions(
  graph: AnalysisGraphPayload | InvestigationGraphPayload,
  mode: GraphMode,
): { nodes: PositionedNode[]; edges: ExplorerGraphEdge[]; bounds: { minX: number; minY: number; width: number; height: number } } {
  const positions = mode === 'findings' ? FINDINGS_REGION_POSITIONS : JOURNEY_REGION_POSITIONS;
  const fallbackKeys = Object.keys(positions);
  const positioned: PositionedNode[] = graph.nodes.map((node, index) => {
    const segmentKey = typeof node.properties.segment_key === 'string' ? node.properties.segment_key : fallbackKeys[index % fallbackKeys.length];
    const position = positions[segmentKey] ?? {
      x: 80 + (index % 4) * (SEGMENT_W + 72),
      y: 80 + Math.floor(index / 4) * (SEGMENT_H + 58),
    };
    return {
      ...node,
      width: SEGMENT_W,
      height: SEGMENT_H,
      x: position.x,
      y: position.y,
      lane: index,
      laneLabel: node.label,
      laneColor: typeof node.properties.color === 'string' ? node.properties.color : colorForKind(node.kind),
    };
  });
  const nodeIds = new Set(positioned.map((node) => node.id));
  const edges = graph.edges.filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target));
  const maxX = positioned.reduce((value, node) => Math.max(value, node.x + node.width), 900);
  const maxY = positioned.reduce((value, node) => Math.max(value, node.y + node.height), 520);

  return {
    nodes: positioned,
    edges,
    bounds: {
      minX: 0,
      minY: 0,
      width: maxX + 90,
      height: maxY + 90,
    },
  };
}

function buildLaneBands(nodes: PositionedNode[]): Array<{ lane: number; label: string; color: string; y: number; height: number }> {
  const bands = new Map<number, { lane: number; label: string; color: string; minY: number; maxY: number }>();
  for (const node of nodes) {
    const band = bands.get(node.lane) ?? {
      lane: node.lane,
      label: node.laneLabel,
      color: node.laneColor,
      minY: node.y,
      maxY: node.y + node.height,
    };
    band.minY = Math.min(band.minY, node.y);
    band.maxY = Math.max(band.maxY, node.y + node.height);
    bands.set(node.lane, band);
  }
  return Array.from(bands.values())
    .sort((a, b) => a.lane - b.lane)
    .map((band) => ({
      lane: band.lane,
      label: band.label,
      color: band.color,
      y: band.minY,
      height: band.maxY - band.minY,
    }));
}

function buildSegments(
  graph: AnalysisGraphPayload | InvestigationGraphPayload,
  mode: GraphMode,
): GraphSegment[] {
  const segmentsByKey = new Map<string, GraphSegment>();

  for (const node of graph.nodes) {
    const meta = segmentMeta(mode, node.kind);
    const segment = segmentsByKey.get(meta.key) ?? {
      key: meta.key,
      label: meta.label,
      color: meta.color,
      order: meta.order,
      kinds: new Set<string>(),
      nodeIds: new Set<string>(),
      nodeCount: 0,
      edgeCount: 0,
      sampleLabels: [],
      importantCount: 0,
    };
    segment.kinds.add(node.kind);
    segment.nodeIds.add(node.id);
    segment.nodeCount += 1;
    if (segment.sampleLabels.length < 4 && isUsefulSample(node)) {
      segment.sampleLabels.push(node.label);
    }
    if (isImportantNode(node)) {
      segment.importantCount += 1;
    }
    segmentsByKey.set(meta.key, segment);
  }

  for (const edge of graph.edges) {
    for (const segment of segmentsByKey.values()) {
      if (segment.nodeIds.has(edge.source) || segment.nodeIds.has(edge.target)) {
        segment.edgeCount += 1;
      }
    }
  }

  return Array.from(segmentsByKey.values()).sort((a, b) => a.order - b.order || a.label.localeCompare(b.label));
}

function buildOverviewGraph(
  graph: AnalysisGraphPayload | InvestigationGraphPayload,
  segments: GraphSegment[],
  mode: GraphMode,
  density: MapDensity,
): AnalysisGraphPayload | InvestigationGraphPayload {
  const nodeToSegment = new Map<string, GraphSegment>();
  for (const segment of segments) {
    for (const nodeId of segment.nodeIds) {
      nodeToSegment.set(nodeId, segment);
    }
  }

  const edgeCounts = new Map<string, { source: string; target: string; count: number; kinds: Set<string>; guide?: boolean }>();
  for (const edge of graph.edges) {
    const sourceSegment = nodeToSegment.get(edge.source);
    const targetSegment = nodeToSegment.get(edge.target);
    if (!sourceSegment || !targetSegment || sourceSegment.key === targetSegment.key) continue;
    const edgeKey = `${sourceSegment.key}->${targetSegment.key}`;
    const current = edgeCounts.get(edgeKey) ?? {
      source: `segment:${sourceSegment.key}`,
      target: `segment:${targetSegment.key}`,
      count: 0,
      kinds: new Set<string>(),
    };
    current.count += 1;
    current.kinds.add(edge.kind);
    edgeCounts.set(edgeKey, current);
  }

  const actualEdges = Array.from(edgeCounts.entries()).sort(([, left], [, right]) => (
    right.count - left.count
    || left.source.localeCompare(right.source)
    || left.target.localeCompare(right.target)
  ));
  const visibleActualEdges = density === 'calm'
    ? []
    : density === 'linked'
    ? actualEdges.slice(0, 8)
    : actualEdges.slice(0, 32);
  const visibleEdgeCounts = new Map<string, { source: string; target: string; count: number; kinds: Set<string>; guide?: boolean }>(visibleActualEdges);

  const segmentKeys = new Set(segments.map((segment) => segment.key));
  for (const [sourceKey, targetKey] of overviewGuidePairs(mode)) {
    if (!segmentKeys.has(sourceKey) || !segmentKeys.has(targetKey)) continue;
    const edgeKey = `${sourceKey}->${targetKey}`;
    if (visibleEdgeCounts.has(edgeKey)) continue;
    visibleEdgeCounts.set(edgeKey, {
      source: `segment:${sourceKey}`,
      target: `segment:${targetKey}`,
      count: 0,
      kinds: new Set(['route']),
      guide: true,
    });
  }

  const nodes: ExplorerGraphNode[] = segments.map((segment) => ({
    id: `segment:${segment.key}`,
    kind: 'segment',
    label: segment.label,
    properties: {
      segment_key: segment.key,
      color: segment.color,
      node_count: segment.nodeCount,
      edge_count: segment.edgeCount,
      kinds: Array.from(segment.kinds).sort().join(', '),
      samples: segment.sampleLabels,
      important_count: segment.importantCount,
      mode,
      density,
    },
  }));

  const edges: ExplorerGraphEdge[] = Array.from(visibleEdgeCounts.entries()).map(([key, edge]) => ({
    id: `segment-edge:${key}`,
    kind: edge.guide ? 'route' : `${edge.count} links`,
    source: edge.source,
    target: edge.target,
    confidence: 1,
    properties: {
      edge_count: edge.count,
      kinds: Array.from(edge.kinds).sort(),
      guide: edge.guide === true,
      density,
    },
  }));

  return {
    ...graph,
    nodes,
    edges,
    summary: {
      ...graph.summary,
      node_count: nodes.length,
      edge_count: edges.length,
      segment_count: segments.length,
      lens: 'overview',
      map_density: density,
      actual_cross_segment_routes: actualEdges.length,
      visible_cross_segment_routes: visibleActualEdges.length,
    },
  };
}

function buildSegmentGraph(
  graph: AnalysisGraphPayload | InvestigationGraphPayload,
  segments: GraphSegment[],
  segmentKey: string | null,
): AnalysisGraphPayload | InvestigationGraphPayload {
  const segment = segments.find((candidate) => candidate.key === segmentKey) ?? segments[0];
  if (!segment) return graph;

  const focusIds = segment.nodeIds;
  const contextIds = new Set<string>(focusIds);
  for (const edge of graph.edges) {
    if (focusIds.has(edge.source) || focusIds.has(edge.target)) {
      contextIds.add(edge.source);
      contextIds.add(edge.target);
    }
  }

  const focusNodes = graph.nodes
    .filter((node) => focusIds.has(node.id))
    .sort(compareGraphNodes)
    .map((node) => ({
      ...node,
      properties: { ...node.properties, map_focus: true, map_segment: segment.key },
    }));
  const contextNodes = graph.nodes
    .filter((node) => contextIds.has(node.id) && !focusIds.has(node.id))
    .sort(compareGraphNodes)
    .slice(0, 28)
    .map((node) => ({
      ...node,
      properties: { ...node.properties, map_context: true, map_segment: segment.key },
    }));
  const compacted = compactSegmentGraph(focusNodes, contextNodes, graph.edges, segment.key);

  return {
    ...graph,
    nodes: compacted.nodes,
    edges: compacted.edges,
    summary: {
      ...graph.summary,
      node_count: compacted.nodes.length,
      edge_count: compacted.edges.length,
      lens: 'segment',
      segment_key: segment.key,
      segment_label: segment.label,
      grouped_node_count: compacted.groupedNodeCount,
      aggregate_count: compacted.aggregateCount,
      omitted_nodes: Math.max(0, segment.nodeCount - compacted.representedFocusCount),
    },
  };
}

function compactSegmentGraph(
  focusNodes: ExplorerGraphNode[],
  contextNodes: ExplorerGraphNode[],
  sourceEdges: ExplorerGraphEdge[],
  segmentKey: string,
): {
  nodes: ExplorerGraphNode[];
  edges: ExplorerGraphEdge[];
  groupedNodeCount: number;
  aggregateCount: number;
  representedFocusCount: number;
} {
  const buckets = new Map<string, ExplorerGraphNode[]>();
  const bucketLabels = new Map<string, string>();

  for (const node of focusNodes) {
    const bucket = aggregateBucket(node);
    if (!bucket) continue;
    const list = buckets.get(bucket.key) ?? [];
    list.push(node);
    buckets.set(bucket.key, list);
    bucketLabels.set(bucket.key, bucket.label);
  }

  const groupedNodeIds = new Map<string, string>();
  const aggregateNodes: ExplorerGraphNode[] = [];
  for (const [bucketKey, nodes] of buckets.entries()) {
    if (nodes.length < aggregateThreshold(nodes[0])) continue;
    const groupId = `aggregate:${safeId(segmentKey)}:${safeId(bucketKey)}`;
    const samples = nodes
      .map((node) => node.label)
      .filter((label, index, labels) => label && labels.indexOf(label) === index)
      .slice(0, 8);
    const importantCount = nodes.filter(isImportantNode).length;
    const groupedKind = nodes[0].kind;
    for (const node of nodes) {
      groupedNodeIds.set(node.id, groupId);
    }
    aggregateNodes.push({
      id: groupId,
      kind: `${groupedKind}_group`,
      label: bucketLabels.get(bucketKey) ?? `${titleCase(groupedKind)} group`,
      source: nodes[0].source,
      properties: {
        aggregate: true,
        grouped_kind: groupedKind,
        group_key: bucketKey,
        group_count: nodes.length,
        important_count: importantCount,
        samples,
        sample_ids: nodes.slice(0, 12).map((node) => node.id),
        map_focus: true,
        map_segment: segmentKey,
      },
    });
  }

  const individualFocusNodes = focusNodes.filter((node) => !groupedNodeIds.has(node.id));
  const compactFocusNodes = [...aggregateNodes, ...individualFocusNodes]
    .sort(compareGraphNodes)
    .slice(0, 96);
  const compactFocusIds = new Set(compactFocusNodes.map((node) => node.id));
  const visibleOriginalToNode = new Map<string, string>();

  for (const node of focusNodes) {
    const groupId = groupedNodeIds.get(node.id);
    if (groupId && compactFocusIds.has(groupId)) {
      visibleOriginalToNode.set(node.id, groupId);
    } else if (compactFocusIds.has(node.id)) {
      visibleOriginalToNode.set(node.id, node.id);
    }
  }

  const compactContextNodes = contextNodes.slice(0, 28);
  const contextIds = new Set(compactContextNodes.map((node) => node.id));
  for (const node of compactContextNodes) {
    visibleOriginalToNode.set(node.id, node.id);
  }

  const edgesByKey = new Map<string, ExplorerGraphEdge>();
  for (const edge of sourceEdges) {
    const source = visibleOriginalToNode.get(edge.source);
    const target = visibleOriginalToNode.get(edge.target);
    if (!source || !target || source === target) continue;
    if (!compactFocusIds.has(source) && !compactFocusIds.has(target) && !(contextIds.has(source) && contextIds.has(target))) {
      continue;
    }
    const key = `${source}->${target}:${edge.kind}`;
    const existing = edgesByKey.get(key);
    if (existing) {
      existing.properties = {
        ...existing.properties,
        edge_count: Number(existing.properties.edge_count ?? 1) + 1,
      };
      continue;
    }
    edgesByKey.set(key, {
      ...edge,
      id: `compact-edge:${safeId(key)}`,
      source,
      target,
      properties: {
        ...edge.properties,
        edge_count: 1,
        compacted: true,
      },
    });
  }

  const representedFocusCount = focusNodes.filter((node) => visibleOriginalToNode.has(node.id)).length;
  return {
    nodes: [...compactFocusNodes, ...compactContextNodes],
    edges: Array.from(edgesByKey.values()).slice(0, 260),
    groupedNodeCount: groupedNodeIds.size,
    aggregateCount: aggregateNodes.length,
    representedFocusCount,
  };
}

function overviewGuidePairs(mode: GraphMode): Array<[string, string]> {
  if (mode === 'journey') {
    return [
      ['subject', 'actors'],
      ['actors', 'actions'],
      ['actions', 'artifacts'],
      ['actions', 'tools'],
    ];
  }

  return [
    ['subject', 'artifacts'],
    ['subject', 'code'],
    ['artifacts', 'code'],
    ['code', 'behavior'],
    ['behavior', 'findings'],
    ['artifacts', 'findings'],
    ['code', 'tools'],
    ['tools', 'findings'],
  ];
}

function aggregateBucket(node: ExplorerGraphNode): { key: string; label: string } | null {
  if (isAggregateNode(node) || node.properties.map_context === true) return null;
  const text = `${node.kind} ${node.label} ${JSON.stringify(node.properties ?? {})}`.toLowerCase();

  if (['embedded_artifact', 'artifact_analysis', 'artifact', 'graph_artifact'].includes(node.kind)) {
    const signature = String(node.properties.kind ?? node.properties.carved_signature ?? node.label ?? 'artifact');
    return {
      key: `${node.kind}:${normalizeBucketValue(signature)}`,
      label: `${titleCase(signature.replace(/_/g, ' '))} artifacts`,
    };
  }

  if (node.kind === 'string') {
    if (/https?:\/\/|ftp:\/\/|tftp|telnet|ssh|dropbear|dns|socket|host/.test(text)) {
      return { key: 'string:network', label: 'Network strings' };
    }
    if (/password|passwd|token|secret|credential|auth|login|admin|root|private key/.test(text)) {
      return { key: 'string:credentials', label: 'Credential strings' };
    }
    if (/ssl|tls|crypto|certificate|cert|rsa|aes|sha256|md5|key/.test(text)) {
      return { key: 'string:crypto', label: 'Crypto strings' };
    }
    if (/\/etc\/|\/bin\/|\/sbin\/|\/usr\/|\/tmp\/|busybox|init.d|rc.d|shell|sh /.test(text)) {
      return { key: 'string:filesystem-shell', label: 'Filesystem and shell strings' };
    }
    if (/firmware|upgrade|update|flash|boot|mtd|ubi|squashfs|kernel/.test(text)) {
      return { key: 'string:firmware-update', label: 'Firmware/update strings' };
    }
    return { key: 'string:other', label: 'Other strings' };
  }

  if (node.kind === 'import') {
    if (/malloc|free|memcpy|memmove|strcpy|strncpy|sprintf|snprintf|gets|scanf/.test(text)) {
      return { key: 'import:memory', label: 'Memory and string APIs' };
    }
    if (/system|exec|popen|fork|spawn|shell|cmd/.test(text)) {
      return { key: 'import:process', label: 'Process execution APIs' };
    }
    if (/socket|connect|bind|listen|accept|send|recv|http|curl|dns/.test(text)) {
      return { key: 'import:network', label: 'Network APIs' };
    }
    if (/ssl|tls|crypto|aes|rsa|sha|md5|x509/.test(text)) {
      return { key: 'import:crypto', label: 'Crypto APIs' };
    }
    if (/open|read|write|stat|chmod|unlink|rename|mount/.test(text)) {
      return { key: 'import:filesystem', label: 'Filesystem APIs' };
    }
    return { key: 'import:other', label: 'Other imports' };
  }

  if (node.kind === 'function') {
    if (/^(fun_|sub_|entry|thunk_)/i.test(node.label)) {
      return { key: 'function:auto', label: 'Auto-named functions' };
    }
    if (/parse|decode|decrypt|auth|login|update|flash|http|socket|memcpy|strcpy|system/i.test(node.label)) {
      return { key: 'function:security-interesting', label: 'Security-relevant functions' };
    }
  }

  if (node.kind === 'basic_block') {
    return { key: `basic_block:${String(node.source ?? 'unknown')}`, label: 'Basic blocks' };
  }

  return null;
}

function aggregateThreshold(node: ExplorerGraphNode): number {
  if (['embedded_artifact', 'artifact_analysis', 'artifact', 'graph_artifact'].includes(node.kind)) return 3;
  if (node.kind === 'string') return 6;
  if (node.kind === 'import') return 4;
  if (node.kind === 'function') return 8;
  if (node.kind === 'basic_block') return 12;
  return 5;
}

function normalizeBucketValue(value: string): string {
  return value.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'unknown';
}

function safeId(value: string): string {
  return normalizeBucketValue(value).slice(0, 96);
}

function isAggregateNode(node: ExplorerGraphNode): boolean {
  return node.properties.aggregate === true || node.kind.endsWith('_group');
}

function compareGraphNodes(a: ExplorerGraphNode, b: ExplorerGraphNode): number {
  const importantDelta = Number(isImportantNode(b)) - Number(isImportantNode(a));
  if (importantDelta !== 0) return importantDelta;
  const aggregateDelta = Number(isAggregateNode(b)) - Number(isAggregateNode(a));
  if (aggregateDelta !== 0) return aggregateDelta;
  const countDelta = Number(b.properties.group_count ?? 1) - Number(a.properties.group_count ?? 1);
  if (countDelta !== 0) return countDelta;
  const ak = `${a.address ?? a.timestamp ?? a.source ?? ''} ${a.label}`;
  const bk = `${b.address ?? b.timestamp ?? b.source ?? ''} ${b.label}`;
  return ak.localeCompare(bk);
}

function isUsefulSample(node: ExplorerGraphNode): boolean {
  if (!node.label || node.label === node.kind) return false;
  if (['tool', 'basic_block'].includes(node.kind)) return false;
  return true;
}

function isImportantNode(node: ExplorerGraphNode): boolean {
  if (isAggregateNode(node)) {
    return Number(node.properties.important_count ?? 0) > 0;
  }
  const text = `${node.kind} ${node.label} ${JSON.stringify(node.properties ?? {})}`.toLowerCase();
  if (node.kind === 'issue') return true;
  if (['embedded_artifact', 'artifact_analysis'].includes(node.kind)) {
    return /credential|private key|certificate|elf|filesystem|squashfs|ubi|uimage|device_tree|compressed/.test(text);
  }
  if (node.kind === 'import') {
    return /malloc|free|strcpy|sprintf|system|exec|socket|http|crypto|ssl|tls/.test(text);
  }
  if (node.kind === 'string') {
    return /http|https|password|passwd|token|key|secret|telnet|dropbear|busybox|admin|root|update|firmware/.test(text);
  }
  if (node.kind === 'function') {
    return /main|parse|decode|decrypt|auth|login|update|flash|http|socket|memcpy|strcpy|system/.test(text);
  }
  return false;
}

function collectMapSignals(nodes: ExplorerGraphNode[]): MapSignal[] {
  const deduped = new Map<string, MapSignal>();
  for (const node of nodes) {
    const score = mapSignalScore(node);
    if (score <= 0) continue;
    const existing = deduped.get(node.id);
    if (!existing || score > existing.score) {
      deduped.set(node.id, {
        node,
        score,
        reason: mapSignalReason(node),
      });
    }
  }
  return Array.from(deduped.values()).sort((a, b) => b.score - a.score || a.node.label.localeCompare(b.node.label));
}

function mapSignalScore(node: ExplorerGraphNode): number {
  const text = `${node.kind} ${node.label} ${JSON.stringify(node.properties ?? {})}`.toLowerCase();
  const groupCount = Number(node.properties.group_count ?? 0);
  const importantCount = Number(node.properties.important_count ?? 0);
  let score = 0;

  if (node.kind === 'issue') score += 110;
  if (isImportantNode(node)) score += 70;
  if (isAggregateNode(node)) score += 35 + Math.min(35, Math.log2(groupCount + 1) * 8) + importantCount * 12;
  if (node.address) score += 8;
  if (/credential|password|passwd|secret|private key|token|admin|root/.test(text)) score += 42;
  if (/telnet|dropbear|ssh|http|https|socket|dns|tftp/.test(text)) score += 28;
  if (/squashfs|ubi|uimage|filesystem|kernel|firmware|update|flash|boot|mtd/.test(text)) score += 26;
  if (/strcpy|sprintf|system|exec|popen|memcpy|malloc|free/.test(text)) score += 24;
  if (node.properties.map_focus === true) score += 10;
  if (node.properties.map_context === true) score -= 18;

  return score;
}

function mapSignalReason(node: ExplorerGraphNode): string {
  const text = `${node.kind} ${node.label} ${JSON.stringify(node.properties ?? {})}`.toLowerCase();
  const groupCount = Number(node.properties.group_count ?? 0);
  const importantCount = Number(node.properties.important_count ?? 0);

  if (node.kind === 'issue') return 'confirmed finding';
  if (importantCount > 0) return `${importantCount} high-signal item${importantCount === 1 ? '' : 's'} grouped`;
  if (groupCount > 0) return `${groupCount} related item${groupCount === 1 ? '' : 's'} grouped`;
  if (/credential|password|passwd|secret|private key|token|admin|root/.test(text)) return 'credential or privilege signal';
  if (/telnet|dropbear|ssh|http|https|socket|dns|tftp/.test(text)) return 'network-facing signal';
  if (/squashfs|ubi|uimage|filesystem|kernel|firmware|update|flash|boot|mtd/.test(text)) return 'firmware structure signal';
  if (/strcpy|sprintf|system|exec|popen|memcpy|malloc|free/.test(text)) return 'dangerous API or code pivot';
  if (node.address) return `address ${node.address}`;
  return 'interesting graph node';
}

function segmentMeta(mode: GraphMode, kind: string): { key: string; label: string; color: string; order: number } {
  if (mode === 'journey') {
    if (['session', 'subject'].includes(kind)) {
      return { key: 'subject', label: 'Subject', color: '#3b82f6', order: 0 };
    }
    if (['actor'].includes(kind)) {
      return { key: 'actors', label: 'Actors', color: '#f97316', order: 1 };
    }
    if (['human_action', 'tool_action', 'message'].includes(kind)) {
      return { key: 'actions', label: 'Actions', color: '#22c55e', order: 2 };
    }
    if (['artifact', 'graph_artifact', 'address'].includes(kind)) {
      return { key: 'artifacts', label: 'Artifacts', color: '#0ea5e9', order: 3 };
    }
    if (kind === 'tool') {
      return { key: 'tools', label: 'Tools', color: '#64748b', order: 4 };
    }
    return { key: kind, label: titleCase(kind), color: colorForKind(kind), order: 20 };
  }

  if (['binary', 'profile', 'firmware_profile', 'mitigation_profile'].includes(kind)) {
    return { key: 'subject', label: 'Subject', color: '#3b82f6', order: 0 };
  }
  if (['section', 'section_group', 'function', 'function_group', 'basic_block', 'basic_block_group', 'decompilation', 'type'].includes(kind)) {
    return { key: 'code', label: 'Code', color: '#22c55e', order: 1 };
  }
  if (['import', 'import_group', 'string', 'string_group'].includes(kind)) {
    return { key: 'behavior', label: 'Behavior', color: '#f59e0b', order: 2 };
  }
  if ([
    'embedded_artifact',
    'embedded_artifact_group',
    'artifact_analysis',
    'artifact_analysis_group',
    'artifact',
    'artifact_group',
    'graph_artifact',
    'graph_artifact_group',
  ].includes(kind)) {
    return { key: 'artifacts', label: 'Artifacts', color: '#0ea5e9', order: 3 };
  }
  if (kind === 'tool') {
    return { key: 'tools', label: 'Tools', color: '#64748b', order: 4 };
  }
  if (kind === 'issue') {
    return { key: 'findings', label: 'Findings', color: '#ef4444', order: 5 };
  }
  return { key: kind, label: titleCase(kind), color: colorForKind(kind), order: 20 };
}

function titleCase(value: string): string {
  return value
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((part) => part.slice(0, 1).toUpperCase() + part.slice(1))
    .join(' ');
}

export default GraphExplorer;
