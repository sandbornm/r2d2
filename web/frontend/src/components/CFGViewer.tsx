import AccountTreeIcon from '@mui/icons-material/AccountTree';
import AutoFixHighIcon from '@mui/icons-material/AutoFixHigh';
import ChatBubbleOutlineIcon from '@mui/icons-material/ChatBubbleOutline';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';
import CloseFullscreenIcon from '@mui/icons-material/CloseFullscreen';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import EditIcon from '@mui/icons-material/Edit';
import FitScreenIcon from '@mui/icons-material/FitScreen';
import FullscreenIcon from '@mui/icons-material/Fullscreen';
import NavigateBeforeIcon from '@mui/icons-material/NavigateBefore';
import NavigateNextIcon from '@mui/icons-material/NavigateNext';
import ZoomInIcon from '@mui/icons-material/ZoomIn';
import ZoomOutIcon from '@mui/icons-material/ZoomOut';
import debug from '../debug';
import { useActivity } from '../contexts/ActivityContext';
import {
  alpha,
  Box,
  Chip,
  CircularProgress,
  IconButton,
  keyframes,
  List,
  ListItemButton,
  ListItemText,
  Paper,
  Stack,
  TextField,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import type { FunctionName, FunctionNameSuggestion } from '../types';
import { FC, memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';

// Smooth fade-in animation
const fadeIn = keyframes`
  from { opacity: 0; transform: translateY(4px); }
  to { opacity: 1; transform: translateY(0); }
`;

// Pulse animation for empty state
const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.6; }
`;

interface CFGNode {
  addr: string;
  size?: number | null;
  function?: string | null;
  function_name?: string | null;
  instruction_count?: number;
  disassembly?: Array<{
    addr: string;
    mnemonic?: string;
    op_str?: string;
    opcode?: string;
    bytes?: string;
  }>;
}

interface CFGEdge {
  source: string;
  target: string;
  type?: string;
}

interface FunctionCFG {
  name: string;
  offset: string;
  size: number;
  block_count?: number;
  blocks?: Array<{
    offset?: string | null;
    size?: number;
    jump?: string | null;
    fail?: string | null;
    disassembly?: Array<{
      addr: string;
      bytes?: string;
      opcode?: string;
    }>;
    ops?: Array<{
      offset?: number;
      esil?: string;
      opcode?: string;
      bytes?: string;
    }>;
  }>;
}

// Graph node for layout
interface GraphNode {
  id: string;
  x: number;
  y: number;
  width: number;
  height: number;
  label: string;
  instructions: Array<{ addr: string; opcode: string }>;
  isEntry?: boolean;
  jumpTarget?: string | null;
  failTarget?: string | null;
}

// Graph edge for layout
interface GraphEdge {
  source: string;
  target: string;
  type: 'jump' | 'fall' | 'call';
}

// Context for Ask Claude feature
export interface CFGContext {
  functionName: string | null;
  functionOffset: string | null;
  selectedBlock: string | null;
  blockAssembly: Array<{ addr: string; opcode?: string }> | null;
  visibleBlocks: Array<{
    offset: string | null;
    disassembly?: Array<{ addr: string; opcode?: string }>;
  }>;
}

interface CFGViewerProps {
  nodes: CFGNode[];
  edges: CFGEdge[];
  functions?: FunctionCFG[];
  angrActive?: number;
  angrFound?: number;
  onAskAboutCFG?: (context: CFGContext) => void;
  sessionId?: string | null;
}

// Simple hierarchical layout for CFG
const layoutGraph = (
  blocks: Array<{
    offset?: string | null;
    size?: number;
    jump?: string | null;
    fail?: string | null;
    disassembly?: Array<{ addr: string; opcode?: string }>;
    ops?: Array<{ offset?: number; opcode?: string }>;
  }>,
  entryOffset: string
): { nodes: GraphNode[]; edges: GraphEdge[] } => {
  const nodeWidth = 200;
  const nodeMinHeight = 60;
  const lineHeight = 16;
  const horizontalGap = 60;
  const verticalGap = 40;

  // Build adjacency map
  const blockMap = new Map<string, typeof blocks[0]>();
  const incomingEdges = new Map<string, Set<string>>();
  const outgoingEdges = new Map<string, Set<string>>();

  for (const block of blocks) {
    const offset = block.offset;
    if (!offset) continue;
    blockMap.set(offset, block);
    if (!incomingEdges.has(offset)) incomingEdges.set(offset, new Set());
    if (!outgoingEdges.has(offset)) outgoingEdges.set(offset, new Set());

    // Add edges
    if (block.jump) {
      outgoingEdges.get(offset)!.add(block.jump);
      if (!incomingEdges.has(block.jump)) incomingEdges.set(block.jump, new Set());
      incomingEdges.get(block.jump)!.add(offset);
    }
    if (block.fail) {
      outgoingEdges.get(offset)!.add(block.fail);
      if (!incomingEdges.has(block.fail)) incomingEdges.set(block.fail, new Set());
      incomingEdges.get(block.fail)!.add(offset);
    }
  }

  // Assign levels using BFS from entry
  const levels = new Map<string, number>();
  const queue: string[] = [];
  
  // Find entry block
  let entry = entryOffset;
  if (!blockMap.has(entry)) {
    // Fallback to first block
    entry = blocks[0]?.offset || '';
  }
  if (!entry) return { nodes: [], edges: [] };

  levels.set(entry, 0);
  queue.push(entry);

  while (queue.length > 0) {
    const current = queue.shift()!;
    const currentLevel = levels.get(current) || 0;
    const successors = outgoingEdges.get(current) || new Set();

    for (const succ of successors) {
      if (!levels.has(succ)) {
        levels.set(succ, currentLevel + 1);
        queue.push(succ);
      }
    }
  }

  // Group nodes by level
  const levelGroups = new Map<number, string[]>();
  for (const [nodeId, level] of levels) {
    if (!levelGroups.has(level)) levelGroups.set(level, []);
    levelGroups.get(level)!.push(nodeId);
  }

  // Calculate positions
  const graphNodes: GraphNode[] = [];
  const graphEdges: GraphEdge[] = [];

  const sortedLevels = Array.from(levelGroups.keys()).sort((a, b) => a - b);
  
  for (const level of sortedLevels) {
    const nodesInLevel = levelGroups.get(level) || [];
    const levelWidth = nodesInLevel.length * (nodeWidth + horizontalGap) - horizontalGap;
    const startX = -levelWidth / 2;

    nodesInLevel.forEach((nodeId, idx) => {
      const block = blockMap.get(nodeId);
      if (!block) return;

      // Get disassembly
      const disasm = block.disassembly || [];
      const ops = block.ops || [];
      const instructions = disasm.length > 0
        ? disasm.map(d => ({ addr: d.addr, opcode: d.opcode || '' }))
        : ops.map(op => ({
            addr: typeof op.offset === 'number' ? `0x${op.offset.toString(16)}` : '?',
            opcode: op.opcode || '',
          }));

      const displayInstructions = instructions.slice(0, 6);
      const nodeHeight = Math.max(
        nodeMinHeight,
        40 + displayInstructions.length * lineHeight
      );

      graphNodes.push({
        id: nodeId,
        x: startX + idx * (nodeWidth + horizontalGap),
        y: level * (nodeMinHeight + 80 + verticalGap),
        width: nodeWidth,
        height: nodeHeight,
        label: nodeId,
        instructions: displayInstructions,
        isEntry: nodeId === entry,
        jumpTarget: block.jump || null,
        failTarget: block.fail || null,
      });

      // Add edges
      if (block.jump) {
        graphEdges.push({
          source: nodeId,
          target: block.jump,
          type: 'jump',
        });
      }
      if (block.fail) {
        graphEdges.push({
          source: nodeId,
          target: block.fail,
          type: 'fall',
        });
      }
    });
  }

  return { nodes: graphNodes, edges: graphEdges };
};

// SVG CFG Graph Component
interface CFGGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onNodeClick?: (nodeId: string) => void;
  selectedNode?: string | null;
  isMaximized?: boolean;
  onMaximizeToggle?: () => void;
  onAskAboutCFG?: () => void;
}

const CFGGraphBase: FC<CFGGraphProps> = ({
  nodes,
  edges,
  onNodeClick,
  selectedNode,
  isMaximized,
  onMaximizeToggle,
  onAskAboutCFG,
}) => {
  const theme = useTheme();
  const isDark = theme.palette.mode === 'dark';
  const containerRef = useRef<HTMLDivElement>(null);
  const [viewBox, setViewBox] = useState({ x: 0, y: 0, width: 800, height: 600 });
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });

  // Calculate bounding box
  useEffect(() => {
    if (nodes.length === 0) return;

    const minX = Math.min(...nodes.map(n => n.x)) - 50;
    const maxX = Math.max(...nodes.map(n => n.x + n.width)) + 50;
    const minY = Math.min(...nodes.map(n => n.y)) - 50;
    const maxY = Math.max(...nodes.map(n => n.y + n.height)) + 50;

    setViewBox({
      x: minX,
      y: minY,
      width: maxX - minX,
      height: maxY - minY,
    });
  }, [nodes]);

  const handleZoomIn = useCallback(() => {
    setZoom(z => {
      const newZoom = Math.min(z * 1.2, 3);
      debug.cfg.zoom(newZoom, 'in');
      return newZoom;
    });
  }, []);
  const handleZoomOut = useCallback(() => {
    setZoom(z => {
      const newZoom = Math.max(z / 1.2, 0.3);
      debug.cfg.zoom(newZoom, 'out');
      return newZoom;
    });
  }, []);
  const handleFit = useCallback(() => {
    debug.cfg.zoom(1, 'fit');
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }, []);

  // Mouse wheel zoom
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const factor = e.deltaY > 0 ? 0.9 : 1.1;
    setZoom(z => {
      const newZoom = Math.max(0.3, Math.min(3, z * factor));
      debug.cfg.zoom(newZoom, 'wheel');
      return newZoom;
    });
  }, []);

  // Keyboard shortcuts
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    // Don't handle if in an input field
    if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
      return;
    }

    switch (e.key) {
      case '+':
      case '=':
        e.preventDefault();
        handleZoomIn();
        break;
      case '-':
        e.preventDefault();
        handleZoomOut();
        break;
      case '0':
        e.preventDefault();
        handleFit();
        break;
      case 'Escape':
        if (isMaximized && onMaximizeToggle) {
          e.preventDefault();
          onMaximizeToggle();
        }
        break;
      case '?':
        if (onAskAboutCFG) {
          e.preventDefault();
          onAskAboutCFG();
        }
        break;
    }
  }, [handleZoomIn, handleZoomOut, handleFit, isMaximized, onMaximizeToggle, onAskAboutCFG]);

  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button === 0) {
      setIsPanning(true);
      setPanStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isPanning) {
      const newPan = {
        x: e.clientX - panStart.x,
        y: e.clientY - panStart.y,
      };
      setPan(newPan);

      // Throttle pan logging (only every 100ms)
      const now = Date.now();
      if (now - lastPanLog.current > 100) {
        debug.cfg.pan(newPan.x, newPan.y);
        lastPanLog.current = now;
      }
    }
  };

  const handleMouseUp = () => setIsPanning(false);

  // Build node position map for edge drawing
  const nodePositions = useMemo(() => {
    const map = new Map<string, GraphNode>();
    for (const node of nodes) {
      map.set(node.id, node);
    }
    return map;
  }, [nodes]);

  // Edge path calculation with curved lines
  const getEdgePath = (edge: GraphEdge) => {
    const source = nodePositions.get(edge.source);
    const target = nodePositions.get(edge.target);
    if (!source || !target) return '';

    const sourceX = source.x + source.width / 2;
    const sourceY = source.y + source.height;
    const targetX = target.x + target.width / 2;
    const targetY = target.y;

    // Offset for multiple edges
    const offset = edge.type === 'fall' ? -15 : 15;

    // Simple curved path
    const midY = (sourceY + targetY) / 2;
    return `M ${sourceX} ${sourceY} C ${sourceX + offset} ${midY}, ${targetX + offset} ${midY}, ${targetX} ${targetY}`;
  };

  const colors = {
    nodeBg: isDark ? '#1a1a2e' : '#ffffff',
    nodeBorder: isDark ? '#3a3a5e' : '#d0d0d0',
    nodeSelectedBorder: theme.palette.primary.main,
    entryBorder: theme.palette.success.main,
    jumpEdge: theme.palette.success.main,
    fallEdge: theme.palette.warning.main,
    text: isDark ? '#e0e0e0' : '#333333',
    textSecondary: isDark ? '#888888' : '#666666',
    addrColor: isDark ? '#7eb8da' : '#0066cc',
    mnemonicColor: theme.palette.primary.main,
  };

  if (nodes.length === 0) {
    return (
      <Box
        sx={{
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'text.secondary',
        }}
      >
        <Typography variant="body2">No blocks to display</Typography>
      </Box>
    );
  }

  return (
    <Box
      ref={containerRef}
      tabIndex={0}
      onKeyDown={handleKeyDown}
      onWheel={handleWheel}
      sx={{
        height: '100%',
        position: 'relative',
        overflow: 'hidden',
        bgcolor: isDark ? '#0d0d14' : '#f8f9fa',
        borderRadius: 1,
        outline: 'none',
        '&:focus-visible': {
          boxShadow: `0 0 0 2px ${theme.palette.primary.main}`,
        },
      }}
    >
      {/* Toolbar controls */}
      <Stack
        direction="row"
        spacing={0.5}
        sx={{
          position: 'absolute',
          top: 8,
          right: 8,
          zIndex: 10,
          bgcolor: alpha(colors.nodeBg, 0.95),
          borderRadius: 1,
          p: 0.5,
          boxShadow: 1,
        }}
      >
        {onAskAboutCFG && (
          <Tooltip title="Ask Claude about this code (?)">
            <IconButton size="small" onClick={onAskAboutCFG} color="primary">
              <ChatBubbleOutlineIcon sx={{ fontSize: 18 }} />
            </IconButton>
          </Tooltip>
        )}
        <Box sx={{ width: 1, bgcolor: 'divider', mx: 0.5 }} />
        <Tooltip title="Zoom In (+)">
          <IconButton size="small" onClick={handleZoomIn}>
            <ZoomInIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>
        <Tooltip title="Zoom Out (-)">
          <IconButton size="small" onClick={handleZoomOut}>
            <ZoomOutIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>
        <Tooltip title="Fit to View (0)">
          <IconButton size="small" onClick={handleFit}>
            <FitScreenIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>
        {onMaximizeToggle && (
          <>
            <Box sx={{ width: 1, bgcolor: 'divider', mx: 0.5 }} />
            <Tooltip title={isMaximized ? 'Exit Fullscreen (Esc)' : 'Fullscreen'}>
              <IconButton size="small" onClick={onMaximizeToggle}>
                {isMaximized ? (
                  <CloseFullscreenIcon sx={{ fontSize: 18 }} />
                ) : (
                  <FullscreenIcon sx={{ fontSize: 18 }} />
                )}
              </IconButton>
            </Tooltip>
          </>
        )}
      </Stack>

      {/* SVG Canvas */}
      <svg
        width="100%"
        height="100%"
        viewBox={`${viewBox.x - pan.x / zoom} ${viewBox.y - pan.y / zoom} ${viewBox.width / zoom} ${viewBox.height / zoom}`}
        style={{ cursor: isPanning ? 'grabbing' : 'grab' }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <defs>
          <marker
            id="arrowhead-jump"
            markerWidth="8"
            markerHeight="6"
            refX="8"
            refY="3"
            orient="auto"
          >
            <polygon points="0 0, 8 3, 0 6" fill={colors.jumpEdge} />
          </marker>
          <marker
            id="arrowhead-fall"
            markerWidth="8"
            markerHeight="6"
            refX="8"
            refY="3"
            orient="auto"
          >
            <polygon points="0 0, 8 3, 0 6" fill={colors.fallEdge} />
          </marker>
        </defs>

        {/* Edges */}
        {edges.map((edge, idx) => (
          <path
            key={`edge-${idx}`}
            d={getEdgePath(edge)}
            fill="none"
            stroke={edge.type === 'jump' ? colors.jumpEdge : colors.fallEdge}
            strokeWidth={2}
            strokeDasharray={edge.type === 'fall' ? '5,3' : undefined}
            markerEnd={`url(#arrowhead-${edge.type})`}
            style={{ opacity: 0.8 }}
          />
        ))}

        {/* Nodes */}
        {nodes.map((node) => {
          const isSelected = selectedNode === node.id;
          const borderColor = node.isEntry
            ? colors.entryBorder
            : isSelected
            ? colors.nodeSelectedBorder
            : colors.nodeBorder;

          return (
            <g
              key={node.id}
              onClick={() => onNodeClick?.(node.id)}
              style={{ cursor: 'pointer' }}
            >
              {/* Node background */}
              <rect
                x={node.x}
                y={node.y}
                width={node.width}
                height={node.height}
                rx={4}
                fill={colors.nodeBg}
                stroke={borderColor}
                strokeWidth={isSelected || node.isEntry ? 2 : 1}
              />

              {/* Node header */}
              <rect
                x={node.x}
                y={node.y}
                width={node.width}
                height={24}
                rx={4}
                fill={alpha(borderColor, 0.15)}
              />
              <rect
                x={node.x}
                y={node.y + 20}
                width={node.width}
                height={4}
                fill={alpha(borderColor, 0.15)}
              />

              {/* Address label */}
              <text
                x={node.x + 8}
                y={node.y + 16}
                fontSize={11}
                fontFamily="JetBrains Mono, monospace"
                fontWeight={600}
                fill={colors.addrColor}
              >
                {node.label}
                {node.isEntry && (
                  <tspan fill={colors.entryBorder} fontSize={9}>
                    {' '}
                    (entry)
                  </tspan>
                )}
              </text>

              {/* Instructions */}
              {node.instructions.map((instr, idx) => (
                <text
                  key={idx}
                  x={node.x + 8}
                  y={node.y + 40 + idx * 16}
                  fontSize={10}
                  fontFamily="JetBrains Mono, monospace"
                  fill={colors.text}
                >
                  <tspan fill={colors.textSecondary} fontSize={9}>
                    {instr.addr.replace(/^0x0+/, '0x')}{' '}
                  </tspan>
                  <tspan fill={colors.mnemonicColor}>{instr.opcode}</tspan>
                </text>
              ))}

              {node.instructions.length === 6 && (
                <text
                  x={node.x + 8}
                  y={node.y + 40 + 6 * 16}
                  fontSize={9}
                  fontFamily="JetBrains Mono, monospace"
                  fill={colors.textSecondary}
                >
                  ...
                </text>
              )}
            </g>
          );
        })}
      </svg>

      {/* Legend */}
      <Box
        sx={{
          position: 'absolute',
          bottom: 8,
          left: 8,
          zIndex: 10,
          bgcolor: alpha(colors.nodeBg, 0.9),
          borderRadius: 1,
          p: 1,
          display: 'flex',
          gap: 2,
          fontSize: '0.7rem',
        }}
      >
        <Stack direction="row" alignItems="center" spacing={0.5}>
          <Box sx={{ width: 20, height: 2, bgcolor: colors.jumpEdge }} />
          <Typography variant="caption" color="text.secondary">
            Jump
          </Typography>
        </Stack>
        <Stack direction="row" alignItems="center" spacing={0.5}>
          <Box
            sx={{
              width: 20,
              height: 2,
              bgcolor: colors.fallEdge,
              backgroundImage: 'repeating-linear-gradient(90deg, transparent, transparent 3px, currentColor 3px, currentColor 6px)',
            }}
          />
          <Typography variant="caption" color="text.secondary">
            Fallthrough
          </Typography>
        </Stack>
      </Box>
    </Box>
  );
};

// Memoize CFG Graph to prevent unnecessary re-renders
const CFGGraph = memo(CFGGraphBase);

const CFGViewer: FC<CFGViewerProps> = ({
  nodes,
  edges,
  functions = [],
  onAskAboutCFG,
  sessionId,
}) => {
  const theme = useTheme();
  const isDark = theme.palette.mode === 'dark';
  const activity = useActivity();

  // Function naming state
  const [functionNames, setFunctionNames] = useState<Map<string, FunctionName>>(new Map());
  const [isNamingFunctions, setIsNamingFunctions] = useState(false);
  const [namingProgress, setNamingProgress] = useState<string | null>(null);
  const [editingFunction, setEditingFunction] = useState<string | null>(null);
  const [editValue, setEditValue] = useState('');

  // Load function names from server
  useEffect(() => {
    if (!sessionId) return;

    const loadFunctionNames = async () => {
      try {
        const response = await fetch(`/api/chats/${sessionId}/function-names`);
        if (response.ok) {
          const data = await response.json();
          const names = new Map<string, FunctionName>();
          for (const fn of data.function_names || []) {
            names.set(fn.address, fn);
          }
          setFunctionNames(names);
        }
      } catch {
        // Ignore errors
      }
    };
    loadFunctionNames();
  }, [sessionId]);

  // Use function_cfgs directly - these are functions with actual CFG blocks extracted
  // Don't create empty shells from radareFunctions as they provide no CFG value
  const allFunctions = useMemo(() => {
    return functions;
  }, [functions]);

  // Get display name for a function (custom name or original)
  const getDisplayName = useCallback((fn: FunctionCFG): { display: string; original: string; isRenamed: boolean; source?: string; reasoning?: string } => {
    const fnName = functionNames.get(fn.offset);
    if (fnName) {
      return {
        display: fnName.displayName,
        original: fnName.originalName || fn.name,
        isRenamed: true,
        source: fnName.source,
        reasoning: fnName.reasoning,
      };
    }
    return { display: fn.name, original: fn.name, isRenamed: false };
  }, [functionNames]);

  const [selectedFunction, setSelectedFunction] = useState<FunctionCFG | null>(
    allFunctions[0] ?? null
  );
  const [selectedBlockIndex, setSelectedBlockIndex] = useState(0);
  const [viewMode, setViewMode] = useState<'graph' | 'blocks'>('graph');
  const [selectedGraphNode, setSelectedGraphNode] = useState<string | null>(null);
  const [isMaximized, setIsMaximized] = useState(false);
  const lastPanLog = useRef<number>(0);

  // Auto-name functions using LLM
  const handleAutoNameFunctions = useCallback(async () => {
    if (!sessionId || isNamingFunctions) return;

    setIsNamingFunctions(true);
    setNamingProgress('Analyzing functions...');
    debug.cfg.autoName(allFunctions.length, 'start');

    try {
      // Prepare function data for the API
      const functionsToName = allFunctions
        .filter((fn) => /^(sub_|fcn\.|func_|FUN_)[0-9a-fA-F]+$/i.test(fn.name))
        .slice(0, 10)
        .map((fn) => ({
          name: fn.name,
          address: fn.offset,
          blocks: fn.blocks?.slice(0, 3).map((b) => ({
            offset: b.offset,
            disassembly: b.disassembly?.slice(0, 10).map((d) => ({
              addr: d.addr,
              opcode: d.opcode,
            })),
          })),
        }));

      if (functionsToName.length === 0) {
        setNamingProgress('No generic function names found');
        setTimeout(() => setNamingProgress(null), 2000);
        setIsNamingFunctions(false);
        debug.cfg.autoName(0, 'complete');
        return;
      }

      setNamingProgress(`Naming ${functionsToName.length} functions...`);

      const response = await fetch('/api/functions/suggest-names', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: sessionId,
          functions: functionsToName,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to suggest names');
      }

      const data = await response.json();
      const suggestions: FunctionNameSuggestion[] = data.suggestions || [];

      // Save each suggestion to the server
      for (const suggestion of suggestions) {
        const originalFn = allFunctions.find((f) => f.offset === suggestion.address);
        if (!originalFn) continue;

        await fetch(`/api/chats/${sessionId}/function-names`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            address: suggestion.address,
            originalName: originalFn.name,
            displayName: suggestion.name,
            reasoning: suggestion.reasoning,
            confidence: suggestion.confidence,
            source: 'llm',
          }),
        });

        // Update local state
        setFunctionNames((prev) => {
          const newMap = new Map(prev);
          newMap.set(suggestion.address, {
            id: `${sessionId}-${suggestion.address}`,
            address: suggestion.address,
            originalName: originalFn.name,
            displayName: suggestion.name,
            reasoning: suggestion.reasoning,
            confidence: suggestion.confidence,
            source: 'llm',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          });
          return newMap;
        });
      }

      setNamingProgress(`Named ${suggestions.length} functions`);
      debug.cfg.autoName(suggestions.length, 'complete');
      setTimeout(() => setNamingProgress(null), 2000);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      debug.cfg.autoName(0, 'error', errorMessage);
      setNamingProgress('Failed to name functions');
      setTimeout(() => setNamingProgress(null), 2000);
    } finally {
      setIsNamingFunctions(false);
    }
  }, [sessionId, isNamingFunctions, allFunctions]);

  // Save a custom function name
  const handleSaveFunctionName = useCallback(async (fn: FunctionCFG, newName: string) => {
    if (!sessionId || !newName.trim()) return;

    try {
      await fetch(`/api/chats/${sessionId}/function-names`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          address: fn.offset,
          originalName: fn.name,
          displayName: newName.trim(),
          source: 'user',
        }),
      });

      setFunctionNames((prev) => {
        const newMap = new Map(prev);
        newMap.set(fn.offset, {
          id: `${sessionId}-${fn.offset}`,
          address: fn.offset,
          originalName: fn.name,
          displayName: newName.trim(),
          source: 'user',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        });
        return newMap;
      });
    } catch {
      // Ignore errors
    }
    setEditingFunction(null);
    setEditValue('');
  }, [sessionId]);

  // Toggle maximize state
  const handleMaximizeToggle = useCallback(() => {
    setIsMaximized(prev => {
      const newMaximized = !prev;
      debug.cfg.maximize(newMaximized);
      activity.trackEvent('cfg_navigate', {
        action: newMaximized ? 'maximize' : 'minimize',
        function: selectedFunction?.name,
      });
      return newMaximized;
    });
  }, [activity, selectedFunction]);

  // Handle escape key at document level for maximize
  useEffect(() => {
    const handleEscapeKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isMaximized) {
        setIsMaximized(false);
      }
    };
    document.addEventListener('keydown', handleEscapeKey);
    return () => document.removeEventListener('keydown', handleEscapeKey);
  }, [isMaximized]);

  // Update selected function when allFunctions changes
  useEffect(() => {
    if (allFunctions.length > 0 && !selectedFunction) {
      setSelectedFunction(allFunctions[0]);
    }
  }, [allFunctions, selectedFunction]);

  // Get blocks from selected function - use radare2 function_cfgs directly
  // No fallback synthesis from angr nodes to avoid brittle assumptions
  const currentBlocks = useMemo(() => {
    if (selectedFunction?.blocks && selectedFunction.blocks.length > 0) {
      return selectedFunction.blocks;
    }
    return [];
  }, [selectedFunction]);

  const currentBlock = currentBlocks[selectedBlockIndex] ?? null;

  // Layout graph for current function
  const graphLayout = useMemo(() => {
    if (!selectedFunction || currentBlocks.length === 0) {
      return { nodes: [], edges: [] };
    }
    return layoutGraph(currentBlocks, selectedFunction.offset);
  }, [selectedFunction, currentBlocks]);

  const handlePrevBlock = useCallback(() => {
    setSelectedBlockIndex((prev) => Math.max(0, prev - 1));
  }, []);

  const handleNextBlock = useCallback(() => {
    setSelectedBlockIndex((prev) => Math.min(currentBlocks.length - 1, prev + 1));
  }, [currentBlocks.length]);

  const handleSelectFunction = useCallback((fn: FunctionCFG) => {
    debug.cfg.functionSelect(fn.name, fn.offset);
    activity.trackEvent('cfg_navigate', {
      function: fn.name,
      offset: fn.offset,
      block_count: fn.block_count,
    });
    setSelectedFunction(fn);
    setSelectedBlockIndex(0);
    setSelectedGraphNode(null);
  }, [activity]);

  const handleCopyDisasm = useCallback(() => {
    if (!currentBlock) return;

    // Handle both radare2 format (disassembly or ops) and angr format
    const blockAny = currentBlock as Record<string, unknown>;
    const disasm = (currentBlock.disassembly || blockAny.ops) as Array<Record<string, unknown>> | undefined;
    if (!disasm) return;

    const text = disasm
      .map((d: Record<string, unknown>) => {
        const addr = (d.addr as string) || (typeof d.offset === 'number' ? d.offset.toString(16) : '') || '';
        const op = (d.opcode as string) || '';
        return `${addr}  ${op}`;
      })
      .join('\n');
    navigator.clipboard.writeText(text);
  }, [currentBlock]);

  const handleGraphNodeClick = useCallback(
    (nodeId: string) => {
      setSelectedGraphNode(nodeId);
      activity.trackEvent('cfg_navigate', {
        block: nodeId,
        function: selectedFunction?.name,
      });
      // Find block index
      const idx = currentBlocks.findIndex((b) => b.offset === nodeId);
      if (idx >= 0) {
        setSelectedBlockIndex(idx);
      }
    },
    [currentBlocks, activity, selectedFunction]
  );

  // Handle view mode switch
  const handleViewModeSwitch = useCallback((newMode: 'graph' | 'blocks') => {
    debug.cfg.viewModeSwitch(viewMode, newMode);
    setViewMode(newMode);
  }, [viewMode]);

  // Handle Ask About CFG - collect context and call callback
  const handleAskAboutCFGInternal = useCallback(() => {
    if (!onAskAboutCFG) return;

    // Find the selected block
    const selectedBlock = selectedGraphNode
      ? currentBlocks.find((b) => b.offset === selectedGraphNode)
      : currentBlock;

    // Build context
    const context: CFGContext = {
      functionName: selectedFunction?.name ?? null,
      functionOffset: selectedFunction?.offset ?? null,
      selectedBlock: selectedBlock?.offset ?? null,
      blockAssembly: selectedBlock?.disassembly?.map((d) => ({
        addr: d.addr,
        opcode: d.opcode,
      })) ?? null,
      visibleBlocks: currentBlocks.slice(0, 5).map((b) => ({
        offset: b.offset ?? null,
        disassembly: b.disassembly?.slice(0, 10).map((d) => ({
          addr: d.addr,
          opcode: d.opcode,
        })),
      })),
    };

    // Track activity
    activity.trackEvent('ask_claude', {
      topic: 'cfg',
      function: selectedFunction?.name,
      block: selectedBlock?.offset,
      has_context: Boolean(selectedBlock?.disassembly?.length),
    });

    debug.cfg.askClaude(context);

    onAskAboutCFG(context);
  }, [onAskAboutCFG, selectedFunction, selectedGraphNode, currentBlocks, currentBlock, activity]);

  // Get disassembly from current block (handle both radare2 and angr formats)
  const blockDisasm = useMemo(() => {
    if (!currentBlock) return [];

    // Handle radare2 format (disassembly array with addr/opcode)
    if (currentBlock.disassembly && currentBlock.disassembly.length > 0) {
      return currentBlock.disassembly.map((d: Record<string, unknown>) => ({
        addr: (d.addr as string) || '?',
        opcode:
          (d.opcode as string | undefined) ||
          (d.mnemonic ? `${d.mnemonic} ${d.op_str || ''}`.trim() : '') ||
          '',
        bytes: (d.bytes as string) || '',
      }));
    }

    // Handle radare2 ops format (from agfj command)
    const blockAny = currentBlock as Record<string, unknown>;
    const ops = blockAny.ops as Array<Record<string, unknown>> | undefined;
    if (ops && ops.length > 0) {
      return ops.map((op: Record<string, unknown>) => ({
        addr:
          typeof op.offset === 'number'
            ? `0x${op.offset.toString(16)}`
            : (op.offset as string) || '?',
        opcode: (op.opcode as string) || '',
        bytes: (op.bytes as string) || '',
      }));
    }

    return [];
  }, [currentBlock]);

  // CFG status for debugging - only show functions with actual CFG blocks
  const cfgStatus = useMemo(() => {
    const issues: string[] = [];
    const functionsWithBlocks = functions.filter((f) => f.blocks && f.blocks.length > 0);

    issues.push(`radare2 function CFGs: ${functionsWithBlocks.length}`);
    
    if (nodes.length > 0) {
      issues.push(`angr CFG nodes: ${nodes.length}`);
    }
    if (edges.length > 0) {
      issues.push(`angr CFG edges: ${edges.length}`);
    }

    return {
      // Only show CFG viewer if we have functions with actual blocks
      hasData: functionsWithBlocks.length > 0,
      hasCFGBlocks: functionsWithBlocks.length > 0,
      issues,
    };
  }, [nodes, edges, functions]);

  if (!cfgStatus.hasData) {
    return (
      <Box
        sx={{
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexDirection: 'column',
          gap: 1,
          p: 2,
          animation: `${fadeIn} 0.4s ease-out`,
        }}
      >
        <AccountTreeIcon
          sx={{
            fontSize: 48,
            opacity: 0.3,
            animation: `${pulse} 3s ease-in-out infinite`,
          }}
        />
        <Typography variant="body2" color="text.secondary">
          No CFG data available
        </Typography>
        <Typography
          variant="caption"
          color="text.secondary"
          sx={{ textAlign: 'center' }}
        >
          Run full analysis (not quick scan) to generate CFG
        </Typography>

        {/* Debug info */}
        <Paper variant="outlined" sx={{ mt: 2, p: 1.5, maxWidth: 350 }}>
          <Typography
            variant="caption"
            color="text.secondary"
            fontWeight={600}
            sx={{ display: 'block', mb: 0.5 }}
          >
            CFG Generation Checklist:
          </Typography>
          <Typography
            variant="caption"
            component="ul"
            sx={{ pl: 2, m: 0, color: 'text.secondary' }}
          >
            <li>Enable &quot;Full Analysis&quot; (not quick scan)</li>
            <li>
              angr must be installed: <code>pip install angr</code>
            </li>
            <li>Binary must be a valid ELF/PE executable</li>
            <li>Check console logs for errors</li>
          </Typography>

          <Typography
            variant="caption"
            color="text.secondary"
            fontWeight={600}
            sx={{ display: 'block', mt: 1, mb: 0.5 }}
          >
            Debug Status:
          </Typography>
          <Box
            sx={{
              fontFamily: 'monospace',
              fontSize: '0.65rem',
              color: 'text.secondary',
            }}
          >
            {cfgStatus.issues.map((issue, i) => (
              <Typography key={i} variant="caption" sx={{ display: 'block' }}>
                • {issue}
              </Typography>
            ))}
          </Box>
        </Paper>
      </Box>
    );
  }

  // Main content component
  const mainContent = (
    <Box sx={{ height: '100%', display: 'flex', gap: 1.5 }}>
      {/* Functions list */}
      <Paper
        variant="outlined"
        sx={{
          width: 220,
          flexShrink: 0,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          animation: `${fadeIn} 0.3s ease-out`,
        }}
      >
        <Box sx={{ p: 1, borderBottom: 1, borderColor: 'divider' }}>
          <Stack direction="row" alignItems="center" justifyContent="space-between">
            <Typography variant="caption" color="text.secondary">
              Functions ({allFunctions.length})
            </Typography>
            {sessionId && (
              <Tooltip title="Auto-name generic functions using AI">
                <span>
                  <IconButton
                    size="small"
                    onClick={handleAutoNameFunctions}
                    disabled={isNamingFunctions}
                    color="primary"
                    sx={{ p: 0.5 }}
                  >
                    {isNamingFunctions ? (
                      <CircularProgress size={14} />
                    ) : (
                      <AutoFixHighIcon sx={{ fontSize: 14 }} />
                    )}
                  </IconButton>
                </span>
              </Tooltip>
            )}
          </Stack>
          {namingProgress && (
            <Typography variant="caption" color="primary" sx={{ display: 'block', mt: 0.5, fontSize: '0.6rem' }}>
              {namingProgress}
            </Typography>
          )}
        </Box>
        <Box sx={{ flex: 1, overflow: 'auto' }}>
          <List dense disablePadding>
            {allFunctions.slice(0, 50).map((fn, idx) => {
              const nameInfo = getDisplayName(fn);
              const isEditing = editingFunction === fn.offset;

              return (
                <ListItemButton
                  key={`fn-${idx}`}
                  selected={selectedFunction?.offset === fn.offset}
                  onClick={() => !isEditing && handleSelectFunction(fn)}
                  sx={{
                    py: 0.5,
                    px: 1,
                    animation: `${fadeIn} 0.2s ease-out`,
                    animationDelay: `${Math.min(idx * 20, 200)}ms`,
                    animationFillMode: 'backwards',
                    transition: 'all 0.15s ease-out',
                    '&:hover': {
                      transform: 'translateX(2px)',
                    },
                    '&.Mui-selected': {
                      borderLeft: 2,
                      borderColor: 'primary.main',
                    },
                  }}
                >
                  <ListItemText
                    primary={
                      isEditing ? (
                        <TextField
                          size="small"
                          value={editValue}
                          onChange={(e) => setEditValue(e.target.value)}
                          onBlur={() => handleSaveFunctionName(fn, editValue)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') {
                              handleSaveFunctionName(fn, editValue);
                            } else if (e.key === 'Escape') {
                              setEditingFunction(null);
                              setEditValue('');
                            }
                          }}
                          autoFocus
                          sx={{
                            '& .MuiInputBase-input': {
                              fontSize: '0.7rem',
                              fontFamily: 'monospace',
                              py: 0.25,
                              px: 0.5,
                            },
                          }}
                          onClick={(e) => e.stopPropagation()}
                        />
                      ) : (
                        <Tooltip
                          title={
                            nameInfo.isRenamed
                              ? `${nameInfo.reasoning || 'Custom name'}${nameInfo.source === 'llm' ? ' (AI)' : ' (Manual)'}`
                              : ''
                          }
                          placement="right"
                        >
                          <Stack direction="row" alignItems="center" spacing={0.5}>
                            <Typography
                              variant="caption"
                              sx={{
                                fontFamily: 'monospace',
                                color: nameInfo.isRenamed ? 'primary.main' : 'text.primary',
                                fontWeight: nameInfo.isRenamed ? 500 : 400,
                              }}
                            >
                              {nameInfo.display.length > 20 ? nameInfo.display.slice(0, 20) + '…' : nameInfo.display}
                            </Typography>
                            {sessionId && selectedFunction?.offset === fn.offset && (
                              <IconButton
                                size="small"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setEditingFunction(fn.offset);
                                  setEditValue(nameInfo.display);
                                }}
                                sx={{ p: 0, opacity: 0.5, '&:hover': { opacity: 1 } }}
                              >
                                <EditIcon sx={{ fontSize: 10 }} />
                              </IconButton>
                            )}
                          </Stack>
                        </Tooltip>
                      )
                    }
                    secondary={
                      <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap">
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          sx={{ fontSize: '0.6rem' }}
                        >
                          {fn.offset}
                        </Typography>
                        {nameInfo.isRenamed && (
                          <Typography
                            variant="caption"
                            color="text.disabled"
                            sx={{ fontSize: '0.55rem' }}
                          >
                            ({nameInfo.original.length > 12 ? nameInfo.original.slice(0, 12) + '…' : nameInfo.original})
                          </Typography>
                        )}
                        {fn.blocks && fn.blocks.length > 0 && (
                          <Chip
                            size="small"
                            label={`${fn.blocks.length}b`}
                            sx={{
                              height: 14,
                              fontSize: '0.5rem',
                              '& .MuiChip-label': { px: 0.5 },
                            }}
                          />
                        )}
                      </Stack>
                    }
                  />
                  {fn.blocks && fn.blocks.length > 0 && !isEditing && (
                    <ChevronRightIcon
                      sx={{ fontSize: 14, color: 'text.disabled', ml: 0.5 }}
                    />
                  )}
                </ListItemButton>
              );
            })}
          </List>
        </Box>
      </Paper>

      {/* Main content area */}
      <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {/* View mode toggle and header */}
        <Paper
          variant="outlined"
          sx={{ p: 1, mb: 1.5, display: 'flex', alignItems: 'center', gap: 1 }}
        >
          {selectedFunction && (
            <>
              {(() => {
                const nameInfo = getDisplayName(selectedFunction);
                return (
                  <>
                    <Typography variant="caption" fontWeight={600} sx={{ fontFamily: 'monospace', color: nameInfo.isRenamed ? 'primary.main' : 'text.primary' }}>
                      {nameInfo.display}
                    </Typography>
                    {nameInfo.isRenamed && (
                      <Typography variant="caption" color="text.disabled" sx={{ fontFamily: 'monospace', fontSize: '0.65rem' }}>
                        ({nameInfo.original})
                      </Typography>
                    )}
                  </>
                );
              })()}
              <Typography variant="caption" color="text.secondary">
                {selectedFunction.offset}
              </Typography>
              <Chip
                size="small"
                label={`${currentBlocks.length} blocks`}
                sx={{ height: 18, fontSize: '0.65rem' }}
              />
            </>
          )}

          <Box sx={{ flex: 1 }} />

          <Stack direction="row" spacing={0.5}>
            <Chip
              size="small"
              label="Graph"
              onClick={() => handleViewModeSwitch('graph')}
              variant={viewMode === 'graph' ? 'filled' : 'outlined'}
              color={viewMode === 'graph' ? 'primary' : 'default'}
              sx={{ height: 22, cursor: 'pointer' }}
            />
            <Chip
              size="small"
              label="Blocks"
              onClick={() => handleViewModeSwitch('blocks')}
              variant={viewMode === 'blocks' ? 'filled' : 'outlined'}
              color={viewMode === 'blocks' ? 'primary' : 'default'}
              sx={{ height: 22, cursor: 'pointer' }}
            />
          </Stack>
        </Paper>

        {/* Graph or Block view */}
        <Paper
          variant="outlined"
          sx={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            animation: `${fadeIn} 0.3s ease-out`,
          }}
        >
          {viewMode === 'graph' ? (
            <Box sx={{ flex: 1 }}>
              {graphLayout.nodes.length > 0 ? (
                <CFGGraph
                  nodes={graphLayout.nodes}
                  edges={graphLayout.edges}
                  onNodeClick={handleGraphNodeClick}
                  selectedNode={selectedGraphNode}
                  isMaximized={isMaximized}
                  onMaximizeToggle={handleMaximizeToggle}
                  onAskAboutCFG={onAskAboutCFG ? handleAskAboutCFGInternal : undefined}
                />
              ) : (
                <Box
                  sx={{
                    height: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexDirection: 'column',
                    gap: 1,
                    color: 'text.secondary',
                  }}
                >
                  <AccountTreeIcon sx={{ fontSize: 40, opacity: 0.3 }} />
                  <Typography variant="body2">No block-level CFG available</Typography>
                  <Typography variant="caption">
                    Run full analysis to extract control flow blocks
                  </Typography>
                </Box>
              )}
            </Box>
          ) : selectedFunction && currentBlocks.length > 0 ? (
            <>
              {/* Block navigation header */}
              <Stack
                direction="row"
                alignItems="center"
                spacing={1}
                sx={{ p: 1, borderBottom: 1, borderColor: 'divider' }}
              >
                <IconButton
                  size="small"
                  onClick={handlePrevBlock}
                  disabled={selectedBlockIndex === 0}
                >
                  <NavigateBeforeIcon sx={{ fontSize: 16 }} />
                </IconButton>
                <Chip
                  size="small"
                  label={`Block ${selectedBlockIndex + 1}/${currentBlocks.length}`}
                  sx={{ height: 18, fontSize: '0.65rem' }}
                />
                <IconButton
                  size="small"
                  onClick={handleNextBlock}
                  disabled={selectedBlockIndex >= currentBlocks.length - 1}
                >
                  <NavigateNextIcon sx={{ fontSize: 16 }} />
                </IconButton>

                <Box sx={{ flex: 1 }} />

                <Tooltip title="Copy">
                  <IconButton size="small" onClick={handleCopyDisasm}>
                    <ContentCopyIcon sx={{ fontSize: 14 }} />
                  </IconButton>
                </Tooltip>
              </Stack>

              {/* Block content */}
              <Box sx={{ flex: 1, overflow: 'auto', p: 1 }}>
                {currentBlock && (
                  <>
                    {/* Block info */}
                    <Stack direction="row" spacing={1} sx={{ mb: 1 }}>
                      <Chip
                        size="small"
                        label={currentBlock.offset || '?'}
                        variant="outlined"
                      />
                      <Chip
                        size="small"
                        label={`${currentBlock.size || '?'}B`}
                        variant="outlined"
                      />
                      {currentBlock.jump && (
                        <Chip
                          size="small"
                          label={`→ ${currentBlock.jump}`}
                          color="success"
                          variant="outlined"
                          sx={{ fontFamily: 'monospace', fontSize: '0.6rem' }}
                        />
                      )}
                      {currentBlock.fail && (
                        <Chip
                          size="small"
                          label={`↓ ${currentBlock.fail}`}
                          color="warning"
                          variant="outlined"
                          sx={{ fontFamily: 'monospace', fontSize: '0.6rem' }}
                        />
                      )}
                    </Stack>

                    {/* Disassembly */}
                    <Paper
                      variant="outlined"
                      sx={{
                        p: 1,
                        bgcolor: isDark ? '#0a0a0a' : '#fafafa',
                        fontFamily: 'monospace',
                        fontSize: '0.75rem',
                        overflow: 'auto',
                        maxHeight: 400,
                      }}
                    >
                      {blockDisasm.length > 0 ? (
                        blockDisasm.map(
                          (
                            insn: { addr: string; opcode: string | undefined; bytes: string },
                            idx: number
                          ) => (
                            <Box
                              key={idx}
                              sx={{
                                display: 'flex',
                                gap: 2,
                                py: 0.25,
                                px: 0.5,
                                borderRadius: 0.5,
                                animation: `${fadeIn} 0.15s ease-out`,
                                animationDelay: `${Math.min(idx * 15, 150)}ms`,
                                animationFillMode: 'backwards',
                                transition: 'all 0.1s ease-out',
                                '&:hover': {
                                  bgcolor: isDark
                                    ? alpha('#fff', 0.05)
                                    : alpha('#000', 0.04),
                                  transform: 'translateX(2px)',
                                },
                              }}
                            >
                              <Typography
                                component="span"
                                sx={{
                                  color: 'text.secondary',
                                  minWidth: 80,
                                  fontSize: 'inherit',
                                  fontFamily: 'inherit',
                                }}
                              >
                                {insn.addr}
                              </Typography>
                              <Typography
                                component="span"
                                sx={{
                                  color: 'primary.main',
                                  fontSize: 'inherit',
                                  fontFamily: 'inherit',
                                }}
                              >
                                {insn.opcode || ''}
                              </Typography>
                            </Box>
                          )
                        )
                      ) : (
                        <Typography variant="caption" color="text.secondary">
                          No disassembly available
                        </Typography>
                      )}
                    </Paper>
                  </>
                )}
              </Box>
            </>
          ) : selectedFunction ? (
            <Box sx={{ p: 2, textAlign: 'center' }}>
              <Typography variant="body2" color="text.secondary">
                No blocks extracted for {selectedFunction.name}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Block-level disassembly requires deep analysis
              </Typography>
            </Box>
          ) : (
            <Box sx={{ p: 2, textAlign: 'center' }}>
              <Typography variant="body2" color="text.secondary">
                Select a function
              </Typography>
            </Box>
          )}
        </Paper>
      </Box>

      {/* Stats sidebar */}
      <Paper
        variant="outlined"
        sx={{
          width: 140,
          flexShrink: 0,
          p: 1,
          display: 'flex',
          flexDirection: 'column',
          gap: 1.5,
          animation: `${fadeIn} 0.3s ease-out`,
          animationDelay: '0.2s',
          animationFillMode: 'backwards',
        }}
      >
        <Typography
          variant="caption"
          color="text.secondary"
          sx={{ fontWeight: 600 }}
        >
          Analysis Summary
        </Typography>

        <Stack spacing={0.75}>
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'baseline',
            }}
          >
            <Typography variant="caption" color="text.secondary">
              Functions
            </Typography>
            <Typography variant="body2" fontWeight={600}>
              {allFunctions.length}
            </Typography>
          </Box>
          {cfgStatus.hasCFGBlocks && (
            <Box
              sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'baseline',
              }}
            >
              <Typography variant="caption" color="text.secondary">
                With CFG
              </Typography>
              <Typography variant="body2" fontWeight={600} color="success.main">
                {functions.filter((f) => f.blocks && f.blocks.length > 0).length}
              </Typography>
            </Box>
          )}
          {nodes.length > 0 && (
            <Box
              sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'baseline',
                pt: 0.5,
                borderTop: 1,
                borderColor: 'divider',
              }}
            >
              <Typography variant="caption" color="text.secondary">
                angr nodes
              </Typography>
              <Typography variant="body2" fontWeight={600}>
                {nodes.length}
              </Typography>
            </Box>
          )}
          {edges.length > 0 && (
            <Box
              sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'baseline',
              }}
            >
              <Typography variant="caption" color="text.secondary">
                angr edges
              </Typography>
              <Typography variant="body2" fontWeight={600}>
                {edges.length}
              </Typography>
            </Box>
          )}
        </Stack>

        {/* Source indicator */}
        <Box sx={{ mt: 'auto', pt: 1, borderTop: 1, borderColor: 'divider' }}>
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{ fontSize: '0.6rem', display: 'block', mb: 0.5 }}
          >
            Data Sources
          </Typography>
          <Stack direction="row" spacing={0.5} flexWrap="wrap" gap={0.5}>
            {functions.length > 0 && (
              <Chip
                size="small"
                label="radare2"
                color="success"
                variant="outlined"
                sx={{ height: 16, fontSize: '0.55rem', '& .MuiChip-label': { px: 0.5 } }}
              />
            )}
            {nodes.length > 0 && (
              <Chip
                size="small"
                label="angr"
                color="info"
                variant="outlined"
                sx={{ height: 16, fontSize: '0.55rem', '& .MuiChip-label': { px: 0.5 } }}
              />
            )}
          </Stack>
        </Box>
      </Paper>
    </Box>
  );

  // Render with optional maximize overlay
  if (isMaximized) {
    return (
      <Box
        sx={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          zIndex: 1300,
          bgcolor: 'background.default',
          p: 2,
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        {/* Header with close button */}
        <Stack
          direction="row"
          alignItems="center"
          justifyContent="space-between"
          sx={{ mb: 1.5 }}
        >
          <Typography variant="h6" sx={{ fontFamily: 'monospace' }}>
            CFG Viewer - {selectedFunction?.name || 'No function selected'}
          </Typography>
          <Tooltip title="Exit Fullscreen (Esc)">
            <IconButton onClick={handleMaximizeToggle}>
              <CloseFullscreenIcon />
            </IconButton>
          </Tooltip>
        </Stack>
        <Box sx={{ flex: 1, overflow: 'hidden' }}>{mainContent}</Box>
      </Box>
    );
  }

  return mainContent;
};

export default CFGViewer;
