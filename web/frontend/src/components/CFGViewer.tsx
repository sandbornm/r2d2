import AccountTreeIcon from '@mui/icons-material/AccountTree';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import FitScreenIcon from '@mui/icons-material/FitScreen';
import NavigateBeforeIcon from '@mui/icons-material/NavigateBefore';
import NavigateNextIcon from '@mui/icons-material/NavigateNext';
import ZoomInIcon from '@mui/icons-material/ZoomIn';
import ZoomOutIcon from '@mui/icons-material/ZoomOut';
import {
  alpha,
  Box,
  Chip,
  IconButton,
  keyframes,
  List,
  ListItemButton,
  ListItemText,
  Paper,
  Stack,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import { FC, useCallback, useEffect, useMemo, useRef, useState } from 'react';

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

interface CFGViewerProps {
  nodes: CFGNode[];
  edges: CFGEdge[];
  functions?: FunctionCFG[];
  radareFunctions?: Array<{ name?: string; offset?: number; size?: number }>;
  angrActive?: number;
  angrFound?: number;
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
}

const CFGGraph: FC<CFGGraphProps> = ({ nodes, edges, onNodeClick, selectedNode }) => {
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

  const handleZoomIn = () => setZoom(z => Math.min(z * 1.2, 3));
  const handleZoomOut = () => setZoom(z => Math.max(z / 1.2, 0.3));
  const handleFit = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.button === 0) {
      setIsPanning(true);
      setPanStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isPanning) {
      setPan({
        x: e.clientX - panStart.x,
        y: e.clientY - panStart.y,
      });
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
      sx={{
        height: '100%',
        position: 'relative',
        overflow: 'hidden',
        bgcolor: isDark ? '#0d0d14' : '#f8f9fa',
        borderRadius: 1,
      }}
    >
      {/* Zoom controls */}
      <Stack
        direction="row"
        spacing={0.5}
        sx={{
          position: 'absolute',
          top: 8,
          right: 8,
          zIndex: 10,
          bgcolor: alpha(colors.nodeBg, 0.9),
          borderRadius: 1,
          p: 0.5,
        }}
      >
        <Tooltip title="Zoom In">
          <IconButton size="small" onClick={handleZoomIn}>
            <ZoomInIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>
        <Tooltip title="Zoom Out">
          <IconButton size="small" onClick={handleZoomOut}>
            <ZoomOutIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>
        <Tooltip title="Fit">
          <IconButton size="small" onClick={handleFit}>
            <FitScreenIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>
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

const CFGViewer: FC<CFGViewerProps> = ({
  nodes,
  edges,
  functions = [],
  radareFunctions = [],
}) => {
  const theme = useTheme();
  const isDark = theme.palette.mode === 'dark';

  // Combine function sources - prefer function_cfgs but fall back to radareFunctions
  const allFunctions = useMemo(() => {
    if (functions.length > 0) return functions;

    // Convert radareFunctions to FunctionCFG format
    return radareFunctions
      .filter((fn) => fn.offset !== undefined)
      .map((fn) => ({
        name: fn.name || `sub_${fn.offset?.toString(16)}`,
        offset: `0x${fn.offset?.toString(16)}`,
        size: fn.size || 0,
        block_count: 0,
        blocks: [],
      }));
  }, [functions, radareFunctions]);

  const [selectedFunction, setSelectedFunction] = useState<FunctionCFG | null>(
    allFunctions[0] ?? null
  );
  const [selectedBlockIndex, setSelectedBlockIndex] = useState(0);
  const [viewMode, setViewMode] = useState<'graph' | 'blocks'>('graph');
  const [selectedGraphNode, setSelectedGraphNode] = useState<string | null>(null);

  // Update selected function when allFunctions changes
  useEffect(() => {
    if (allFunctions.length > 0 && !selectedFunction) {
      setSelectedFunction(allFunctions[0]);
    }
  }, [allFunctions, selectedFunction]);

  // Get blocks from selected function, or synthesize from angr nodes
  const currentBlocks = useMemo(() => {
    // Prefer radare2 function_cfgs blocks (has more detail)
    if (selectedFunction?.blocks && selectedFunction.blocks.length > 0) {
      return selectedFunction.blocks;
    }

    // Try to find blocks from angr nodes for this function
    if (selectedFunction && nodes.length > 0) {
      const funcAddr = selectedFunction.offset;
      const funcName = selectedFunction.name;

      // Match by function address or name (handle both hex formats)
      const matchingNodes = nodes.filter((n) => {
        const normalizeAddr = (addr: string | null | undefined) =>
          addr ? addr.toLowerCase().replace(/^0x0+/, '0x') : '';

        const nodeFunc = normalizeAddr(n.function);
        const targetFunc = normalizeAddr(funcAddr);
        const nodeFuncName = n.function_name;

        return (
          (nodeFunc && targetFunc && nodeFunc === targetFunc) ||
          (nodeFuncName && funcName && nodeFuncName === funcName)
        );
      });

      // If no matches by function, check if it's the first/entry function
      const blocksToUse = matchingNodes.length > 0 ? matchingNodes : nodes.slice(0, 10);

      return blocksToUse.map((n) => ({
        offset: n.addr,
        size: n.size || 0,
        jump: null,
        fail: null,
        disassembly:
          n.disassembly?.map((d: Record<string, unknown>) => ({
            addr: (d.addr as string) || '?',
            opcode: d.mnemonic
              ? `${d.mnemonic} ${d.op_str || ''}`.trim()
              : (d.opcode as string) || '',
            bytes: (d.bytes as string) || '',
          })) || [],
      }));
    }

    return [];
  }, [selectedFunction, nodes]);

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
    setSelectedFunction(fn);
    setSelectedBlockIndex(0);
    setSelectedGraphNode(null);
  }, []);

  const handleCopyDisasm = useCallback(() => {
    if (!currentBlock) return;

    const disasm = currentBlock.disassembly || currentBlock.ops;
    if (!disasm) return;

    const text = disasm
      .map((d) => {
        const addr = ('addr' in d ? d.addr : (d as { offset?: number }).offset?.toString(16)) || '';
        const op = ('opcode' in d ? d.opcode : '') || '';
        return `${addr}  ${op}`;
      })
      .join('\n');
    navigator.clipboard.writeText(text);
  }, [currentBlock]);

  const handleGraphNodeClick = useCallback(
    (nodeId: string) => {
      setSelectedGraphNode(nodeId);
      // Find block index
      const idx = currentBlocks.findIndex((b) => b.offset === nodeId);
      if (idx >= 0) {
        setSelectedBlockIndex(idx);
      }
    },
    [currentBlocks]
  );

  // Get disassembly from current block (handle both radare2 and angr formats)
  const blockDisasm = useMemo(() => {
    if (!currentBlock) return [];

    // Handle radare2 format (disassembly array with addr/opcode)
    if (currentBlock.disassembly && currentBlock.disassembly.length > 0) {
      return currentBlock.disassembly.map((d: Record<string, unknown>) => ({
        addr: (d.addr as string) || '?',
        opcode:
          d.opcode ||
          (d.mnemonic ? `${d.mnemonic} ${d.op_str || ''}`.trim() : ''),
        bytes: (d.bytes as string) || '',
      }));
    }

    // Handle radare2 ops format (from agfj command)
    if (currentBlock.ops && currentBlock.ops.length > 0) {
      return currentBlock.ops.map((op: Record<string, unknown>) => ({
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

  // CFG status for debugging
  const cfgStatus = useMemo(() => {
    const issues: string[] = [];

    if (nodes.length === 0) {
      issues.push('angr CFG nodes: 0');
    } else {
      issues.push(`angr CFG nodes: ${nodes.length}`);
    }

    if (edges.length === 0) {
      issues.push('angr CFG edges: 0');
    } else {
      issues.push(`angr CFG edges: ${edges.length}`);
    }

    if (functions.length === 0) {
      issues.push('radare2 function CFGs: 0');
    } else {
      issues.push(`radare2 function CFGs: ${functions.length}`);
    }

    if (radareFunctions.length === 0) {
      issues.push('radare2 functions: 0');
    } else {
      issues.push(`radare2 functions: ${radareFunctions.length}`);
    }

    return {
      hasData:
        nodes.length > 0 || functions.length > 0 || radareFunctions.length > 0,
      hasCFGBlocks: functions.some((f) => f.blocks && f.blocks.length > 0),
      issues,
    };
  }, [nodes, edges, functions, radareFunctions]);

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

  return (
    <Box sx={{ height: '100%', display: 'flex', gap: 1.5 }}>
      {/* Functions list */}
      <Paper
        variant="outlined"
        sx={{
          width: 200,
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
          </Stack>
        </Box>
        <Box sx={{ flex: 1, overflow: 'auto' }}>
          <List dense disablePadding>
            {allFunctions.slice(0, 50).map((fn, idx) => (
              <ListItemButton
                key={`fn-${idx}`}
                selected={selectedFunction?.offset === fn.offset}
                onClick={() => handleSelectFunction(fn)}
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
                    <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                      {fn.name.length > 22 ? fn.name.slice(0, 22) + '…' : fn.name}
                    </Typography>
                  }
                  secondary={
                    <Stack direction="row" spacing={0.5} alignItems="center">
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        sx={{ fontSize: '0.65rem' }}
                      >
                        {fn.offset}
                      </Typography>
                      {fn.blocks && fn.blocks.length > 0 && (
                        <Chip
                          size="small"
                          label={`${fn.blocks.length}b`}
                          sx={{
                            height: 14,
                            fontSize: '0.55rem',
                            '& .MuiChip-label': { px: 0.5 },
                          }}
                        />
                      )}
                    </Stack>
                  }
                />
                {fn.blocks && fn.blocks.length > 0 && (
                  <ChevronRightIcon
                    sx={{ fontSize: 14, color: 'text.disabled', ml: 0.5 }}
                  />
                )}
              </ListItemButton>
            ))}
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
              <Typography variant="caption" fontWeight={600} sx={{ fontFamily: 'monospace' }}>
                {selectedFunction.name}
              </Typography>
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
              onClick={() => setViewMode('graph')}
              variant={viewMode === 'graph' ? 'filled' : 'outlined'}
              color={viewMode === 'graph' ? 'primary' : 'default'}
              sx={{ height: 22, cursor: 'pointer' }}
            />
            <Chip
              size="small"
              label="Blocks"
              onClick={() => setViewMode('blocks')}
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
};

export default CFGViewer;
