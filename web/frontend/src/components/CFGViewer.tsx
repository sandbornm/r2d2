import AccountTreeIcon from '@mui/icons-material/AccountTree';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';
import CompareArrowsIcon from '@mui/icons-material/CompareArrows';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import NavigateBeforeIcon from '@mui/icons-material/NavigateBefore';
import NavigateNextIcon from '@mui/icons-material/NavigateNext';
import VerifiedIcon from '@mui/icons-material/Verified';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import {
  alpha,
  Box,
  Chip,
  IconButton,
  keyframes,
  LinearProgress,
  List,
  ListItemButton,
  ListItemText,
  Paper,
  Stack,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import { FC, useCallback, useMemo, useState } from 'react';

// Smooth fade-in animation
const fadeIn = keyframes`
  from { opacity: 0; transform: translateY(4px); }
  to { opacity: 1; transform: translateY(0); }
`;

// Pulse animation for uncertainty indicator
const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.6; }
`;

// Confidence levels for decompilation
type ConfidenceLevel = 'high' | 'medium' | 'low' | 'unknown';

interface ConfidenceInfo {
  level: ConfidenceLevel;
  score: number;
  reasons: string[];
  radareMatch: boolean;
  angrMatch: boolean;
}

// Calculate confidence based on cross-referencing radare2 and angr analysis
const calculateConfidence = (
  nodes: CFGNode[],
  functions: FunctionCFG[],
  radareFunctions: Array<{name?: string; offset?: number; size?: number}>,
): ConfidenceInfo => {
  const reasons: string[] = [];
  let score = 0;
  const hasAngr = nodes.length > 0;
  const hasRadare = functions.length > 0 || radareFunctions.length > 0;

  // Base scoring
  if (hasAngr && hasRadare) {
    score += 40;
    reasons.push('Both angr and radare2 provided analysis');

    // Check function count agreement
    const angrFuncCount = new Set(nodes.map(n => n.function || n.function_name).filter(Boolean)).size;
    const radareFuncCount = functions.length || radareFunctions.length;
    const funcDiff = Math.abs(angrFuncCount - radareFuncCount);

    if (funcDiff === 0) {
      score += 30;
      reasons.push('Function counts match exactly');
    } else if (funcDiff <= 3) {
      score += 20;
      reasons.push(`Function counts differ by ${funcDiff}`);
    } else if (funcDiff <= 10) {
      score += 10;
      reasons.push(`Function counts differ by ${funcDiff} (moderate variance)`);
    } else {
      reasons.push(`Function counts differ significantly (${funcDiff})`);
    }

    // Check for matching function addresses
    const radareAddrs = new Set(
      radareFunctions.map(f => f.offset?.toString(16)).filter(Boolean)
    );
    const angrAddrs = new Set(
      nodes.map(n => n.addr?.replace('0x', '')).filter(Boolean)
    );

    let matchCount = 0;
    radareAddrs.forEach(addr => {
      if (addr && angrAddrs.has(addr)) matchCount++;
    });

    if (matchCount > 0) {
      const matchRatio = matchCount / Math.max(radareAddrs.size, 1);
      if (matchRatio > 0.8) {
        score += 30;
        reasons.push(`High address agreement (${Math.round(matchRatio * 100)}%)`);
      } else if (matchRatio > 0.5) {
        score += 20;
        reasons.push(`Moderate address agreement (${Math.round(matchRatio * 100)}%)`);
      } else {
        score += 10;
        reasons.push(`Low address agreement (${Math.round(matchRatio * 100)}%)`);
      }
    }
  } else if (hasAngr) {
    score += 30;
    reasons.push('Only angr analysis available');
    reasons.push('Cross-reference with radare2 for higher confidence');
  } else if (hasRadare) {
    score += 30;
    reasons.push('Only radare2 analysis available');
    reasons.push('Run with angr for higher confidence');
  } else {
    reasons.push('No analysis data available');
  }

  // Determine confidence level
  let level: ConfidenceLevel;
  if (score >= 80) {
    level = 'high';
  } else if (score >= 50) {
    level = 'medium';
  } else if (score > 0) {
    level = 'low';
  } else {
    level = 'unknown';
  }

  return {
    level,
    score: Math.min(100, score),
    reasons,
    radareMatch: hasRadare,
    angrMatch: hasAngr,
  };
};

// Confidence indicator component
interface ConfidenceIndicatorProps {
  confidence: ConfidenceInfo;
  compact?: boolean;
}

const ConfidenceIndicator: FC<ConfidenceIndicatorProps> = ({
  confidence,
  compact = false,
}: ConfidenceIndicatorProps) => {
  const theme = useTheme();

  const getColor = () => {
    switch (confidence.level) {
      case 'high': return theme.palette.success.main;
      case 'medium': return theme.palette.warning.main;
      case 'low': return theme.palette.error.main;
      default: return theme.palette.grey[500];
    }
  };

  const getIcon = () => {
    switch (confidence.level) {
      case 'high': return <VerifiedIcon sx={{ fontSize: 14, color: getColor() }} />;
      case 'medium': return <CompareArrowsIcon sx={{ fontSize: 14, color: getColor() }} />;
      case 'low':
      case 'unknown':
        return <WarningAmberIcon sx={{ fontSize: 14, color: getColor(), animation: `${pulse} 2s ease-in-out infinite` }} />;
    }
  };

  const getLabel = () => {
    switch (confidence.level) {
      case 'high': return 'High Confidence';
      case 'medium': return 'Medium Confidence';
      case 'low': return 'Low Confidence';
      default: return 'Unknown';
    }
  };

  if (compact) {
    return (
      <Tooltip
        title={
          <Box sx={{ p: 0.5 }}>
            <Typography variant="caption" fontWeight={600} sx={{ display: 'block' }}>
              {getLabel()} ({confidence.score}%)
            </Typography>
            <Box sx={{ mt: 0.5 }}>
              {confidence.reasons.map((r, i) => (
                <Typography key={i} variant="caption" sx={{ display: 'block', fontSize: '0.65rem' }}>
                  • {r}
                </Typography>
              ))}
            </Box>
            <Stack direction="row" spacing={0.5} sx={{ mt: 1 }}>
              <Chip
                size="small"
                label="radare2"
                sx={{
                  height: 16,
                  fontSize: '0.6rem',
                  bgcolor: confidence.radareMatch ? alpha(theme.palette.success.main, 0.2) : alpha(theme.palette.grey[500], 0.2),
                }}
              />
              <Chip
                size="small"
                label="angr"
                sx={{
                  height: 16,
                  fontSize: '0.6rem',
                  bgcolor: confidence.angrMatch ? alpha(theme.palette.success.main, 0.2) : alpha(theme.palette.grey[500], 0.2),
                }}
              />
            </Stack>
          </Box>
        }
      >
        <Stack direction="row" alignItems="center" spacing={0.5} sx={{ cursor: 'help' }}>
          {getIcon()}
          <Typography variant="caption" sx={{ color: getColor(), fontWeight: 500 }}>
            {confidence.score}%
          </Typography>
        </Stack>
      </Tooltip>
    );
  }

  return (
    <Paper
      variant="outlined"
      sx={{
        p: 1,
        bgcolor: alpha(getColor(), 0.05),
        borderColor: alpha(getColor(), 0.3),
        animation: `${fadeIn} 0.3s ease-out`,
      }}
    >
      <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }}>
        {getIcon()}
        <Typography variant="caption" fontWeight={600} sx={{ color: getColor() }}>
          {getLabel()}
        </Typography>
      </Stack>

      <LinearProgress
        variant="determinate"
        value={confidence.score}
        sx={{
          height: 4,
          borderRadius: 2,
          mb: 1,
          bgcolor: alpha(getColor(), 0.1),
          '& .MuiLinearProgress-bar': {
            bgcolor: getColor(),
            borderRadius: 2,
          },
        }}
      />

      <Stack direction="row" spacing={0.5} sx={{ mb: 0.5 }}>
        <Chip
          size="small"
          icon={confidence.radareMatch ? <VerifiedIcon sx={{ fontSize: '12px !important' }} /> : undefined}
          label="radare2"
          sx={{
            height: 18,
            fontSize: '0.6rem',
            bgcolor: confidence.radareMatch ? alpha(theme.palette.success.main, 0.15) : 'transparent',
            borderColor: confidence.radareMatch ? theme.palette.success.main : theme.palette.divider,
          }}
          variant="outlined"
        />
        <Chip
          size="small"
          icon={confidence.angrMatch ? <VerifiedIcon sx={{ fontSize: '12px !important' }} /> : undefined}
          label="angr"
          sx={{
            height: 18,
            fontSize: '0.6rem',
            bgcolor: confidence.angrMatch ? alpha(theme.palette.success.main, 0.15) : 'transparent',
            borderColor: confidence.angrMatch ? theme.palette.success.main : theme.palette.divider,
          }}
          variant="outlined"
        />
      </Stack>

      <Box sx={{ mt: 0.5 }}>
        {confidence.reasons.slice(0, 3).map((r, i) => (
          <Typography key={i} variant="caption" color="text.secondary" sx={{ display: 'block', fontSize: '0.6rem' }}>
            • {r}
          </Typography>
        ))}
      </Box>
    </Paper>
  );
};

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

interface CFGViewerProps {
  nodes: CFGNode[];
  edges: CFGEdge[];
  functions?: FunctionCFG[];
  radareFunctions?: Array<{name?: string; offset?: number; size?: number}>;
  angrActive?: number;
  angrFound?: number;
}

const CFGViewer: FC<CFGViewerProps> = ({
  nodes,
  edges,
  functions = [],
  radareFunctions = [],
  angrActive = 0,
  angrFound = 0,
}) => {
  const theme = useTheme();
  const isDark = theme.palette.mode === 'dark';

  // Combine function sources - prefer function_cfgs but fall back to radareFunctions
  const allFunctions = useMemo(() => {
    if (functions.length > 0) return functions;
    
    // Convert radareFunctions to FunctionCFG format
    return radareFunctions
      .filter(fn => fn.offset !== undefined)
      .map(fn => ({
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

  // Calculate confidence by cross-referencing radare2 and angr
  const confidence = useMemo(
    () => calculateConfidence(nodes, functions, radareFunctions),
    [nodes, functions, radareFunctions]
  );

  // Get blocks from selected function, or synthesize from angr nodes
  const currentBlocks = useMemo(() => {
    if (selectedFunction?.blocks && selectedFunction.blocks.length > 0) {
      return selectedFunction.blocks;
    }
    
    // Try to find blocks from angr nodes for this function
    if (selectedFunction && nodes.length > 0) {
      const funcAddr = selectedFunction.offset;
      const matchingNodes = nodes.filter(
        n => n.function === funcAddr || n.function_name === selectedFunction.name
      );
      return matchingNodes.map(n => ({
        offset: n.addr,
        size: n.size || 0,
        disassembly: n.disassembly?.map(d => ({
          addr: d.addr,
          opcode: d.mnemonic ? `${d.mnemonic} ${d.op_str || ''}` : d.opcode || '',
          bytes: d.bytes,
        })),
      }));
    }
    
    return [];
  }, [selectedFunction, nodes]);

  const currentBlock = currentBlocks[selectedBlockIndex] ?? null;

  const handlePrevBlock = useCallback(() => {
    setSelectedBlockIndex(prev => Math.max(0, prev - 1));
  }, []);

  const handleNextBlock = useCallback(() => {
    setSelectedBlockIndex(prev => Math.min(currentBlocks.length - 1, prev + 1));
  }, [currentBlocks.length]);

  const handleSelectFunction = useCallback((fn: FunctionCFG) => {
    setSelectedFunction(fn);
    setSelectedBlockIndex(0);
  }, []);

  const handleCopyDisasm = useCallback(() => {
    if (!currentBlock) return;
    
    const disasm = currentBlock.disassembly || currentBlock.ops;
    if (!disasm) return;
    
    const text = disasm
      .map(d => {
        const addr = ('addr' in d ? d.addr : d.offset?.toString(16)) || '';
        const op = ('opcode' in d ? d.opcode : '') || '';
        return `${addr}  ${op}`;
      })
      .join('\n');
    navigator.clipboard.writeText(text);
  }, [currentBlock]);

  // Get disassembly from current block (handle both formats)
  const blockDisasm = useMemo(() => {
    if (!currentBlock) return [];
    
    if (currentBlock.disassembly && currentBlock.disassembly.length > 0) {
      return currentBlock.disassembly;
    }
    
    if (currentBlock.ops && currentBlock.ops.length > 0) {
      return currentBlock.ops.map(op => ({
        addr: op.offset ? `0x${op.offset.toString(16)}` : '?',
        opcode: op.opcode || '',
        bytes: op.bytes || '',
      }));
    }
    
    return [];
  }, [currentBlock]);

  // Log CFG status for debugging
  const cfgStatus = useMemo(() => {
    const issues: string[] = [];
    
    if (nodes.length === 0) {
      issues.push('angr CFG nodes: 0 (angr may not be installed or analysis failed)');
    } else {
      issues.push(`angr CFG nodes: ${nodes.length}`);
    }
    
    if (edges.length === 0) {
      issues.push('angr CFG edges: 0');
    } else {
      issues.push(`angr CFG edges: ${edges.length}`);
    }
    
    if (functions.length === 0) {
      issues.push('radare2 function CFGs: 0 (run deep analysis)');
    } else {
      issues.push(`radare2 function CFGs: ${functions.length}`);
    }
    
    if (radareFunctions.length === 0) {
      issues.push('radare2 functions: 0');
    } else {
      issues.push(`radare2 functions: ${radareFunctions.length}`);
    }
    
    return {
      hasData: nodes.length > 0 || functions.length > 0 || radareFunctions.length > 0,
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
        <AccountTreeIcon sx={{ fontSize: 48, opacity: 0.3, animation: `${pulse} 3s ease-in-out infinite` }} />
        <Typography variant="body2" color="text.secondary">
          No CFG data available
        </Typography>
        <Typography variant="caption" color="text.secondary" sx={{ textAlign: 'center' }}>
          Run full analysis (not quick scan) to generate CFG
        </Typography>
        
        {/* Debug info */}
        <Paper variant="outlined" sx={{ mt: 2, p: 1.5, maxWidth: 350 }}>
          <Typography variant="caption" color="text.secondary" fontWeight={600} sx={{ display: 'block', mb: 0.5 }}>
            CFG Generation Checklist:
          </Typography>
          <Typography variant="caption" component="ul" sx={{ pl: 2, m: 0, color: 'text.secondary' }}>
            <li>Enable "Full Analysis" (not quick scan)</li>
            <li>angr must be installed: <code>pip install angr</code></li>
            <li>Binary must be a valid ELF/PE executable</li>
            <li>Check console logs for errors</li>
          </Typography>
          
          <Typography variant="caption" color="text.secondary" fontWeight={600} sx={{ display: 'block', mt: 1, mb: 0.5 }}>
            Debug Status:
          </Typography>
          <Box sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: 'text.secondary' }}>
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
            <ConfidenceIndicator confidence={confidence} compact />
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
                      {fn.name.length > 24 ? fn.name.slice(0, 24) + '…' : fn.name}
                    </Typography>
                  }
                  secondary={
                    <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.65rem' }}>
                      {fn.offset} · {fn.size}B
                    </Typography>
                  }
                />
                {fn.blocks && fn.blocks.length > 0 && (
                  <ChevronRightIcon sx={{ fontSize: 14, color: 'text.disabled', ml: 0.5 }} />
                )}
              </ListItemButton>
            ))}
          </List>
        </Box>
      </Paper>

      {/* Block viewer */}
      <Paper
        variant="outlined"
        sx={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          animation: `${fadeIn} 0.3s ease-out`,
          animationDelay: '0.1s',
          animationFillMode: 'backwards',
        }}
      >
        {selectedFunction && currentBlocks.length > 0 ? (
          <>
            {/* Header */}
            <Stack
              direction="row"
              alignItems="center"
              spacing={1}
              sx={{ p: 1, borderBottom: 1, borderColor: 'divider' }}
            >
              <Typography variant="caption" fontWeight={600}>
                {selectedFunction.name}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {selectedFunction.offset}
              </Typography>
              
              <Box sx={{ flex: 1 }} />
              
              <IconButton size="small" onClick={handlePrevBlock} disabled={selectedBlockIndex === 0}>
                <NavigateBeforeIcon sx={{ fontSize: 16 }} />
              </IconButton>
              <Chip
                size="small"
                label={`${selectedBlockIndex + 1}/${currentBlocks.length}`}
                sx={{ height: 18, fontSize: '0.65rem' }}
              />
              <IconButton size="small" onClick={handleNextBlock} disabled={selectedBlockIndex >= currentBlocks.length - 1}>
                <NavigateNextIcon sx={{ fontSize: 16 }} />
              </IconButton>
              
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
                    <Chip size="small" label={currentBlock.offset || '?'} variant="outlined" />
                    <Chip size="small" label={`${currentBlock.size || '?'}B`} variant="outlined" />
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
                      blockDisasm.map((insn, idx) => (
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
                              bgcolor: isDark ? alpha('#fff', 0.05) : alpha('#000', 0.04),
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
                      ))
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

      {/* Stats sidebar */}
      <Paper
        variant="outlined"
        sx={{
          width: 160,
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
        {/* Confidence indicator */}
        <ConfidenceIndicator confidence={confidence} />

        {/* Stats */}
        <Box>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1, fontWeight: 600 }}>
            CFG Stats
          </Typography>
          <Stack spacing={0.75}>
            <Box
              sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'baseline',
                animation: `${fadeIn} 0.2s ease-out`,
                animationDelay: '0.25s',
                animationFillMode: 'backwards',
              }}
            >
              <Typography variant="caption" color="text.secondary">Nodes</Typography>
              <Typography variant="body2" fontWeight={600}>{nodes.length.toLocaleString()}</Typography>
            </Box>
            <Box
              sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'baseline',
                animation: `${fadeIn} 0.2s ease-out`,
                animationDelay: '0.3s',
                animationFillMode: 'backwards',
              }}
            >
              <Typography variant="caption" color="text.secondary">Edges</Typography>
              <Typography variant="body2" fontWeight={600}>{edges.length.toLocaleString()}</Typography>
            </Box>
            <Box
              sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'baseline',
                animation: `${fadeIn} 0.2s ease-out`,
                animationDelay: '0.35s',
                animationFillMode: 'backwards',
              }}
            >
              <Typography variant="caption" color="text.secondary">Functions</Typography>
              <Typography variant="body2" fontWeight={600}>{allFunctions.length.toLocaleString()}</Typography>
            </Box>
            {angrActive > 0 && (
              <Box
                sx={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'baseline',
                  animation: `${fadeIn} 0.2s ease-out`,
                  pt: 0.5,
                  borderTop: 1,
                  borderColor: 'divider',
                }}
              >
                <Typography variant="caption" color="text.secondary">Active paths</Typography>
                <Typography variant="body2" fontWeight={600} color="info.main">{angrActive}</Typography>
              </Box>
            )}
            {angrFound > 0 && (
              <Box
                sx={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'baseline',
                  animation: `${fadeIn} 0.2s ease-out`,
                }}
              >
                <Typography variant="caption" color="text.secondary">Found</Typography>
                <Typography variant="body2" fontWeight={600} color="success.main">{angrFound}</Typography>
              </Box>
            )}
          </Stack>
        </Box>
      </Paper>
    </Box>
  );
};

export default CFGViewer;
