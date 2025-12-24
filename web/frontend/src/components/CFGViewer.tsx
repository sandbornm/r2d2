import AccountTreeIcon from '@mui/icons-material/AccountTree';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import NavigateBeforeIcon from '@mui/icons-material/NavigateBefore';
import NavigateNextIcon from '@mui/icons-material/NavigateNext';
import {
  Box,
  Chip,
  IconButton,
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
        }}
      >
        <AccountTreeIcon sx={{ fontSize: 48, opacity: 0.3 }} />
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
        }}
      >
        <Box sx={{ p: 1, borderBottom: 1, borderColor: 'divider' }}>
          <Typography variant="caption" color="text.secondary">
            Functions ({allFunctions.length})
          </Typography>
        </Box>
        <Box sx={{ flex: 1, overflow: 'auto' }}>
          <List dense disablePadding>
            {allFunctions.slice(0, 50).map((fn, idx) => (
              <ListItemButton
                key={`fn-${idx}`}
                selected={selectedFunction?.offset === fn.offset}
                onClick={() => handleSelectFunction(fn)}
                sx={{ py: 0.5, px: 1 }}
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
                            '&:hover': { bgcolor: 'action.hover' },
                          }}
                        >
                          <Typography
                            component="span"
                            sx={{ color: 'text.secondary', minWidth: 80 }}
                          >
                            {insn.addr}
                          </Typography>
                          <Typography component="span" sx={{ color: 'primary.main' }}>
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
          width: 140,
          flexShrink: 0,
          p: 1,
        }}
      >
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
          CFG Stats
        </Typography>
        <Stack spacing={0.5}>
          <Box>
            <Typography variant="caption" color="text.secondary">Nodes</Typography>
            <Typography variant="body2" fontWeight={600}>{nodes.length}</Typography>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary">Edges</Typography>
            <Typography variant="body2" fontWeight={600}>{edges.length}</Typography>
          </Box>
          <Box>
            <Typography variant="caption" color="text.secondary">Functions</Typography>
            <Typography variant="body2" fontWeight={600}>{allFunctions.length}</Typography>
          </Box>
          {angrActive > 0 && (
            <Box>
              <Typography variant="caption" color="text.secondary">Active paths</Typography>
              <Typography variant="body2" fontWeight={600}>{angrActive}</Typography>
            </Box>
          )}
          {angrFound > 0 && (
            <Box>
              <Typography variant="caption" color="text.secondary">Found</Typography>
              <Typography variant="body2" fontWeight={600}>{angrFound}</Typography>
            </Box>
          )}
        </Stack>
      </Paper>
    </Box>
  );
};

export default CFGViewer;
