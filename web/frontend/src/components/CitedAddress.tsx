/**
 * CitedAddress component - renders address references with assembly hover.
 * 
 * When the LLM mentions an address like 0x1234, this component shows
 * the relevant assembly context on hover.
 */
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import {
  alpha,
  Box,
  Fade,
  IconButton,
  Paper,
  Popper,
  Stack,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import { FC, useCallback, useMemo, useRef, useState } from 'react';
import type { CodeCitation } from '../types';

interface CitedAddressProps {
  address: string;
  // Full disassembly text to search for context
  disassembly?: string;
  // Pre-computed citation if available
  citation?: CodeCitation;
  // Function to navigate to address in disassembly viewer
  onNavigate?: (address: string) => void;
}

// Parse disassembly to find context around an address
function findAddressContext(disassembly: string, targetAddress: string, contextLines: number = 5): CodeCitation | null {
  if (!disassembly) return null;
  
  const lines = disassembly.split('\n');
  const normalizedTarget = targetAddress.toLowerCase().replace(/^0x/, '');
  
  // Find the line containing this address
  let targetIndex = -1;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].toLowerCase();
    // Match address at start of instruction line
    const addrMatch = line.match(/0x([0-9a-f]+)/);
    if (addrMatch) {
      const lineAddr = addrMatch[1];
      if (lineAddr === normalizedTarget || lineAddr.endsWith(normalizedTarget)) {
        targetIndex = i;
        break;
      }
    }
  }
  
  if (targetIndex === -1) return null;
  
  // Extract context lines
  const start = Math.max(0, targetIndex - contextLines);
  const end = Math.min(lines.length, targetIndex + contextLines + 1);
  const contextLinesList = lines.slice(start, end);
  
  // Parse the target line for instruction details
  const targetLine = lines[targetIndex];
  const instrMatch = targetLine.match(/0x([0-9a-f]+)\s+([0-9a-f]+)?\s*(\w+(?:\.\w+)?)\s*(.*)/i);
  
  // Try to find function name from nearby labels
  let functionName: string | undefined;
  for (let i = targetIndex; i >= Math.max(0, targetIndex - 50); i--) {
    const line = lines[i];
    // Look for function label patterns
    const funcMatch = line.match(/;--\s*(\w+):|<(\w+)>:|^(\w+):$/);
    if (funcMatch) {
      functionName = funcMatch[1] || funcMatch[2] || funcMatch[3];
      break;
    }
  }
  
  return {
    address: targetAddress,
    function_name: functionName,
    instruction: instrMatch ? `${instrMatch[3]} ${instrMatch[4] || ''}`.trim() : undefined,
    bytes: instrMatch?.[2],
    context_lines: contextLinesList,
  };
}

// Syntax highlight a disassembly line
const HighlightedLine: FC<{ line: string; isTarget?: boolean }> = ({ line, isTarget }) => {
  const theme = useTheme();
  const isDark = theme.palette.mode === 'dark';
  
  // Colors for syntax highlighting
  const colors = {
    address: isDark ? '#6a9fb5' : '#0550ae',
    bytes: isDark ? '#555' : '#999',
    mnemonic: isDark ? '#b294bb' : '#a626a4',
    register: isDark ? '#cc6666' : '#c18401',
    immediate: isDark ? '#8abeb7' : '#0184bc',
    comment: isDark ? '#5a5a5a' : '#a0a0a0',
  };
  
  // Simple regex-based highlighting
  const parts: JSX.Element[] = [];
  let remaining = line;
  let key = 0;
  
  // Match address
  const addrMatch = remaining.match(/^(\s*[│├└─]*\s*)(0x[0-9a-f]+)/i);
  if (addrMatch) {
    parts.push(<span key={key++}>{addrMatch[1]}</span>);
    parts.push(<span key={key++} style={{ color: colors.address }}>{addrMatch[2]}</span>);
    remaining = remaining.slice(addrMatch[0].length);
  }
  
  // Match bytes (hex sequence)
  const bytesMatch = remaining.match(/^(\s+)([0-9a-f]{2,})/i);
  if (bytesMatch) {
    parts.push(<span key={key++}>{bytesMatch[1]}</span>);
    parts.push(<span key={key++} style={{ color: colors.bytes }}>{bytesMatch[2]}</span>);
    remaining = remaining.slice(bytesMatch[0].length);
  }
  
  // Match mnemonic
  const mnemonicMatch = remaining.match(/^(\s+)(\w+(?:\.\w+)?)/);
  if (mnemonicMatch) {
    parts.push(<span key={key++}>{mnemonicMatch[1]}</span>);
    parts.push(<span key={key++} style={{ color: colors.mnemonic, fontWeight: 500 }}>{mnemonicMatch[2]}</span>);
    remaining = remaining.slice(mnemonicMatch[0].length);
  }
  
  // Highlight operands
  if (remaining) {
    const tokens = remaining.split(/(\s+|,|\[|\])/);
    for (const token of tokens) {
      if (!token) continue;
      if (/^(r\d+|sp|lr|pc|fp|x\d+|w\d+|[re][abcd]x|[re][sd]i|[re]bp|[re]sp)$/i.test(token)) {
        parts.push(<span key={key++} style={{ color: colors.register }}>{token}</span>);
      } else if (/^#?-?0x[0-9a-f]+$/i.test(token) || /^#?-?\d+$/.test(token)) {
        parts.push(<span key={key++} style={{ color: colors.immediate }}>{token}</span>);
      } else if (/^;/.test(token)) {
        parts.push(<span key={key++} style={{ color: colors.comment }}>{token}</span>);
      } else {
        parts.push(<span key={key++}>{token}</span>);
      }
    }
  }
  
  return (
    <Box
      sx={{
        fontFamily: '"JetBrains Mono", "Fira Code", Consolas, monospace',
        fontSize: '0.7rem',
        lineHeight: 1.5,
        whiteSpace: 'pre',
        bgcolor: isTarget ? alpha(theme.palette.warning.main, 0.15) : 'transparent',
        borderLeft: isTarget ? `2px solid ${theme.palette.warning.main}` : '2px solid transparent',
        pl: 0.5,
        mx: -0.5,
      }}
    >
      {parts.length > 0 ? parts : line}
    </Box>
  );
};

export const CitedAddress: FC<CitedAddressProps> = ({
  address,
  disassembly,
  citation: precomputedCitation,
  onNavigate,
}) => {
  const theme = useTheme();
  const isDark = theme.palette.mode === 'dark';
  const anchorRef = useRef<HTMLSpanElement>(null);
  const [open, setOpen] = useState(false);
  
  // Compute citation from disassembly if not provided
  const citation = useMemo(() => {
    if (precomputedCitation) return precomputedCitation;
    if (!disassembly) return null;
    return findAddressContext(disassembly, address);
  }, [address, disassembly, precomputedCitation]);
  
  const handleMouseEnter = useCallback(() => {
    setOpen(true);
  }, []);
  
  const handleMouseLeave = useCallback(() => {
    setOpen(false);
  }, []);
  
  const handleNavigate = useCallback(() => {
    onNavigate?.(address);
    setOpen(false);
  }, [address, onNavigate]);
  
  // Determine which line is the target in context
  const targetLineIndex = useMemo(() => {
    if (!citation?.context_lines) return -1;
    const normalizedAddr = address.toLowerCase().replace(/^0x/, '');
    return citation.context_lines.findIndex(line => {
      const match = line.toLowerCase().match(/0x([0-9a-f]+)/);
      return match && (match[1] === normalizedAddr || match[1].endsWith(normalizedAddr));
    });
  }, [citation, address]);
  
  return (
    <>
      <Box
        component="span"
        ref={anchorRef}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        sx={{
          fontFamily: '"JetBrains Mono", Consolas, monospace',
          fontSize: '0.85em',
          color: citation ? 'primary.main' : 'text.primary',
          bgcolor: alpha(theme.palette.primary.main, 0.1),
          px: 0.5,
          py: 0.125,
          borderRadius: 0.5,
          cursor: citation ? 'pointer' : 'default',
          borderBottom: citation ? `1px dashed ${theme.palette.primary.main}` : 'none',
          transition: 'background-color 0.15s',
          '&:hover': {
            bgcolor: citation ? alpha(theme.palette.primary.main, 0.2) : undefined,
          },
        }}
      >
        {address}
      </Box>
      
      <Popper
        open={open && Boolean(citation)}
        anchorEl={anchorRef.current}
        placement="bottom-start"
        transition
        modifiers={[
          { name: 'offset', options: { offset: [0, 8] } },
          { name: 'preventOverflow', options: { padding: 16 } },
        ]}
        sx={{ zIndex: theme.zIndex.tooltip }}
      >
        {({ TransitionProps }) => (
          <Fade {...TransitionProps} timeout={150}>
            <Paper
              elevation={8}
              onMouseEnter={handleMouseEnter}
              onMouseLeave={handleMouseLeave}
              sx={{
                maxWidth: 520,
                minWidth: 360,
                overflow: 'hidden',
                border: `1px solid ${isDark ? '#30363d' : '#d0d7de'}`,
              }}
            >
              {/* Header */}
              <Box
                sx={{
                  px: 1.5,
                  py: 1,
                  bgcolor: isDark ? '#161b22' : '#f6f8fa',
                  borderBottom: `1px solid ${isDark ? '#21262d' : '#d0d7de'}`,
                }}
              >
                <Stack direction="row" alignItems="center" justifyContent="space-between">
                  <Stack direction="row" alignItems="center" spacing={1}>
                    <InfoOutlinedIcon sx={{ fontSize: 16, color: 'primary.main' }} />
                    <Typography variant="caption" fontWeight={600} sx={{ fontFamily: 'monospace' }}>
                      {address}
                    </Typography>
                    {citation?.function_name && (
                      <Typography variant="caption" color="text.secondary">
                        in {citation.function_name}
                      </Typography>
                    )}
                  </Stack>
                  {onNavigate && (
                    <Tooltip title="Go to address">
                      <IconButton size="small" onClick={handleNavigate}>
                        <OpenInNewIcon sx={{ fontSize: 14 }} />
                      </IconButton>
                    </Tooltip>
                  )}
                </Stack>
                
                {citation?.instruction && (
                  <Typography
                    variant="body2"
                    sx={{
                      mt: 0.5,
                      fontFamily: 'monospace',
                      fontSize: '0.75rem',
                      color: isDark ? '#b294bb' : '#a626a4',
                    }}
                  >
                    {citation.instruction}
                  </Typography>
                )}
              </Box>
              
              {/* Context code */}
              {citation?.context_lines && citation.context_lines.length > 0 && (
                <Box
                  sx={{
                    p: 1,
                    bgcolor: isDark ? '#0d1117' : '#ffffff',
                    maxHeight: 280,
                    overflow: 'auto',
                    '&::-webkit-scrollbar': { width: 6 },
                    '&::-webkit-scrollbar-thumb': {
                      bgcolor: isDark ? '#30363d' : '#c1c1c1',
                      borderRadius: 3,
                    },
                  }}
                >
                  {citation.context_lines.map((line, i) => (
                    <HighlightedLine
                      key={i}
                      line={line}
                      isTarget={i === targetLineIndex}
                    />
                  ))}
                </Box>
              )}
              
              {/* Footer hint */}
              <Box
                sx={{
                  px: 1.5,
                  py: 0.5,
                  bgcolor: isDark ? '#161b22' : '#f6f8fa',
                  borderTop: `1px solid ${isDark ? '#21262d' : '#d0d7de'}`,
                }}
              >
                <Typography variant="caption" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                  Click icon to navigate • Yellow = target address
                </Typography>
              </Box>
            </Paper>
          </Fade>
        )}
      </Popper>
    </>
  );
};

export default CitedAddress;

