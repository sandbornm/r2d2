import ChatIcon from '@mui/icons-material/Chat';
import CodeIcon from '@mui/icons-material/Code';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Chip,
  IconButton,
  List,
  ListItemButton,
  ListItemText,
  Paper,
  Stack,
  Theme,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import { FC, useState } from 'react';
import type { GhidraData, GhidraDecompiledFunction, GhidraTypeInfo } from '../types';

interface DecompilerPanelProps {
  data: GhidraData | null;
  onAskClaude?: (question: string) => void;
}

// Simple syntax highlighting for C code
const highlightCCode = (code: string, theme: Theme): string => {
  const isDark = theme.palette.mode === 'dark';

  // Colors for syntax highlighting
  const colors = {
    keyword: isDark ? '#c678dd' : '#a626a4',
    type: isDark ? '#e5c07b' : '#c18401',
    string: isDark ? '#98c379' : '#50a14f',
    number: isDark ? '#d19a66' : '#986801',
    comment: isDark ? '#5c6370' : '#a0a1a7',
    function: isDark ? '#61afef' : '#4078f2',
    operator: isDark ? '#56b6c2' : '#0184bc',
  };

  // Keywords
  const keywords = ['if', 'else', 'while', 'for', 'return', 'break', 'continue', 'switch', 'case', 'default', 'do', 'goto', 'sizeof', 'typedef', 'struct', 'union', 'enum', 'const', 'static', 'extern', 'register', 'volatile'];

  // Types
  const types = ['void', 'int', 'char', 'short', 'long', 'float', 'double', 'unsigned', 'signed', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t', 'size_t', 'bool', 'BOOL', 'DWORD', 'WORD', 'BYTE'];

  let result = code;

  // Escape HTML
  result = result
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // Comments (simple line and block comments)
  result = result.replace(/(\/\/[^\n]*)/g, `<span style="color:${colors.comment}">$1</span>`);
  result = result.replace(/(\/\*[\s\S]*?\*\/)/g, `<span style="color:${colors.comment}">$1</span>`);

  // Strings
  result = result.replace(/("(?:[^"\\]|\\.)*")/g, `<span style="color:${colors.string}">$1</span>`);
  result = result.replace(/('(?:[^'\\]|\\.)*')/g, `<span style="color:${colors.string}">$1</span>`);

  // Numbers (hex and decimal)
  result = result.replace(/\b(0x[0-9a-fA-F]+)\b/g, `<span style="color:${colors.number}">$1</span>`);
  result = result.replace(/\b(\d+)\b/g, `<span style="color:${colors.number}">$1</span>`);

  // Keywords
  for (const kw of keywords) {
    const regex = new RegExp(`\\b(${kw})\\b`, 'g');
    result = result.replace(regex, `<span style="color:${colors.keyword};font-weight:bold">$1</span>`);
  }

  // Types
  for (const t of types) {
    const regex = new RegExp(`\\b(${t})\\b`, 'g');
    result = result.replace(regex, `<span style="color:${colors.type}">$1</span>`);
  }

  return result;
};

const FunctionListItem: FC<{
  func: GhidraDecompiledFunction;
  selected: boolean;
  onClick: () => void;
}> = ({ func, selected, onClick }) => {
  return (
    <ListItemButton
      selected={selected}
      onClick={onClick}
      sx={{
        py: 0.5,
        borderRadius: 1,
        '&.Mui-selected': {
          bgcolor: 'action.selected',
        },
      }}
    >
      <ListItemText
        primary={
          <Typography variant="body2" fontFamily="monospace" noWrap>
            {func.name}
          </Typography>
        }
        secondary={
          <Typography variant="caption" color="text.secondary" noWrap>
            {func.address} · {func.return_type}
          </Typography>
        }
      />
    </ListItemButton>
  );
};

const TypesExplorer: FC<{ types: GhidraTypeInfo[] }> = ({ types }) => {
  const theme = useTheme();

  // Group types by kind
  const structs = types.filter((t) => t.kind === 'struct');
  const enums = types.filter((t) => t.kind === 'enum');
  const others = types.filter((t) => t.kind !== 'struct' && t.kind !== 'enum');

  const TypeGroup: FC<{ title: string; items: GhidraTypeInfo[] }> = ({ title, items }) => {
    if (items.length === 0) return null;

    return (
      <Accordion defaultExpanded={items.length <= 10} disableGutters>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="caption" fontWeight={600}>
            {title} ({items.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails sx={{ p: 0 }}>
          <List dense disablePadding>
            {items.map((t, i) => (
              <Box
                key={i}
                sx={{
                  px: 1.5,
                  py: 0.5,
                  borderBottom: `1px solid ${theme.palette.divider}`,
                  '&:last-child': { borderBottom: 0 },
                }}
              >
                <Typography variant="caption" fontFamily="monospace" fontWeight={500}>
                  {t.name}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
                  ({t.size} bytes)
                </Typography>
                {t.members.length > 0 && (
                  <Box sx={{ pl: 2, mt: 0.5 }}>
                    {t.members.slice(0, 5).map((m, j) => (
                      <Typography
                        key={j}
                        variant="caption"
                        color="text.secondary"
                        sx={{ display: 'block', fontFamily: 'monospace' }}
                      >
                        {t.kind === 'enum'
                          ? `${m.name} = ${m.value}`
                          : `${m.type || '?'} ${m.name}`}
                      </Typography>
                    ))}
                    {t.members.length > 5 && (
                      <Typography variant="caption" color="text.disabled">
                        ... {t.members.length - 5} more
                      </Typography>
                    )}
                  </Box>
                )}
              </Box>
            ))}
          </List>
        </AccordionDetails>
      </Accordion>
    );
  };

  return (
    <Box>
      <TypeGroup title="Structs" items={structs} />
      <TypeGroup title="Enums" items={enums} />
      <TypeGroup title="Other" items={others} />
    </Box>
  );
};

const DecompilerPanel: FC<DecompilerPanelProps> = ({ data, onAskClaude }) => {
  const theme = useTheme();
  const [selectedIndex, setSelectedIndex] = useState(0);

  if (!data || data.decompiled_count === 0) {
    return (
      <Box
        sx={{
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'text.secondary',
          p: 3,
        }}
      >
        <CodeIcon sx={{ fontSize: 40, mb: 1.5, opacity: 0.4 }} />
        <Typography variant="body2">No decompiled code available</Typography>
        <Typography variant="caption" color="text.secondary" sx={{ textAlign: 'center', mt: 1 }}>
          {data?.mode === 'bridge'
            ? 'Connect Ghidra with bridge server to see decompiled code'
            : 'Enable Ghidra bridge mode for decompilation'}
        </Typography>
      </Box>
    );
  }

  const decompiled = data.decompiled || [];
  const selectedFunc = decompiled[selectedIndex] || null;

  const handleAskAboutFunction = () => {
    if (!selectedFunc || !onAskClaude) return;

    const question = `Explain this decompiled function:\n\n\`\`\`c\n${selectedFunc.decompiled_c}\n\`\`\``;
    onAskClaude(question);
  };

  return (
    <Box sx={{ height: '100%', display: 'flex' }}>
      {/* Left sidebar: Function list */}
      <Paper
        variant="outlined"
        sx={{
          width: 220,
          flexShrink: 0,
          overflow: 'auto',
          borderRadius: 0,
          borderLeft: 0,
          borderTop: 0,
          borderBottom: 0,
        }}
      >
        <Box sx={{ p: 1, borderBottom: 1, borderColor: 'divider' }}>
          <Typography variant="caption" color="text.secondary" fontWeight={600}>
            Functions ({decompiled.length})
          </Typography>
        </Box>
        <List dense disablePadding sx={{ py: 0.5 }}>
          {decompiled.map((func, i) => (
            <FunctionListItem
              key={i}
              func={func}
              selected={i === selectedIndex}
              onClick={() => setSelectedIndex(i)}
            />
          ))}
        </List>
      </Paper>

      {/* Main area: Decompiled code */}
      <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {selectedFunc && (
          <>
            {/* Function header */}
            <Box
              sx={{
                p: 1,
                borderBottom: 1,
                borderColor: 'divider',
                bgcolor: theme.palette.mode === 'dark' ? 'grey.900' : 'grey.50',
              }}
            >
              <Stack direction="row" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography variant="body2" fontFamily="monospace" fontWeight={600}>
                    {selectedFunc.name}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" fontFamily="monospace">
                    {selectedFunc.signature}
                  </Typography>
                </Box>
                <Stack direction="row" spacing={0.5} alignItems="center">
                  <Chip label={selectedFunc.address} size="small" variant="outlined" />
                  {selectedFunc.calling_convention && (
                    <Chip label={selectedFunc.calling_convention} size="small" color="info" variant="outlined" />
                  )}
                  {onAskClaude && (
                    <Tooltip title="Ask Claude about this function">
                      <IconButton size="small" onClick={handleAskAboutFunction}>
                        <ChatIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  )}
                </Stack>
              </Stack>
            </Box>

            {/* Code area */}
            <Box
              sx={{
                flex: 1,
                overflow: 'auto',
                p: 1.5,
                fontFamily: 'monospace',
                fontSize: '0.75rem',
                lineHeight: 1.6,
                bgcolor: theme.palette.mode === 'dark' ? '#1e1e1e' : '#fafafa',
                whiteSpace: 'pre',
              }}
              dangerouslySetInnerHTML={{
                __html: highlightCCode(selectedFunc.decompiled_c ?? '', theme),
              }}
            />
          </>
        )}
      </Box>

      {/* Right panel: Types explorer */}
      {data.types && data.types.length > 0 && (
        <Paper
          variant="outlined"
          sx={{
            width: 200,
            flexShrink: 0,
            overflow: 'auto',
            borderRadius: 0,
            borderRight: 0,
            borderTop: 0,
            borderBottom: 0,
          }}
        >
          <Box sx={{ p: 1, borderBottom: 1, borderColor: 'divider' }}>
            <Typography variant="caption" color="text.secondary" fontWeight={600}>
              Types ({data.types.length})
            </Typography>
          </Box>
          <TypesExplorer types={data.types} />
        </Paper>
      )}
    </Box>
  );
};

export default DecompilerPanel;
