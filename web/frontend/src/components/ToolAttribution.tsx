import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import RadioButtonUncheckedIcon from '@mui/icons-material/RadioButtonUnchecked';
import { Box, Chip, Stack, Tooltip, Typography, useTheme } from '@mui/material';
import { FC, useMemo } from 'react';

// Tool configuration with beginner-friendly descriptions
// These descriptions help users understand what each tool contributes to the analysis
const TOOL_INFO = {
  autoprofile: {
    displayName: 'AutoProfile',
    description: 'Quick binary profiling: security features (RELRO, NX, PIE), strings, and risk analysis',
    color: 'primary' as const,
    produces: 'Security profile, interesting strings, risk assessment',
  },
  radare2: {
    displayName: 'radare2',
    description: 'Disassembles your binary into readable assembly code and extracts functions/imports',
    color: 'success' as const,
    produces: 'Disassembly, functions, imports, strings, binary metadata',
  },
  angr: {
    displayName: 'angr',
    description: 'Symbolic execution engine that builds Control Flow Graphs (CFG) and analyzes execution paths',
    color: 'info' as const,
    produces: 'CFG nodes/edges, reachability analysis, path constraints',
  },
  capstone: {
    displayName: 'Capstone',
    description: 'Multi-architecture disassembly framework for accurate instruction decoding',
    color: 'secondary' as const,
    produces: 'Instruction-level disassembly with operand details',
  },
  ghidra: {
    displayName: 'Ghidra',
    description: 'NSA reverse engineering tool that decompiles assembly back to C-like pseudocode',
    color: 'warning' as const,
    produces: 'Decompiled C code, type information, cross-references',
  },
  frida: {
    displayName: 'Frida',
    description: 'Dynamic instrumentation toolkit for runtime analysis and hooking',
    color: 'error' as const,
    produces: 'Runtime module info, memory layout, hook points',
  },
  gef: {
    displayName: 'GEF/GDB',
    description: 'GDB Enhanced Features for dynamic analysis with execution tracing in isolated Docker container',
    color: 'error' as const,
    produces: 'Register snapshots, memory maps, execution traces',
  },
  libmagic: {
    displayName: 'libmagic',
    description: 'File type identification using magic number signatures (same as the `file` command)',
    color: 'default' as const,
    produces: 'File type, MIME type, encoding detection',
  },
  dwarf: {
    displayName: 'DWARF',
    description: 'Debug information parser for extracting symbols, types, and source mappings from debug sections',
    color: 'secondary' as const,
    produces: 'Debug symbols, type definitions, source line mappings',
  },
} as const;

type ToolName = keyof typeof TOOL_INFO;

// Mapping from backend result keys to tool names (some tools store data under different keys)
const KEY_TO_TOOL: Record<string, ToolName> = {
  autoprofile: 'autoprofile',
  radare2: 'radare2',
  angr: 'angr',
  capstone: 'capstone',
  ghidra: 'ghidra',
  frida: 'frida',
  gef: 'gef',
  dwarf: 'dwarf',
  identification: 'libmagic', // libmagic stores data under "identification" key
  libmagic: 'libmagic',
};

interface ToolAttributionProps {
  quickScan?: Record<string, unknown>;
  deepScan?: Record<string, unknown>;
  compact?: boolean;
}

const ToolAttribution: FC<ToolAttributionProps> = ({
  quickScan = {},
  deepScan = {},
  compact = false,
}) => {
  const theme = useTheme();

  // Detect which tools were used based on scan results
  const toolsUsed = useMemo(() => {
    const used: Record<ToolName, boolean> = {
      autoprofile: false,
      radare2: false,
      angr: false,
      capstone: false,
      ghidra: false,
      frida: false,
      gef: false,
      libmagic: false,
      dwarf: false,
    };

    // Check quick scan results - map keys to tool names
    for (const key of Object.keys(quickScan)) {
      const lowerKey = key.toLowerCase();
      const toolName = KEY_TO_TOOL[lowerKey];
      if (toolName && toolName in used) {
        used[toolName] = true;
      }
    }

    // Check deep scan results - map keys to tool names
    for (const key of Object.keys(deepScan)) {
      const lowerKey = key.toLowerCase();
      const toolName = KEY_TO_TOOL[lowerKey];
      if (toolName && toolName in used) {
        used[toolName] = true;
      }
    }

    return used;
  }, [quickScan, deepScan]);

  // Count active tools
  const activeCount = useMemo(
    () => Object.values(toolsUsed).filter(Boolean).length,
    [toolsUsed]
  );

  if (activeCount === 0) {
    return null;
  }

  // Order tools by whether they're used (active first)
  const orderedTools = useMemo(() => {
    const tools = Object.entries(TOOL_INFO) as [ToolName, (typeof TOOL_INFO)[ToolName]][];
    return tools.sort((a, b) => {
      const aUsed = toolsUsed[a[0]] ? 1 : 0;
      const bUsed = toolsUsed[b[0]] ? 1 : 0;
      return bUsed - aUsed;
    });
  }, [toolsUsed]);

  // Build detailed tooltip content
  const getTooltipContent = (info: (typeof TOOL_INFO)[ToolName], isUsed: boolean) => (
    <Box sx={{ maxWidth: 280 }}>
      <Typography variant="body2" sx={{ fontWeight: 600, mb: 0.5 }}>
        {info.displayName}
      </Typography>
      <Typography variant="caption" sx={{ display: 'block', mb: 0.5 }}>
        {info.description}
      </Typography>
      {isUsed && info.produces && (
        <Typography variant="caption" color="success.light" sx={{ display: 'block', fontStyle: 'italic' }}>
          Produced: {info.produces}
        </Typography>
      )}
      {!isUsed && (
        <Typography variant="caption" color="warning.light" sx={{ display: 'block', fontStyle: 'italic' }}>
          Not enabled or unavailable
        </Typography>
      )}
    </Box>
  );

  if (compact) {
    // Compact mode: just show active tool names
    return (
      <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap" gap={0.5}>
        <Typography
          variant="caption"
          color="text.secondary"
          sx={{ fontSize: '0.65rem', mr: 0.5 }}
        >
          Powered by:
        </Typography>
        {orderedTools
          .filter(([name]) => toolsUsed[name])
          .map(([name, info]) => (
            <Tooltip key={name} title={getTooltipContent(info, true)} arrow>
              <Chip
                size="small"
                label={info.displayName}
                color={info.color}
                variant="outlined"
                sx={{
                  height: 18,
                  fontSize: '0.6rem',
                  '& .MuiChip-label': { px: 0.75 },
                }}
              />
            </Tooltip>
          ))}
      </Stack>
    );
  }

  // Full mode: show all tools with status
  return (
    <Box
      sx={{
        p: 1.5,
        borderRadius: 1,
        bgcolor: theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.02)' : 'rgba(0,0,0,0.02)',
        border: 1,
        borderColor: 'divider',
      }}
    >
      <Typography
        variant="caption"
        color="text.secondary"
        sx={{ fontWeight: 600, display: 'block', mb: 1 }}
      >
        Analysis Tools ({activeCount} active)
      </Typography>
      <Stack direction="row" spacing={1} flexWrap="wrap" gap={1}>
        {orderedTools.map(([name, info]) => {
          const isUsed = toolsUsed[name];
          return (
            <Tooltip key={name} title={getTooltipContent(info, isUsed)} arrow placement="top">
              <Chip
                icon={
                  isUsed ? (
                    <CheckCircleIcon sx={{ fontSize: 14 }} />
                  ) : (
                    <RadioButtonUncheckedIcon sx={{ fontSize: 14, opacity: 0.5 }} />
                  )
                }
                label={info.displayName}
                size="small"
                color={isUsed ? info.color : 'default'}
                variant={isUsed ? 'filled' : 'outlined'}
                sx={{
                  opacity: isUsed ? 1 : 0.5,
                  cursor: 'help',
                  '& .MuiChip-label': {
                    fontWeight: isUsed ? 500 : 400,
                  },
                }}
              />
            </Tooltip>
          );
        })}
      </Stack>
    </Box>
  );
};

export default ToolAttribution;
