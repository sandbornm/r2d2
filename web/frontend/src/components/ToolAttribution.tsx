import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import RadioButtonUncheckedIcon from '@mui/icons-material/RadioButtonUnchecked';
import { alpha, Box, Chip, Stack, Tooltip, Typography, useTheme } from '@mui/material';
import { FC, useMemo } from 'react';
import { toolColors } from '../theme';
import type { ToolStatusInfo } from '../types';

// Tool configuration with beginner-friendly descriptions
const TOOL_INFO = {
  radare2: {
    displayName: 'radare2',
    shortName: 'r2',
    description: 'Disassembles your binary into readable assembly code and extracts functions, imports, and strings.',
    produces: 'Disassembly, functions, imports, strings, binary metadata',
    icon: 'terminal',
  },
  angr: {
    displayName: 'angr',
    shortName: 'angr',
    description: 'Symbolic execution engine that builds Control Flow Graphs (CFG) and analyzes execution paths.',
    produces: 'CFG nodes/edges, reachability analysis, path constraints',
    icon: 'graph',
  },
  ghidra: {
    displayName: 'Ghidra',
    shortName: 'ghidra',
    description: 'NSA reverse engineering tool that decompiles assembly back to C-like pseudocode.',
    produces: 'Decompiled C code, type information, cross-references',
    icon: 'code',
  },
  capstone: {
    displayName: 'Capstone',
    shortName: 'cap',
    description: 'Multi-architecture disassembly framework for accurate instruction decoding.',
    produces: 'Instruction-level disassembly with operand details',
    icon: 'cpu',
  },
  frida: {
    displayName: 'Frida',
    shortName: 'frida',
    description: 'Dynamic instrumentation toolkit for runtime analysis and hooking.',
    produces: 'Runtime module info, memory layout, hook points',
    icon: 'hook',
  },
  gef: {
    displayName: 'GEF/GDB',
    shortName: 'gef',
    description: 'GDB Enhanced Features for dynamic analysis with execution tracing in isolated Docker container.',
    produces: 'Register snapshots, memory maps, execution traces',
    icon: 'debug',
  },
  libmagic: {
    displayName: 'libmagic',
    shortName: 'magic',
    description: 'File type identification using magic number signatures (same as the `file` command).',
    produces: 'File type, MIME type, encoding detection',
    icon: 'file',
  },
  autoprofile: {
    displayName: 'AutoProfile',
    shortName: 'profile',
    description: 'Quick binary profiling: security features (RELRO, NX, PIE), strings, and risk analysis.',
    produces: 'Security profile, interesting strings, risk assessment',
    icon: 'shield',
  },
  dwarf: {
    displayName: 'DWARF',
    shortName: 'dwarf',
    description: 'Debug information parser for extracting symbols, types, and source mappings.',
    produces: 'Debug symbols, type definitions, source line mappings',
    icon: 'info',
  },
} as const;

type ToolName = keyof typeof TOOL_INFO;

// Mapping from backend result keys to tool names
const KEY_TO_TOOL: Record<string, ToolName> = {
  autoprofile: 'autoprofile',
  radare2: 'radare2',
  angr: 'angr',
  capstone: 'capstone',
  ghidra: 'ghidra',
  frida: 'frida',
  gef: 'gef',
  dwarf: 'dwarf',
  identification: 'libmagic',
  libmagic: 'libmagic',
};

// Order of tools to display (most important first)
const TOOL_ORDER: ToolName[] = ['radare2', 'angr', 'ghidra', 'capstone', 'gef', 'frida', 'autoprofile', 'libmagic', 'dwarf'];

interface ToolAttributionProps {
  quickScan?: Record<string, unknown>;
  deepScan?: Record<string, unknown>;
  toolAvailability?: Record<string, boolean>;  // Which tools were available during analysis
  toolsInfo?: Record<string, ToolStatusInfo>;  // Detailed tool info from health endpoint
  compact?: boolean;
}

const ToolAttribution: FC<ToolAttributionProps> = ({
  quickScan = {},
  deepScan = {},
  toolAvailability = {},
  toolsInfo = {},
  compact = false,
}) => {
  const theme = useTheme();
  const isDark = theme.palette.mode === 'dark';

  // Detect which tools were used
  const toolsUsed = useMemo(() => {
    const used = new Set<ToolName>();

    for (const key of Object.keys(quickScan)) {
      const toolName = KEY_TO_TOOL[key.toLowerCase()];
      if (toolName) used.add(toolName);
    }

    for (const key of Object.keys(deepScan)) {
      const toolName = KEY_TO_TOOL[key.toLowerCase()];
      if (toolName) used.add(toolName);
    }

    return used;
  }, [quickScan, deepScan]);

  // Check tool availability - map from backend names to our tool names
  const getToolAvailable = (name: ToolName): boolean | undefined => {
    // Try exact match from toolAvailability first (from analysis result)
    if (name in toolAvailability) {
      return toolAvailability[name];
    }
    // Then try toolsInfo from health endpoint
    if (name in toolsInfo) {
      return toolsInfo[name].available;
    }
    // Handle special cases (libmagic vs identification)
    if (name === 'libmagic') {
      if ('libmagic' in toolAvailability) return toolAvailability['libmagic'];
      if ('libmagic' in toolsInfo) return toolsInfo['libmagic'].available;
    }
    return undefined; // Unknown
  };

  // Get install hint for a tool
  const getInstallHint = (name: ToolName): string | undefined => {
    if (name in toolsInfo) {
      return toolsInfo[name].install_hint;
    }
    return undefined;
  };

  const activeCount = toolsUsed.size;

  if (activeCount === 0) {
    return null;
  }

  // Get color for a tool
  const getToolColor = (name: ToolName): string => {
    return toolColors[name as keyof typeof toolColors] || theme.palette.grey[500];
  };

  // Build tooltip content
  const getTooltipContent = (name: ToolName, isUsed: boolean) => {
    const info = TOOL_INFO[name];
    const isAvailable = getToolAvailable(name);
    const installHint = getInstallHint(name);
    
    return (
      <Box sx={{ maxWidth: 300, p: 0.5 }}>
        <Typography variant="body2" sx={{ fontWeight: 600, mb: 0.75, color: 'inherit' }}>
          {info.displayName}
        </Typography>
        <Typography variant="caption" sx={{ display: 'block', mb: 1, lineHeight: 1.5 }}>
          {info.description}
        </Typography>
        {isUsed && info.produces && (
          <Box
            sx={{
              p: 1,
              borderRadius: 1,
              bgcolor: alpha(theme.palette.success.main, 0.1),
              border: `1px solid ${alpha(theme.palette.success.main, 0.2)}`,
            }}
          >
            <Typography variant="caption" color="success.main" sx={{ fontWeight: 500 }}>
              Output: {info.produces}
            </Typography>
          </Box>
        )}
        {!isUsed && isAvailable === false && (
          <Box>
            <Typography variant="caption" color="error.main" sx={{ fontWeight: 500 }}>
              ⚠ Not installed
            </Typography>
            {installHint && (
              <Typography 
                variant="caption" 
                sx={{ 
                  display: 'block', 
                  mt: 0.5, 
                  fontFamily: 'monospace',
                  fontSize: '0.65rem',
                  color: 'warning.main',
                  bgcolor: alpha(theme.palette.warning.main, 0.1),
                  p: 0.5,
                  borderRadius: 0.5,
                }}
              >
                → {installHint}
              </Typography>
            )}
          </Box>
        )}
        {!isUsed && isAvailable === true && (
          <Typography variant="caption" color="warning.main" sx={{ fontStyle: 'italic' }}>
            Available but not used in this analysis
          </Typography>
        )}
        {!isUsed && isAvailable === undefined && (
          <Typography variant="caption" color="text.secondary" sx={{ fontStyle: 'italic' }}>
            Status unknown
          </Typography>
        )}
      </Box>
    );
  };

  if (compact) {
    // Compact mode: inline badges
    return (
      <Stack direction="row" spacing={0.75} alignItems="center" flexWrap="wrap" gap={0.5}>
        <Typography variant="caption" color="text.secondary" sx={{ mr: 0.5 }}>
          Tools:
        </Typography>
        {TOOL_ORDER.filter((name) => toolsUsed.has(name)).map((name) => {
          const info = TOOL_INFO[name];
          const color = getToolColor(name);
          return (
            <Tooltip key={name} title={getTooltipContent(name, true)} arrow placement="top">
              <Chip
                size="small"
                label={info.shortName}
                sx={{
                  height: 20,
                  fontSize: '0.65rem',
                  fontWeight: 500,
                  bgcolor: alpha(color, isDark ? 0.2 : 0.12),
                  color: color,
                  border: `1px solid ${alpha(color, 0.3)}`,
                  cursor: 'help',
                  '& .MuiChip-label': { px: 0.75 },
                }}
              />
            </Tooltip>
          );
        })}
      </Stack>
    );
  }

  // Full mode: card with all tools
  return (
    <Box
      sx={{
        p: 2,
        borderRadius: 2,
        bgcolor: isDark ? alpha(theme.palette.common.white, 0.02) : alpha(theme.palette.common.black, 0.02),
        border: 1,
        borderColor: 'divider',
      }}
    >
      <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1.5}>
        <Typography variant="caption" color="text.secondary" fontWeight={600}>
          Analysis Tools
        </Typography>
        <Chip
          size="small"
          label={`${activeCount} active`}
          sx={{
            height: 18,
            fontSize: '0.65rem',
            bgcolor: alpha(theme.palette.primary.main, 0.1),
            color: 'primary.main',
          }}
        />
      </Stack>
      <Stack direction="row" spacing={1} flexWrap="wrap" gap={1}>
        {TOOL_ORDER.map((name) => {
          const info = TOOL_INFO[name];
          const isUsed = toolsUsed.has(name);
          const isAvailable = getToolAvailable(name);
          const color = getToolColor(name);

          // Determine icon based on state
          let icon;
          if (isUsed) {
            icon = <CheckCircleIcon sx={{ fontSize: 14, color: `${color} !important` }} />;
          } else if (isAvailable === false) {
            icon = <ErrorOutlineIcon sx={{ fontSize: 14, color: `${theme.palette.error.main} !important` }} />;
          } else {
            icon = <RadioButtonUncheckedIcon sx={{ fontSize: 14, opacity: 0.4 }} />;
          }

          return (
            <Tooltip key={name} title={getTooltipContent(name, isUsed)} arrow placement="top">
              <Chip
                icon={icon}
                label={info.displayName}
                size="small"
                sx={{
                  height: 26,
                  bgcolor: isUsed 
                    ? alpha(color, isDark ? 0.15 : 0.1) 
                    : isAvailable === false
                      ? alpha(theme.palette.error.main, isDark ? 0.1 : 0.05)
                      : 'transparent',
                  color: isUsed ? color : isAvailable === false ? 'error.main' : 'text.disabled',
                  border: `1px solid ${
                    isUsed 
                      ? alpha(color, 0.3) 
                      : isAvailable === false 
                        ? alpha(theme.palette.error.main, 0.3)
                        : 'divider'
                  }`,
                  opacity: isUsed ? 1 : isAvailable === false ? 0.8 : 0.5,
                  cursor: 'help',
                  fontWeight: isUsed ? 500 : 400,
                  transition: 'all 0.15s ease',
                  '&:hover': {
                    bgcolor: isUsed 
                      ? alpha(color, isDark ? 0.2 : 0.15) 
                      : alpha(theme.palette.action.hover, 0.5),
                    opacity: 1,
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
