import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import RadioButtonUncheckedIcon from '@mui/icons-material/RadioButtonUnchecked';
import { Box, Chip, Stack, Tooltip, Typography, useTheme } from '@mui/material';
import { FC, useMemo } from 'react';

// Tool configuration with beginner-friendly descriptions
const TOOL_INFO = {
  radare2: {
    displayName: 'radare2',
    description: 'Disassembles your binary into readable assembly code',
    color: 'success' as const,
  },
  angr: {
    displayName: 'angr',
    description: 'Analyzes all possible execution paths in your program',
    color: 'info' as const,
  },
  capstone: {
    displayName: 'Capstone',
    description: 'Decodes individual CPU instructions with high accuracy',
    color: 'secondary' as const,
  },
  ghidra: {
    displayName: 'Ghidra',
    description: 'Decompiles assembly back to C-like source code',
    color: 'warning' as const,
  },
  frida: {
    displayName: 'Frida',
    description: 'Enables live debugging and runtime instrumentation',
    color: 'error' as const,
  },
  libmagic: {
    displayName: 'libmagic',
    description: 'Identifies the file type and format of your binary',
    color: 'default' as const,
  },
} as const;

type ToolName = keyof typeof TOOL_INFO;

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
      radare2: false,
      angr: false,
      capstone: false,
      ghidra: false,
      frida: false,
      libmagic: false,
    };

    // Check quick scan results
    for (const key of Object.keys(quickScan)) {
      const toolKey = key.toLowerCase() as ToolName;
      if (toolKey in used) {
        used[toolKey] = true;
      }
    }

    // Check deep scan results
    for (const key of Object.keys(deepScan)) {
      const toolKey = key.toLowerCase() as ToolName;
      if (toolKey in used) {
        used[toolKey] = true;
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
            <Tooltip key={name} title={info.description} arrow>
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
            <Tooltip key={name} title={info.description} arrow placement="top">
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
