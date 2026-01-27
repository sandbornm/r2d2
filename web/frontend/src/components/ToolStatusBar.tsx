import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import LinkIcon from '@mui/icons-material/Link';
import { alpha, Box, Chip, CircularProgress, Stack, Tooltip, Typography, useTheme } from '@mui/material';
import { FC, useEffect, useState } from 'react';
import type { ToolsStatusResponse, ToolExecutionStatus } from '../types';
import { toolColors } from '../theme';

// Tool display configuration
const TOOL_ORDER = ['ghidra', 'radare2', 'angr', 'binwalk', 'gdb'] as const;

const TOOL_DISPLAY_NAMES: Record<string, string> = {
  ghidra: 'Ghidra',
  radare2: 'radare2',
  angr: 'angr',
  binwalk: 'binwalk',
  gdb: 'GDB',
};

interface ToolStatusBarProps {
  compact?: boolean;
  refreshInterval?: number;
}

const ToolStatusBar: FC<ToolStatusBarProps> = ({ compact = false, refreshInterval = 30000 }) => {
  const theme = useTheme();
  const isDark = theme.palette.mode === 'dark';
  const [status, setStatus] = useState<ToolsStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const response = await fetch('/api/tools/status');
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();
        setStatus(data);
        setError(null);
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Unknown error');
      } finally {
        setLoading(false);
      }
    };

    fetchStatus();

    // Refresh periodically
    const interval = setInterval(fetchStatus, refreshInterval);
    return () => clearInterval(interval);
  }, [refreshInterval]);

  if (loading) {
    return (
      <Stack direction="row" spacing={1} alignItems="center">
        <CircularProgress size={14} />
        <Typography variant="caption" color="text.secondary">
          Loading tools...
        </Typography>
      </Stack>
    );
  }

  if (error) {
    return (
      <Stack direction="row" spacing={1} alignItems="center">
        <ErrorIcon color="error" sx={{ fontSize: 16 }} />
        <Typography variant="caption" color="error">
          Error loading tools
        </Typography>
      </Stack>
    );
  }

  if (!status) {
    return null;
  }

  const getToolColor = (name: string): string => {
    return toolColors[name as keyof typeof toolColors] || theme.palette.grey[500];
  };

  const getToolTooltip = (name: string, toolStatus: ToolExecutionStatus) => {
    const lines = [toolStatus.description];
    if (name === 'ghidra') {
      if (toolStatus.bridge_connected) {
        lines.push('Bridge: Connected');
      } else if (toolStatus.bridge_available) {
        lines.push('Bridge: Available (not connected)');
      }
      if (toolStatus.headless_available) {
        lines.push('Headless: Available');
      }
    }
    return lines.join('\n');
  };

  if (compact) {
    return (
      <Stack direction="row" spacing={0.75} alignItems="center">
        <Typography variant="caption" color="text.secondary">
          Tools: {status.available_count} / {status.total_count}
        </Typography>
        {TOOL_ORDER.filter((name) => status.tools[name]?.available).map((name) => {
          const toolStatus = status.tools[name];
          const color = getToolColor(name);
          return (
            <Tooltip key={name} title={getToolTooltip(name, toolStatus)} arrow>
              <Chip
                size="small"
                label={TOOL_DISPLAY_NAMES[name] || name}
                icon={<CheckCircleIcon sx={{ fontSize: 12 }} />}
                sx={{
                  height: 20,
                  fontSize: '0.65rem',
                  bgcolor: alpha(color, isDark ? 0.2 : 0.12),
                  color: color,
                  border: `1px solid ${alpha(color, 0.3)}`,
                  '& .MuiChip-icon': { color: color },
                  '& .MuiChip-label': { px: 0.5 },
                }}
              />
            </Tooltip>
          );
        })}
      </Stack>
    );
  }

  // Full mode
  return (
    <Box
      sx={{
        p: 1.5,
        borderRadius: 1,
        bgcolor: isDark ? alpha(theme.palette.common.white, 0.02) : alpha(theme.palette.common.black, 0.02),
        border: 1,
        borderColor: 'divider',
      }}
    >
      <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1}>
        <Typography variant="caption" color="text.secondary" fontWeight={600}>
          Tool Execution Status
        </Typography>
        <Chip
          size="small"
          label={`${status.available_count} / ${status.total_count} ready`}
          sx={{
            height: 18,
            fontSize: '0.65rem',
            bgcolor: alpha(theme.palette.primary.main, 0.1),
            color: 'primary.main',
          }}
        />
      </Stack>
      <Stack direction="row" spacing={1} flexWrap="wrap" gap={0.75}>
        {TOOL_ORDER.map((name) => {
          const toolStatus = status.tools[name];
          if (!toolStatus) return null;

          const color = getToolColor(name);
          const isAvailable = toolStatus.available;
          const isBridgeConnected = name === 'ghidra' && toolStatus.bridge_connected;

          return (
            <Tooltip key={name} title={getToolTooltip(name, toolStatus)} arrow>
              <Chip
                size="small"
                label={TOOL_DISPLAY_NAMES[name] || name}
                icon={
                  isAvailable ? (
                    isBridgeConnected ? (
                      <LinkIcon sx={{ fontSize: 14 }} />
                    ) : (
                      <CheckCircleIcon sx={{ fontSize: 14 }} />
                    )
                  ) : (
                    <ErrorIcon sx={{ fontSize: 14 }} />
                  )
                }
                sx={{
                  height: 24,
                  bgcolor: isAvailable
                    ? alpha(color, isDark ? 0.15 : 0.1)
                    : alpha(theme.palette.error.main, isDark ? 0.1 : 0.05),
                  color: isAvailable ? color : 'error.main',
                  border: `1px solid ${isAvailable ? alpha(color, 0.3) : alpha(theme.palette.error.main, 0.3)}`,
                  opacity: isAvailable ? 1 : 0.6,
                  '& .MuiChip-icon': {
                    color: isAvailable ? color : theme.palette.error.main,
                  },
                }}
              />
            </Tooltip>
          );
        })}
        {/* Show bridge indicator separately if Ghidra bridge is connected */}
        {status.tools.ghidra?.bridge_connected && (
          <Chip
            size="small"
            label="Bridge"
            icon={<LinkIcon sx={{ fontSize: 14 }} />}
            sx={{
              height: 24,
              bgcolor: alpha(theme.palette.success.main, isDark ? 0.15 : 0.1),
              color: 'success.main',
              border: `1px solid ${alpha(theme.palette.success.main, 0.3)}`,
              '& .MuiChip-icon': { color: theme.palette.success.main },
            }}
          />
        )}
      </Stack>
    </Box>
  );
};

export default ToolStatusBar;
