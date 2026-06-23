import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import LinkIcon from '@mui/icons-material/Link';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import { alpha, Box, Chip, CircularProgress, IconButton, Stack, Tooltip, Typography, useTheme } from '@mui/material';
import { FC, useCallback, useEffect, useState } from 'react';
import type { ToolsStartResponse, ToolsStatusResponse, ToolExecutionStatus } from '../types';
import { toolColors } from '../theme';

// Tool display configuration
const TOOL_ORDER = ['firmware', 'binwalk', 'autoprofile', 'ollama', 'ghidra_mcp', 'ghidra_gdb', 'angr_mcp', 'radare2', 'angr', 'ghidra', 'capstone', 'dwarf', 'gdb'] as const;

const TOOL_DISPLAY_NAMES: Record<string, string> = {
  firmware: 'Firmware',
  binwalk: 'binwalk',
  autoprofile: 'Profile',
  ollama: 'Ollama',
  ghidra_mcp: 'GhidraMCP',
  ghidra_gdb: 'GDB MCP',
  angr_mcp: 'angr MCP',
  ghidra: 'Ghidra',
  radare2: 'radare2',
  angr: 'angr',
  capstone: 'Capstone',
  dwarf: 'DWARF',
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
  const [launching, setLaunching] = useState<Record<string, boolean>>({});
  const [launchMessage, setLaunchMessage] = useState<string | null>(null);

  const fetchStatus = useCallback(async (live = false) => {
    try {
      const response = await fetch(`/api/tools/status${live ? '?live=1' : ''}`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data: ToolsStatusResponse = await response.json();
      setStatus(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus().catch(console.error);

    const interval = setInterval(() => {
      fetchStatus().catch(console.error);
    }, refreshInterval);

    return () => clearInterval(interval);
  }, [fetchStatus, refreshInterval]);

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
      if (toolStatus.headless_ready || toolStatus.headless_available) {
        lines.push('Headless: Available');
      }
    }
    if (toolStatus.details) lines.push(toolStatus.details);
    if (toolStatus.active_url || toolStatus.url || toolStatus.command) {
      lines.push(String(toolStatus.active_url || toolStatus.url || toolStatus.command));
    }
    if (toolStatus.start_command?.length) {
      const command = toolStatus.start_command.join(' ');
      if (toolStatus.working_dir) lines.push(`Working dir: ${toolStatus.working_dir}`);
      lines.push(`Run: ${command}`);
    } else if (toolStatus.command && toolStatus.args?.length) {
      lines.push(`Run: ${[toolStatus.command, ...toolStatus.args].join(' ')}`);
    }
    if (toolStatus.install_hint) lines.push(toolStatus.install_hint);
    if (toolStatus.path) lines.push(`Path: ${toolStatus.path}`);
    return lines.join('\n');
  };

  const canLaunchTool = (name: string, toolStatus: ToolExecutionStatus) => {
    return name.endsWith('_mcp') || name === 'ghidra_gdb'
      ? !toolStatus.available && Boolean(toolStatus.start_command?.length)
      : false;
  };

  const startTool = async (name: string) => {
    setLaunching((prev) => ({ ...prev, [name]: true }));
    setLaunchMessage(null);
    try {
      const response = await fetch('/api/tools/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ services: [name] }),
      });
      const data: ToolsStartResponse | { error?: string } = await response.json();
      if (!response.ok || 'error' in data) {
        throw new Error(('error' in data && data.error) || `HTTP ${response.status}`);
      }
      setStatus({
        tools: data.tools,
        available_count: data.available_count,
        total_count: data.total_count,
        meta: data.meta,
      });
      const result = data.launch[name];
      setLaunchMessage(`${TOOL_DISPLAY_NAMES[name] || name}: ${result?.status ?? 'started'}`);
    } catch (e) {
      setLaunchMessage(`${TOOL_DISPLAY_NAMES[name] || name}: ${e instanceof Error ? e.message : 'launch failed'}`);
    } finally {
      setLaunching((prev) => ({ ...prev, [name]: false }));
    }
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
        <Stack direction="row" spacing={0.75} alignItems="center">
          {launchMessage && (
            <Typography variant="caption" color="text.secondary">
              {launchMessage}
            </Typography>
          )}
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
      </Stack>
      <Stack direction="row" spacing={1} flexWrap="wrap" gap={0.75}>
        {TOOL_ORDER.map((name) => {
          const toolStatus = status.tools[name];
          if (!toolStatus) return null;

          const color = getToolColor(name);
          const isAvailable = toolStatus.available;
          const isBridgeConnected = name === 'ghidra' && toolStatus.bridge_connected;
          const canLaunch = canLaunchTool(name, toolStatus);

          return (
            <Stack key={name} direction="row" spacing={0.25} alignItems="center">
              <Tooltip title={getToolTooltip(name, toolStatus)} arrow>
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
              {canLaunch && (
                <Tooltip title={`Start ${TOOL_DISPLAY_NAMES[name] || name}`}>
                  <span>
                    <IconButton
                      size="small"
                      aria-label={`Start ${TOOL_DISPLAY_NAMES[name] || name}`}
                      disableRipple
                      disabled={launching[name]}
                      onClick={() => startTool(name)}
                      sx={{
                        width: 24,
                        height: 24,
                        color,
                        border: `1px solid ${alpha(color, 0.28)}`,
                        bgcolor: alpha(color, isDark ? 0.1 : 0.06),
                      }}
                    >
                      {launching[name] ? <CircularProgress size={12} /> : <PlayArrowIcon sx={{ fontSize: 15 }} />}
                    </IconButton>
                  </span>
                </Tooltip>
              )}
            </Stack>
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
