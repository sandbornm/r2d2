import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import {
  Box,
  CircularProgress,
  ClickAwayListener,
  Paper,
  Popper,
  Stack,
  Switch,
  Typography,
  alpha,
  useTheme,
} from '@mui/material';
import { FC, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { AnalysisSettings } from './SettingsDrawer';
import type { ToolExecutionStatus, ToolsStartResponse, ToolsStatusResponse } from '../types';
import { getToolCatalogEntry, getToolDisplayName, getToolShortName, sortToolEntries } from '../toolCatalog';

interface ToolStatusBarProps {
  compact?: boolean;
  refreshInterval?: number;
  settings?: AnalysisSettings;
  onSettingsChange?: (next: AnalysisSettings) => void;
}

const HIDDEN_TOOLS = new Set(['pwntools', 'ghidra_mcp']);

const COMPACT_TOOL_ORDER = [
  'firmware',
  'radare2',
  'ghidra',
  'angr',
  'angr_mcp',
  'capstone',
  'binwalk',
];

type EnableKey = 'enableAngr' | 'enableGhidra' | 'enableGef' | 'enableFrida';

const ENABLE_BY_TOOL: Record<string, EnableKey> = {
  angr: 'enableAngr',
  angr_mcp: 'enableAngr',
  ghidra: 'enableGhidra',
  ghidra_gdb: 'enableGhidra',
  gef: 'enableGef',
  gdb: 'enableGef',
  frida: 'enableFrida',
};

type HealthKind = 'ok' | 'off' | 'down';

const toolHealth = (name: string, tool: ToolExecutionStatus, settings?: AnalysisSettings): HealthKind => {
  const enableKey = ENABLE_BY_TOOL[name];
  if (enableKey && settings && settings[enableKey] === false) return 'off';
  if (!tool.available) return 'down';
  return 'ok';
};

const healthLabel = (kind: HealthKind): string => {
  if (kind === 'ok') return 'Ready';
  if (kind === 'off') return 'Off for this run';
  return 'Not running';
};

const ToolStatusBar: FC<ToolStatusBarProps> = ({
  compact = false,
  refreshInterval = 30000,
  settings,
  onSettingsChange,
}) => {
  const theme = useTheme();
  const isDark = theme.palette.mode === 'dark';
  const [status, setStatus] = useState<ToolsStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [launching, setLaunching] = useState<Record<string, boolean>>({});
  const [openTool, setOpenTool] = useState<string | null>(null);
  const closeTimer = useRef<number | null>(null);
  const anchors = useRef<Record<string, HTMLElement | null>>({});

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

  const visibleTools = useMemo(() => {
    if (!status) return [] as Array<[string, ToolExecutionStatus]>;
    const entries = Object.entries(status.tools).filter(([name]) => !HIDDEN_TOOLS.has(name));
    if (!compact) return sortToolEntries(entries);
    return COMPACT_TOOL_ORDER
      .filter((name) => status.tools[name] && !HIDDEN_TOOLS.has(name))
      .map((name) => [name, status.tools[name]] as [string, ToolExecutionStatus]);
  }, [compact, status]);

  const readyCount = visibleTools.filter(([, tool]) => tool.available).length;

  const canLaunchTool = (name: string, toolStatus: ToolExecutionStatus) =>
    (name.endsWith('_mcp') || name === 'ghidra_gdb')
    && !toolStatus.available
    && Boolean(toolStatus.start_command?.length);

  const startTool = async (name: string) => {
    setLaunching((prev) => ({ ...prev, [name]: true }));
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
        scorecard: data.scorecard,
        score_summary: data.score_summary,
      });
    } finally {
      setLaunching((prev) => ({ ...prev, [name]: false }));
    }
  };

  const toggleEnabled = (name: string, enabled: boolean) => {
    const key = ENABLE_BY_TOOL[name];
    if (!key || !settings || !onSettingsChange) return;
    onSettingsChange({ ...settings, [key]: enabled });
  };

  const open = (name: string) => {
    if (closeTimer.current) window.clearTimeout(closeTimer.current);
    setOpenTool(name);
  };

  const scheduleClose = () => {
    if (closeTimer.current) window.clearTimeout(closeTimer.current);
    closeTimer.current = window.setTimeout(() => setOpenTool(null), 160);
  };

  if (loading) {
    return (
      <Stack direction="row" spacing={1} alignItems="center" aria-label="Loading tools">
        <CircularProgress size={12} />
      </Stack>
    );
  }

  if (error) {
    return (
      <Typography variant="caption" color="error">
        tools offline
      </Typography>
    );
  }

  if (!status) return null;

  const renderCard = (name: string, toolStatus: ToolExecutionStatus) => {
    const health = toolHealth(name, toolStatus, settings);
    const catalog = getToolCatalogEntry(name);
    const enableKey = ENABLE_BY_TOOL[name];
    const enabled = enableKey && settings ? settings[enableKey] : true;
    const launchable = canLaunchTool(name, toolStatus);
    const hint = health === 'down'
      ? (toolStatus.install_hint || toolStatus.details || 'Not reachable on this box.')
      : catalog?.description;

    return (
      <Paper
        elevation={0}
        onMouseEnter={() => open(name)}
        onMouseLeave={scheduleClose}
        sx={{
          p: 1.25,
          minWidth: 200,
          maxWidth: 260,
          border: 1,
          borderColor: 'divider',
          bgcolor: isDark ? '#141310' : '#fff',
        }}
      >
        <Stack spacing={0.75}>
          <Stack direction="row" justifyContent="space-between" alignItems="baseline">
            <Typography variant="body2" fontWeight={600}>
              {getToolDisplayName(name)}
            </Typography>
            <Typography
              variant="caption"
              sx={{ color: health === 'ok' ? 'success.main' : health === 'off' ? 'text.secondary' : 'warning.main' }}
            >
              {healthLabel(health)}
            </Typography>
          </Stack>
          <Typography variant="caption" color="text.secondary">
            {hint}
          </Typography>
          {enableKey && settings && onSettingsChange && (
            <Stack direction="row" alignItems="center" justifyContent="space-between">
              <Typography variant="caption">Use on next analyze</Typography>
              <Switch
                size="small"
                checked={Boolean(enabled)}
                onChange={(event) => toggleEnabled(name, event.target.checked)}
                inputProps={{ 'aria-label': `Enable ${getToolDisplayName(name)}` }}
              />
            </Stack>
          )}
          {launchable && (
            <Box
              component="button"
              onClick={() => startTool(name)}
              disabled={launching[name]}
              aria-label={`Start ${getToolDisplayName(name)}`}
              sx={{
                border: 1,
                borderColor: 'divider',
                bgcolor: 'transparent',
                color: 'text.primary',
                font: 'inherit',
                fontSize: 12,
                py: 0.5,
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 0.5,
              }}
            >
              {launching[name] ? <CircularProgress size={10} /> : <PlayArrowIcon sx={{ fontSize: 14 }} />}
              Start service
            </Box>
          )}
        </Stack>
      </Paper>
    );
  };

  const dots = compact ? visibleTools : visibleTools.slice(0, 10);

  return (
    <ClickAwayListener onClickAway={() => setOpenTool(null)}>
      <Stack direction="row" spacing={0.75} alignItems="center" sx={{ minWidth: 0 }}>
        {dots.map(([name, toolStatus]) => {
          const health = toolHealth(name, toolStatus, settings);
          const label = getToolShortName(name);
          return (
            <Box
              key={name}
              ref={(node: HTMLDivElement | null) => {
                anchors.current[name] = node;
              }}
              onMouseEnter={() => open(name)}
              onMouseLeave={scheduleClose}
              sx={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 0.5,
                px: 0.6,
                py: 0.15,
                cursor: 'default',
                opacity: health === 'off' ? 0.4 : 1,
              }}
            >
              <Box
                sx={{
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  bgcolor:
                    health === 'ok'
                      ? alpha(theme.palette.success.main, 0.9)
                      : health === 'off'
                        ? theme.palette.text.disabled
                        : theme.palette.warning.main,
                  boxShadow: health === 'down' ? `0 0 0 3px ${alpha(theme.palette.warning.main, 0.2)}` : 'none',
                }}
              />
              <Typography variant="caption" sx={{ fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.02em' }}>
                {label}
              </Typography>
              <Popper
                open={openTool === name}
                anchorEl={anchors.current[name]}
                placement="bottom-start"
                sx={{ zIndex: theme.zIndex.tooltip }}
              >
                {renderCard(name, toolStatus)}
              </Popper>
            </Box>
          );
        })}
        {!compact && (
          <Typography variant="caption" color="text.secondary" sx={{ ml: 0.5 }}>
            {readyCount}/{visibleTools.length}
          </Typography>
        )}
      </Stack>
    </ClickAwayListener>
  );
};

export default ToolStatusBar;
