import {
  alpha,
  Box,
  Chip,
  Divider,
  Drawer,
  FormControl,
  FormControlLabel,
  IconButton,
  LinearProgress,
  MenuItem,
  Select,
  Stack,
  Switch,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import SettingsIcon from '@mui/icons-material/Settings';
import DarkModeIcon from '@mui/icons-material/DarkMode';
import LightModeIcon from '@mui/icons-material/LightMode';
import SpeedIcon from '@mui/icons-material/Speed';
import PsychologyIcon from '@mui/icons-material/Psychology';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import CodeIcon from '@mui/icons-material/Code';
import BugReportIcon from '@mui/icons-material/BugReport';
import MemoryIcon from '@mui/icons-material/Memory';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import InfoIcon from '@mui/icons-material/Info';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import RefreshIcon from '@mui/icons-material/Refresh';
import { FC, useCallback, useEffect, useState } from 'react';

// Static defaults; the top bar model picker is populated from backend health.
export const AI_MODELS = [
  { id: 'gemma4:latest', name: 'Gemma 4 8B', provider: 'Ollama local', isDefault: true },
  { id: 'gemma3:4b', name: 'Gemma 3 4B', provider: 'Ollama local', isDefault: false },
  { id: 'gemma3:12b', name: 'Gemma 3 12B', provider: 'Ollama local', isDefault: false },
  { id: 'gemma2:9b', name: 'Gemma 2 9B', provider: 'Ollama local', isDefault: false },
  { id: 'claude-opus-4-5', name: 'Claude Opus 4.5', provider: 'Anthropic', isDefault: false },
  { id: 'claude-5-1', name: 'Claude 5.1', provider: 'Anthropic', isDefault: false },
  { id: 'claude-sonnet-4-5', name: 'Claude Sonnet 4.5', provider: 'Anthropic', isDefault: false },
  { id: 'gpt-4o', name: 'GPT-4o', provider: 'OpenAI', isDefault: false },
] as const;

export type ModelId = string;

export interface AnalysisSettings {
  quickScanOnly: boolean;
  enableAngr: boolean;
  enableGhidra: boolean;
  enableGef: boolean;
  enableFrida: boolean;
  autoAskLLM: boolean;
  selectedModel: ModelId;
}

interface ToolStatus {
  available: boolean;
  enabled?: boolean;
  install_hint?: string;
  description?: string;
  details?: string;
  path?: string | null;
  binwalk_available?: boolean;
  python_package_available?: boolean;
  bridge_connected?: boolean;
  bridge_available?: boolean;
  headless_ready?: boolean;
  headless_available?: boolean;
  bridge_program_loaded?: string | null;
  docker_available?: boolean;
  image_built?: boolean;
  cli_available?: boolean;
  service_available?: boolean;
  installed_models?: string[];
  selected_model?: string;
  selected_model_available?: boolean;
  transport?: string;
  url?: string;
  active_url?: string;
  command?: string;
  args?: string[];
  command_available?: boolean;
  start_command?: string[];
  working_dir?: string | null;
  status_code?: number;
  capabilities_count?: number;
  latency_ms?: number;
}

interface ToolsStatusMap {
  [key: string]: ToolStatus;
}

interface ToolsStatusMeta {
  cached?: boolean;
  live?: boolean;
  generated_at?: string | null;
}

interface ToolsStartResponse {
  tools?: ToolsStatusMap;
  meta?: ToolsStatusMeta;
  launch?: Record<string, { status: string; details?: string }>;
  error?: string;
}

interface SettingsDrawerProps {
  open: boolean;
  onClose: () => void;
  isDarkMode: boolean;
  onToggleTheme: () => void;
  settings: AnalysisSettings;
  onSettingsChange: (settings: AnalysisSettings) => void;
}

interface SettingRowProps {
  icon: React.ReactNode;
  label: string;
  description: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  available?: boolean;
  installHint?: string;
}

const SettingRow: FC<SettingRowProps> = ({ 
  icon, label, description, checked, onChange, disabled, available = true, installHint 
}) => {
  const theme = useTheme();
  const isDisabled = disabled || !available;
  
  return (
    <Box
      sx={{
        p: 2,
        borderRadius: 1.5,
        bgcolor: checked && !isDisabled
          ? alpha(theme.palette.primary.main, 0.15)
          : alpha(theme.palette.background.paper, 0.6),
        border: `1px solid ${alpha(
          !available ? theme.palette.error.main : theme.palette.primary.main, 
          checked && !isDisabled ? 0.4 : 0.15
        )}`,
        transition: 'background-color 0.2s ease, border-color 0.2s ease',
        opacity: isDisabled ? 0.6 : 1,
      }}
    >
      <FormControlLabel
        control={
          <Switch
            checked={checked && available}
            onChange={(e) => onChange(e.target.checked)}
            disabled={isDisabled}
            size="small"
            color="primary"
          />
        }
        label={
          <Stack direction="row" spacing={1.5} alignItems="center" sx={{ ml: 1 }}>
            <Box
              sx={{
                color: checked && !isDisabled ? 'primary.main' : 'text.secondary',
                display: 'flex',
                bgcolor: alpha(theme.palette.primary.main, checked && !isDisabled ? 0.18 : 0.08),
                borderRadius: 1,
                p: 0.75,
              }}
            >
              {icon}
            </Box>
            <Box sx={{ flex: 1 }}>
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography variant="body2" fontWeight={500}>
                  {label}
                </Typography>
                {!available && (
                  <Tooltip title={installHint || 'Not installed'}>
                    <Chip
                      size="small"
                      label="Not installed"
                      color="error"
                      variant="outlined"
                      sx={{ height: 18, fontSize: '0.6rem' }}
                    />
                  </Tooltip>
                )}
              </Stack>
              <Typography variant="caption" color="text.secondary">
                {description}
              </Typography>
              {!available && installHint && (
                <Typography 
                  variant="caption" 
                  sx={{ 
                    display: 'block', 
                    color: 'warning.main',
                    fontFamily: 'monospace',
                    fontSize: '0.65rem',
                    mt: 0.5,
                  }}
                >
                  → {installHint}
                </Typography>
              )}
            </Box>
          </Stack>
        }
        labelPlacement="start"
        sx={{
          m: 0,
          width: '100%',
          justifyContent: 'space-between',
        }}
      />
    </Box>
  );
};

// Tool status indicator component
const ToolStatusIndicator: FC<{
  name: string;
  status: ToolStatus;
  launching?: boolean;
  onStart?: (name: string) => void;
}> = ({ name, status, launching = false, onStart }) => {
  const canLaunch = (name.endsWith('_mcp') || name === 'ghidra_gdb') && !status.available && Boolean(status.start_command?.length);
  const detail = [
    status.details,
    status.path ? `path: ${status.path}` : null,
    status.python_package_available !== undefined ? `python: ${status.python_package_available ? 'yes' : 'no'}` : null,
    status.binwalk_available !== undefined ? `binwalk: ${status.binwalk_available ? 'yes' : 'no'}` : null,
    status.transport ? `transport: ${status.transport}` : null,
    status.active_url || status.url || status.command || null,
    status.start_command?.length ? `run: ${status.start_command.join(' ')}` : null,
    status.working_dir ? `cwd: ${status.working_dir}` : null,
    status.capabilities_count !== undefined ? `${status.capabilities_count} capabilities` : null,
  ].filter(Boolean).join(' | ');

  return (
    <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ py: 0.5 }}>
      <Typography variant="caption">{name}</Typography>
      <Stack direction="row" alignItems="center" spacing={0.5}>
        {status.available ? (
          <Tooltip title={detail || status.description || 'Ready'}>
            <CheckCircleIcon sx={{ fontSize: 14, color: 'success.main', cursor: 'help' }} />
          </Tooltip>
        ) : (
          <Tooltip title={detail || status.install_hint || 'Not available'}>
            <ErrorIcon sx={{ fontSize: 14, color: 'error.main', cursor: 'help' }} />
          </Tooltip>
        )}
        <Typography 
          variant="caption" 
          sx={{ 
            color: status.available ? 'success.main' : 'error.main',
            fontWeight: 500,
          }}
        >
          {status.available ? 'Ready' : 'Missing'}
        </Typography>
        {canLaunch && onStart && (
          <Tooltip title={`Start ${name}`}>
            <span>
              <IconButton
                size="small"
                aria-label={`Start ${name}`}
                disabled={launching}
                onClick={() => onStart(name)}
                sx={{ width: 22, height: 22 }}
              >
                <PlayArrowIcon sx={{ fontSize: 14 }} />
              </IconButton>
            </span>
          </Tooltip>
        )}
      </Stack>
    </Stack>
  );
};

export const SettingsDrawer: FC<SettingsDrawerProps> = ({
  open,
  onClose,
  isDarkMode,
  onToggleTheme,
  settings,
  onSettingsChange,
}) => {
  const theme = useTheme();
  const [toolsStatus, setToolsStatus] = useState<ToolsStatusMap>({});
  const [toolsMeta, setToolsMeta] = useState<ToolsStatusMeta>({});
  const [loadingTools, setLoadingTools] = useState(true);
  const [launchingTools, setLaunchingTools] = useState<Record<string, boolean>>({});
  const [launchMessage, setLaunchMessage] = useState<string | null>(null);

  // Fetch tools status from backend
  const fetchToolsStatus = useCallback(async () => {
    setLoadingTools(true);
    try {
      const response = await fetch('/api/tools/status?live=1');
      const data = await response.json();
      if (data.tools) {
        setToolsStatus(data.tools);
      }
      setToolsMeta(data.meta ?? {});
    } catch (err) {
      console.error('Failed to fetch tools status:', err);
    } finally {
      setLoadingTools(false);
    }
  }, []);

  useEffect(() => {
    if (open) {
      fetchToolsStatus();
    }
  }, [open, fetchToolsStatus]);

  const startTool = useCallback(async (name: string) => {
    setLaunchingTools((prev) => ({ ...prev, [name]: true }));
    setLaunchMessage(null);
    try {
      const response = await fetch('/api/tools/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ services: [name] }),
      });
      const data: ToolsStartResponse = await response.json();
      if (!response.ok || data.error) {
        throw new Error(data.error || `HTTP ${response.status}`);
      }
      if (data.tools) setToolsStatus(data.tools);
      setToolsMeta(data.meta ?? {});
      setLaunchMessage(`${name}: ${data.launch?.[name]?.status ?? 'started'}`);
    } catch (err) {
      setLaunchMessage(`${name}: ${err instanceof Error ? err.message : 'launch failed'}`);
    } finally {
      setLaunchingTools((prev) => ({ ...prev, [name]: false }));
    }
  }, []);

  const updateSetting = <K extends keyof AnalysisSettings>(key: K, value: AnalysisSettings[K]) => {
    onSettingsChange({ ...settings, [key]: value });
  };

  // Count available tools
  const availableCount = Object.values(toolsStatus).filter(t => t.available).length;
  const totalCount = Object.keys(toolsStatus).length;
  const generatedAtLabel = toolsMeta.generated_at
    ? new Date(toolsMeta.generated_at).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    : null;
  const orderedToolEntries = Object.entries(toolsStatus).sort(([left], [right]) => {
    const order = [
      'firmware',
      'binwalk',
      'autoprofile',
      'ollama',
      'ghidra_mcp',
      'ghidra_gdb',
      'angr_mcp',
      'radare2',
      'angr',
      'ghidra',
      'capstone',
      'dwarf',
      'libmagic',
      'gef',
      'gdb',
      'frida',
    ];
    const leftIndex = order.indexOf(left);
    const rightIndex = order.indexOf(right);
    return (leftIndex === -1 ? 999 : leftIndex) - (rightIndex === -1 ? 999 : rightIndex) || left.localeCompare(right);
  });

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      PaperProps={{
        sx: {
          width: 380,
          bgcolor: alpha(theme.palette.background.paper, isDarkMode ? 0.95 : 0.9),
          backgroundImage: isDarkMode
            ? `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.08)} 0%, ${alpha(
                theme.palette.secondary.main,
                0.04,
              )} 100%)`
            : `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.06)} 0%, ${alpha(
                theme.palette.secondary.main,
                0.08,
              )} 100%)`,
          borderLeft: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
          boxShadow: `-12px 0 30px -12px ${alpha(theme.palette.primary.dark, 0.3)}`,
          backdropFilter: 'blur(18px)',
        },
      }}
    >
      <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
        {/* Header */}
        <Box
          sx={{
            px: 3,
            py: 2,
            borderBottom: 1,
            borderColor: 'divider',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <Stack direction="row" spacing={1.5} alignItems="center">
            <Box
              sx={{
                bgcolor: alpha(theme.palette.primary.main, 0.2),
                borderRadius: 1,
                p: 0.75,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <SettingsIcon sx={{ color: 'primary.main' }} />
            </Box>
            <Typography variant="h6" fontWeight={700}>
              Settings
            </Typography>
          </Stack>
          <IconButton onClick={onClose} size="small">
            <CloseIcon fontSize="small" />
          </IconButton>
        </Box>

        {/* Content */}
        <Box sx={{ flex: 1, overflow: 'auto', p: 2 }}>
          {/* Tools Status Overview */}
          <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ px: 1 }}>
            <Typography variant="overline" color="text.secondary">
              Tools Status
            </Typography>
            <Tooltip title="Refresh live tool status">
              <span>
                <IconButton size="small" onClick={fetchToolsStatus} disabled={loadingTools}>
                  <RefreshIcon sx={{ fontSize: 16 }} />
                </IconButton>
              </span>
            </Tooltip>
          </Stack>
          <Box
            sx={{
              mt: 1,
              mb: 2,
              p: 2,
              borderRadius: 1.5,
              bgcolor: alpha(theme.palette.background.paper, 0.6),
              border: `1px solid ${alpha(theme.palette.divider, 0.5)}`,
            }}
          >
            {loadingTools ? (
              <LinearProgress sx={{ borderRadius: 1 }} />
            ) : (
              <>
                <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
                  <Typography variant="body2" fontWeight={500}>
                    {availableCount}/{totalCount} tools ready
                  </Typography>
                  <Tooltip title="Run: uv sync --extra analyzers">
                    <InfoIcon sx={{ fontSize: 16, color: 'text.secondary', cursor: 'help' }} />
                  </Tooltip>
                </Stack>
                {generatedAtLabel && (
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
                    {toolsMeta.live ? 'Live' : 'Cached'} check at {generatedAtLabel}
                    {toolsMeta.cached ? ' from cache' : ''}
                  </Typography>
                )}
                {launchMessage && (
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
                    {launchMessage}
                  </Typography>
                )}
                <LinearProgress 
                  variant="determinate" 
                  value={(availableCount / Math.max(totalCount, 1)) * 100} 
                  sx={{ 
                    height: 6, 
                    borderRadius: 1,
                    bgcolor: alpha(theme.palette.error.main, 0.15),
                    '& .MuiLinearProgress-bar': {
                      bgcolor: availableCount === totalCount ? 'success.main' : 'warning.main',
                    },
                  }} 
                />
                <Box sx={{ mt: 1.5 }}>
                  {orderedToolEntries.map(([name, status]) => (
                    <ToolStatusIndicator
                      key={name}
                      name={name}
                      status={status}
                      launching={launchingTools[name]}
                      onStart={startTool}
                    />
                  ))}
                </Box>
              </>
            )}
          </Box>

          <Divider sx={{ my: 2 }} />

          {/* Appearance */}
          <Typography variant="overline" color="text.secondary" sx={{ px: 1 }}>
            Appearance
          </Typography>
          <Box sx={{ mt: 1, mb: 2 }}>
            <Box
              onClick={onToggleTheme}
              sx={{
                p: 2,
                borderRadius: 1.5,
                border: 1,
                borderColor: 'divider',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 2,
                transition: 'all 0.2s',
                '&:hover': {
                  borderColor: 'primary.main',
                  bgcolor: alpha(theme.palette.primary.main, 0.04),
                },
              }}
            >
              <Box
                sx={{
                  width: 40,
                  height: 40,
                  borderRadius: 1,
                  bgcolor: isDarkMode
                    ? alpha(theme.palette.warning.main, 0.15)
                    : alpha(theme.palette.info.main, 0.15),
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                {isDarkMode ? (
                  <LightModeIcon sx={{ color: 'warning.main' }} />
                ) : (
                  <DarkModeIcon sx={{ color: 'info.main' }} />
                )}
              </Box>
              <Box sx={{ flex: 1 }}>
                <Typography variant="body2" fontWeight={500}>
                  {isDarkMode ? 'Light Mode' : 'Dark Mode'}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Switch to {isDarkMode ? 'light' : 'dark'} theme
                </Typography>
              </Box>
            </Box>
          </Box>

          <Divider sx={{ my: 2 }} />

          {/* Analysis Settings */}
          <Typography variant="overline" color="text.secondary" sx={{ px: 1 }}>
            Analysis Tools
          </Typography>
          <Stack spacing={1} sx={{ mt: 1 }}>
            <SettingRow
              icon={<SpeedIcon sx={{ fontSize: 20 }} />}
              label="Quick Scan Only"
              description="Skip deep analysis (faster, but no CFG or decompilation)"
              checked={settings.quickScanOnly}
              onChange={(v) => updateSetting('quickScanOnly', v)}
            />
            <SettingRow
              icon={<AccountTreeIcon sx={{ fontSize: 20 }} />}
              label="angr (CFG Analysis)"
              description="Build control flow graphs with symbolic execution"
              checked={settings.enableAngr}
              onChange={(v) => updateSetting('enableAngr', v)}
              disabled={settings.quickScanOnly}
              available={toolsStatus.angr?.available}
              installHint={toolsStatus.angr?.install_hint}
            />
            <SettingRow
              icon={<CodeIcon sx={{ fontSize: 20 }} />}
              label="Ghidra (Decompiler)"
              description="Decompile to C pseudocode via Ghidra Bridge"
              checked={settings.enableGhidra}
              onChange={(v) => updateSetting('enableGhidra', v)}
              disabled={settings.quickScanOnly}
              available={toolsStatus.ghidra?.available}
              installHint={toolsStatus.ghidra?.install_hint}
            />
            <SettingRow
              icon={<BugReportIcon sx={{ fontSize: 20 }} />}
              label="GEF/GDB (Dynamic)"
              description="Execute in Docker container with instruction tracing"
              checked={settings.enableGef}
              onChange={(v) => updateSetting('enableGef', v)}
              disabled={settings.quickScanOnly}
              available={toolsStatus.gef?.available}
              installHint={toolsStatus.gef?.install_hint}
            />
            <SettingRow
              icon={<MemoryIcon sx={{ fontSize: 20 }} />}
              label="Frida (Instrumentation)"
              description="Dynamic instrumentation for runtime analysis"
              checked={settings.enableFrida}
              onChange={(v) => updateSetting('enableFrida', v)}
              disabled={settings.quickScanOnly}
              available={toolsStatus.frida?.available}
              installHint={toolsStatus.frida?.install_hint}
            />
          </Stack>

          <Divider sx={{ my: 2 }} />

          {/* AI Assistant */}
          <Typography variant="overline" color="text.secondary" sx={{ px: 1 }}>
            AI Assistant
          </Typography>
          <Stack spacing={1.5} sx={{ mt: 1 }}>
            {/* Model selector */}
            <Box
              sx={{
                p: 2,
                borderRadius: 1.5,
                bgcolor: alpha(theme.palette.primary.main, 0.08),
                border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
              }}
            >
              <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 1.5 }}>
                <Box
                  sx={{
                    color: 'primary.main',
                    display: 'flex',
                    bgcolor: alpha(theme.palette.primary.main, 0.15),
                    borderRadius: 1,
                    p: 0.75,
                  }}
                >
                  <SmartToyIcon sx={{ fontSize: 20 }} />
                </Box>
                <Box>
                  <Typography variant="body2" fontWeight={500}>
                    AI Model
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    For code explanation and analysis help
                  </Typography>
                </Box>
              </Stack>
              <FormControl fullWidth size="small">
                <Select
                  value={settings.selectedModel}
                  onChange={(e) => updateSetting('selectedModel', e.target.value as ModelId)}
                  sx={{
                    bgcolor: 'background.paper',
                    '& .MuiSelect-select': {
                      py: 1,
                    },
                  }}
                >
                  {AI_MODELS.map((model) => (
                    <MenuItem key={model.id} value={model.id}>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography variant="body2">{model.name}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          ({model.provider})
                        </Typography>
                      </Stack>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Box>

            <SettingRow
              icon={<PsychologyIcon sx={{ fontSize: 20 }} />}
              label="Auto-analyze with AI"
              description="Automatically ask the selected model about the binary after analysis"
              checked={settings.autoAskLLM}
              onChange={(v) => updateSetting('autoAskLLM', v)}
            />
          </Stack>
        </Box>

        {/* Footer */}
        <Box
          sx={{
            px: 3,
            py: 2,
            borderTop: 1,
            borderColor: 'divider',
          }}
        >
          <Typography variant="caption" color="text.secondary">
            Settings are saved automatically to localStorage
          </Typography>
        </Box>
      </Box>
    </Drawer>
  );
};

export default SettingsDrawer;
