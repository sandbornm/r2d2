import {
  alpha,
  Box,
  Divider,
  Drawer,
  FormControl,
  FormControlLabel,
  IconButton,
  MenuItem,
  Select,
  Stack,
  Switch,
  Typography,
  useTheme,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import SettingsIcon from '@mui/icons-material/Settings';
import DarkModeIcon from '@mui/icons-material/DarkMode';
import LightModeIcon from '@mui/icons-material/LightMode';
import SpeedIcon from '@mui/icons-material/Speed';
import PsychologyIcon from '@mui/icons-material/Psychology';
import BugReportIcon from '@mui/icons-material/BugReport';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import { FC } from 'react';

// Available AI models - must match backend LLMBridge.AVAILABLE_MODELS
export const AI_MODELS = [
  { id: 'claude-sonnet-4-5', name: 'Claude Sonnet 4', provider: 'Anthropic' },
  { id: 'claude-opus-4-5', name: 'Claude Opus 4', provider: 'Anthropic' },
  { id: 'gpt-5.2-2025-12-11', name: 'GPT-5.2', provider: 'OpenAI' },
] as const;

export type ModelId = typeof AI_MODELS[number]['id'];

export interface AnalysisSettings {
  quickScanOnly: boolean;
  enableAngr: boolean;
  autoAskLLM: boolean;
  selectedModel: ModelId;
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
}

const SettingRow: FC<SettingRowProps> = ({ icon, label, description, checked, onChange, disabled }) => {
  const theme = useTheme();
  
  return (
    <Box
      sx={{
        p: 2,
        borderRadius: 1.5,
        bgcolor: checked
          ? alpha(theme.palette.primary.main, 0.15)
          : alpha(theme.palette.background.paper, 0.6),
        border: `1px solid ${alpha(theme.palette.primary.main, checked ? 0.4 : 0.15)}`,
        transition: 'background-color 0.2s ease, border-color 0.2s ease',
      }}
    >
      <FormControlLabel
        control={
          <Switch
            checked={checked}
            onChange={(e) => onChange(e.target.checked)}
            disabled={disabled}
            size="small"
            color="primary"
          />
        }
        label={
          <Stack direction="row" spacing={1.5} alignItems="center" sx={{ ml: 1 }}>
            <Box
              sx={{
                color: checked ? 'primary.main' : 'text.secondary',
                display: 'flex',
                bgcolor: alpha(theme.palette.primary.main, checked ? 0.18 : 0.08),
                borderRadius: 1,
                p: 0.75,
              }}
            >
              {icon}
            </Box>
            <Box>
              <Typography variant="body2" fontWeight={500}>
                {label}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {description}
              </Typography>
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

export const SettingsDrawer: FC<SettingsDrawerProps> = ({
  open,
  onClose,
  isDarkMode,
  onToggleTheme,
  settings,
  onSettingsChange,
}) => {
  const theme = useTheme();

  const updateSetting = <K extends keyof AnalysisSettings>(key: K, value: AnalysisSettings[K]) => {
    onSettingsChange({ ...settings, [key]: value });
  };

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      PaperProps={{
        sx: {
          width: 360,
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
          {/* Appearance */}
          <Typography variant="overline" color="text.secondary" sx={{ px: 1 }}>
            Appearance
          </Typography>
          <Box sx={{ mt: 1, mb: 3 }}>
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

          {/* Analysis */}
          <Typography variant="overline" color="text.secondary" sx={{ px: 1 }}>
            Analysis
          </Typography>
          <Stack spacing={1} sx={{ mt: 1 }}>
            <SettingRow
              icon={<SpeedIcon sx={{ fontSize: 20 }} />}
              label="Quick Scan Only"
              description="Skip deep analysis for faster results"
              checked={settings.quickScanOnly}
              onChange={(v) => updateSetting('quickScanOnly', v)}
            />
            <SettingRow
              icon={<BugReportIcon sx={{ fontSize: 20 }} />}
              label="Symbolic Execution"
              description="Enable angr for deeper analysis (slower)"
              checked={settings.enableAngr}
              onChange={(v) => updateSetting('enableAngr', v)}
              disabled={settings.quickScanOnly}
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
                    Choose your preferred AI assistant
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
              description="Automatically request AI insights after analysis"
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
            Settings are saved automatically
          </Typography>
        </Box>
      </Box>
    </Drawer>
  );
};

export default SettingsDrawer;

