import {
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
import { FC, useCallback, useEffect, useState } from 'react';

export type ModelId = string;

export interface AnalysisSettings {
  analysisProfile: 'triage' | 'standard' | 'exhaustive';
  quickScanOnly: boolean;
  enableAngr: boolean;
  enableGhidra: boolean;
  enableGef: boolean;
  enableFrida: boolean;
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

const Toggle: FC<{
  label: string;
  hint: string;
  checked: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
}> = ({ label, hint, checked, onChange, disabled }) => (
  <FormControlLabel
    sx={{ mx: 0, width: '100%', justifyContent: 'space-between', alignItems: 'flex-start' }}
    labelPlacement="start"
    control={
      <Switch
        size="small"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
      />
    }
    label={
      <Box sx={{ pr: 2 }}>
        <Typography variant="body2">{label}</Typography>
        <Typography variant="caption" color="text.secondary">
          {hint}
        </Typography>
      </Box>
    }
  />
);

export const SettingsDrawer: FC<SettingsDrawerProps> = ({
  open,
  onClose,
  isDarkMode,
  onToggleTheme,
  settings,
  onSettingsChange,
}) => {
  const theme = useTheme();
  const [availability, setAvailability] = useState<Record<string, boolean>>({});

  const loadCachedStatus = useCallback(async () => {
    try {
      const response = await fetch('/api/tools/status');
      if (!response.ok) return;
      const data = await response.json();
      const next: Record<string, boolean> = {};
      for (const [name, tool] of Object.entries(data.tools || {})) {
        next[name] = Boolean((tool as { available?: boolean }).available);
      }
      setAvailability(next);
    } catch {
      // Header bar already owns live tool health.
    }
  }, []);

  useEffect(() => {
    if (open) loadCachedStatus().catch(() => undefined);
  }, [open, loadCachedStatus]);

  const update = <K extends keyof AnalysisSettings>(key: K, value: AnalysisSettings[K]) => {
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
          bgcolor: theme.palette.background.paper,
          borderLeft: 1,
          borderColor: 'divider',
        },
      }}
    >
      <Box sx={{ px: 2.5, py: 2, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="subtitle1">Settings</Typography>
        <IconButton onClick={onClose} size="small" aria-label="Close settings">
          <CloseIcon fontSize="small" />
        </IconButton>
      </Box>
      <Divider />
      <Stack spacing={2.5} sx={{ p: 2.5 }}>
        <Box>
          <Typography variant="overline" color="text.secondary">Appearance</Typography>
          <Toggle
            label={isDarkMode ? 'Dark' : 'Light'}
            hint="Theme for this browser"
            checked={isDarkMode}
            onChange={() => onToggleTheme()}
          />
        </Box>

        <Box>
          <Typography variant="overline" color="text.secondary">Depth</Typography>
          <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mt: 1 }}>
            <Box>
              <Typography variant="body2">Profile</Typography>
              <Typography variant="caption" color="text.secondary">
                How hard the next analyze should work
              </Typography>
            </Box>
            <FormControl size="small" sx={{ minWidth: 128 }}>
              <Select
                value={settings.analysisProfile}
                onChange={(event) => {
                  const profile = event.target.value as AnalysisSettings['analysisProfile'];
                  onSettingsChange({
                    ...settings,
                    analysisProfile: profile,
                    quickScanOnly: profile === 'triage',
                  });
                }}
              >
                <MenuItem value="triage">Triage</MenuItem>
                <MenuItem value="standard">Standard</MenuItem>
                <MenuItem value="exhaustive">Exhaustive</MenuItem>
              </Select>
            </FormControl>
          </Stack>
        </Box>

        <Box>
          <Typography variant="overline" color="text.secondary">Optional engines</Typography>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
            Firmware inventory and r2 always run. These only apply after an ELF exists.
          </Typography>
          <Toggle
            label="angr"
            hint={availability.angr === false ? 'Not installed' : 'CFG / symbolic, slow'}
            checked={settings.enableAngr}
            onChange={(value) => update('enableAngr', value)}
            disabled={settings.analysisProfile === 'triage'}
          />
          <Toggle
            label="Ghidra"
            hint={availability.ghidra === false ? 'Not installed' : 'Headless decompile'}
            checked={settings.enableGhidra}
            onChange={(value) => update('enableGhidra', value)}
            disabled={settings.analysisProfile === 'triage'}
          />
          <Toggle
            label="GEF / GDB"
            hint="Docker traces. Skip for firmware blobs."
            checked={settings.enableGef}
            onChange={(value) => update('enableGef', value)}
            disabled={settings.analysisProfile === 'triage'}
          />
          <Toggle
            label="Frida"
            hint="Runtime hooks. Skip until you have a running process."
            checked={settings.enableFrida}
            onChange={(value) => update('enableFrida', value)}
            disabled={settings.analysisProfile === 'triage'}
          />
        </Box>

        <Box>
          <Typography variant="overline" color="text.secondary">Qwen</Typography>
          <Toggle
            label="Ask after analyze"
            hint="Sends the overall briefing ask. Off by default."
            checked={settings.autoAskLLM}
            onChange={(value) => update('autoAskLLM', value)}
          />
        </Box>
      </Stack>
    </Drawer>
  );
};

export default SettingsDrawer;
