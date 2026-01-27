import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import SecurityIcon from '@mui/icons-material/Security';
import WarningIcon from '@mui/icons-material/Warning';
import {
  Alert,
  AlertTitle,
  Box,
  Chip,
  Grid,
  Paper,
  Stack,
  Tooltip,
  Typography,
} from '@mui/material';
import { FC } from 'react';
import type { AutoProfileData, SecurityFeatures } from '../types';

interface AutoProfilePanelProps {
  data: AutoProfileData | null;
  compact?: boolean;
}

// Security feature display config
const SECURITY_FEATURES: Array<{
  key: keyof SecurityFeatures;
  label: string;
  goodValue: string | boolean;
  tooltip: string;
}> = [
  {
    key: 'relro',
    label: 'RELRO',
    goodValue: 'full',
    tooltip: 'Relocation Read-Only: Protects the GOT from being overwritten',
  },
  {
    key: 'stack_canary',
    label: 'Stack Canary',
    goodValue: true,
    tooltip: 'Detects stack buffer overflows before they can be exploited',
  },
  {
    key: 'nx',
    label: 'NX',
    goodValue: true,
    tooltip: 'No-eXecute: Prevents execution of code on the stack',
  },
  {
    key: 'pie',
    label: 'PIE',
    goodValue: true,
    tooltip: 'Position Independent Executable: Enables ASLR for the main binary',
  },
  {
    key: 'fortify',
    label: 'FORTIFY',
    goodValue: true,
    tooltip: 'Buffer overflow checks for common libc functions',
  },
];

const SecurityBadge: FC<{
  feature: (typeof SECURITY_FEATURES)[number];
  value: string | boolean | null;
}> = ({ feature, value }) => {

  const isGood =
    value === feature.goodValue ||
    (feature.key === 'relro' && value === 'partial');
  const isBad = value === false || value === 'none';
  const isUnknown = value === null || value === 'unknown';

  let color: 'success' | 'error' | 'warning' | 'default' = 'default';
  let label = feature.label;

  if (isGood) {
    color = 'success';
    if (feature.key === 'relro') {
      label = `${feature.label}: ${value}`;
    }
  } else if (isBad) {
    color = 'error';
  } else if (isUnknown) {
    color = 'warning';
  }

  return (
    <Tooltip title={feature.tooltip} arrow>
      <Chip
        size="small"
        label={label}
        color={color}
        variant={isGood ? 'filled' : 'outlined'}
        sx={{
          fontWeight: 500,
          fontSize: '0.7rem',
          opacity: isUnknown ? 0.6 : 1,
        }}
      />
    </Tooltip>
  );
};

const RiskAlert: FC<{ level: string; factors: string[] }> = ({ level, factors }) => {
  if (factors.length === 0) return null;

  const severity = level === 'high' ? 'error' : level === 'medium' ? 'warning' : 'info';
  const Icon = level === 'high' ? ErrorIcon : level === 'medium' ? WarningIcon : CheckCircleIcon;

  return (
    <Alert
      severity={severity}
      icon={<Icon />}
      sx={{ mb: 2 }}
    >
      <AlertTitle sx={{ fontWeight: 600 }}>
        {level === 'high' ? 'High Risk Indicators' : level === 'medium' ? 'Medium Risk Indicators' : 'Low Risk'}
      </AlertTitle>
      {factors.length > 0 && (
        <Box component="ul" sx={{ m: 0, pl: 2, mt: 0.5 }}>
          {factors.map((factor, i) => (
            <Typography
              key={i}
              component="li"
              variant="caption"
              sx={{ lineHeight: 1.6 }}
            >
              {factor}
            </Typography>
          ))}
        </Box>
      )}
    </Alert>
  );
};

const StringCategory: FC<{
  title: string;
  strings: string[];
  color?: 'default' | 'primary' | 'secondary' | 'error' | 'warning' | 'info' | 'success';
  icon?: React.ReactNode;
}> = ({ title, strings, color = 'default', icon }) => {
  if (strings.length === 0) return null;

  return (
    <Box sx={{ mb: 1.5 }}>
      <Stack direction="row" alignItems="center" spacing={0.5} sx={{ mb: 0.5 }}>
        {icon}
        <Typography variant="caption" color="text.secondary" fontWeight={600}>
          {title} ({strings.length})
        </Typography>
      </Stack>
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
        {strings.slice(0, 10).map((s, i) => (
          <Chip
            key={i}
            label={s.length > 40 ? s.slice(0, 40) + '...' : s}
            size="small"
            color={color}
            variant="outlined"
            sx={{
              fontFamily: 'monospace',
              fontSize: '0.65rem',
              maxWidth: 250,
            }}
          />
        ))}
        {strings.length > 10 && (
          <Chip
            label={`+${strings.length - 10} more`}
            size="small"
            variant="outlined"
            sx={{ fontSize: '0.65rem' }}
          />
        )}
      </Box>
    </Box>
  );
};

const AutoProfilePanel: FC<AutoProfilePanelProps> = ({ data, compact = false }) => {
  if (!data || !data.profile) {
    return (
      <Box
        sx={{
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'text.secondary',
          p: compact ? 1.5 : 3,
        }}
      >
        <SecurityIcon sx={{ fontSize: compact ? 24 : 40, mb: compact ? 1 : 1.5, opacity: 0.4 }} />
        <Typography variant={compact ? 'caption' : 'body2'}>No profile data available</Typography>
        {!compact && (
          <Typography variant="caption" color="text.secondary">
            Run analysis to generate binary profile
          </Typography>
        )}
      </Box>
    );
  }

  const profile = data.profile;

  // Compact mode: show only security badges and risk level
  if (compact) {
    const severity = profile.risk_level === 'high' ? 'error' : profile.risk_level === 'medium' ? 'warning' : 'success';
    return (
      <Box sx={{ p: 1 }}>
        <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1}>
          <Typography variant="caption" color="text.secondary" fontWeight={600}>
            Security Profile
          </Typography>
          <Chip
            size="small"
            label={`${profile.risk_level.toUpperCase()} Risk`}
            color={severity}
            sx={{ fontWeight: 600, fontSize: '0.65rem', height: 20 }}
          />
        </Stack>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
          {SECURITY_FEATURES.map((feature) => (
            <SecurityBadge
              key={feature.key}
              feature={feature}
              value={profile.security[feature.key]}
            />
          ))}
        </Box>
        {profile.risk_factors.length > 0 && (
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1, fontStyle: 'italic' }}>
            {profile.risk_factors.length} risk factor{profile.risk_factors.length !== 1 ? 's' : ''} detected
          </Typography>
        )}
      </Box>
    );
  }

  return (
    <Box sx={{ p: 1.5, height: '100%', overflow: 'auto' }}>
      {/* Risk Alert */}
      <RiskAlert level={profile.risk_level} factors={profile.risk_factors} />

      <Grid container spacing={1.5}>
        {/* Binary Info */}
        <Grid item xs={12} md={6}>
          <Paper variant="outlined" sx={{ p: 1.5, height: '100%' }}>
            <Typography variant="caption" color="text.secondary" fontWeight={600}>
              Binary Info
            </Typography>
            <Box sx={{ mt: 1 }}>
              {[
                ['File Type', profile.file_type || 'Unknown'],
                ['Architecture', profile.architecture || 'Unknown'],
                ['Bits', profile.bits ? `${profile.bits}-bit` : 'Unknown'],
                ['Endianness', profile.endian],
                ['Stripped', profile.is_stripped === null ? 'Unknown' : profile.is_stripped ? 'Yes' : 'No'],
                ['Debug Info', profile.has_debug_info === null ? 'Unknown' : profile.has_debug_info ? 'Yes' : 'No'],
                ['Total Strings', profile.total_strings.toLocaleString()],
              ].map(([label, value]) => (
                <Box key={label} sx={{ display: 'flex', justifyContent: 'space-between', py: 0.25 }}>
                  <Typography variant="caption" color="text.secondary">{label}</Typography>
                  <Typography variant="caption" sx={{ fontFamily: label === 'Total Strings' ? 'inherit' : 'monospace' }}>
                    {value}
                  </Typography>
                </Box>
              ))}
            </Box>
          </Paper>
        </Grid>

        {/* Security Features */}
        <Grid item xs={12} md={6}>
          <Paper variant="outlined" sx={{ p: 1.5, height: '100%' }}>
            <Typography variant="caption" color="text.secondary" fontWeight={600}>
              Security Features
            </Typography>
            <Box sx={{ mt: 1, display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
              {SECURITY_FEATURES.map((feature) => (
                <SecurityBadge
                  key={feature.key}
                  feature={feature}
                  value={profile.security[feature.key]}
                />
              ))}
            </Box>
            {(profile.security.rpath || profile.security.runpath) && (
              <Box sx={{ mt: 1 }}>
                <Typography variant="caption" color="warning.main">
                  {profile.security.rpath && 'RPATH set '}
                  {profile.security.runpath && 'RUNPATH set'}
                  {' (potential hijacking risk)'}
                </Typography>
              </Box>
            )}
          </Paper>
        </Grid>

        {/* Embedded Files */}
        {profile.embedded_files.length > 0 && (
          <Grid item xs={12}>
            <Paper variant="outlined" sx={{ p: 1.5 }}>
              <Typography variant="caption" color="text.secondary" fontWeight={600}>
                Embedded Data ({profile.embedded_files.length} items)
              </Typography>
              <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                {profile.has_compressed_data && (
                  <Chip label="Contains compressed data" size="small" color="info" variant="outlined" />
                )}
                {profile.has_encrypted_data && (
                  <Chip label="Contains encrypted data" size="small" color="warning" variant="outlined" />
                )}
              </Stack>
              <Box sx={{ mt: 1, fontFamily: 'monospace', fontSize: '0.7rem' }}>
                {profile.embedded_files.slice(0, 5).map((file, i) => (
                  <Box key={i} sx={{ py: 0.25 }}>
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ fontFamily: 'monospace' }}
                    >
                      0x{file.offset.toString(16)}:
                    </Typography>{' '}
                    <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                      {file.description}
                    </Typography>
                  </Box>
                ))}
                {profile.embedded_files.length > 5 && (
                  <Typography variant="caption" color="text.secondary">
                    ...and {profile.embedded_files.length - 5} more
                  </Typography>
                )}
              </Box>
            </Paper>
          </Grid>
        )}

        {/* Interesting Strings */}
        <Grid item xs={12}>
          <Paper variant="outlined" sx={{ p: 1.5 }}>
            <Typography variant="caption" color="text.secondary" fontWeight={600} sx={{ mb: 1, display: 'block' }}>
              Interesting Strings
            </Typography>

            <StringCategory
              title="Network-related"
              strings={profile.network_strings}
              color="info"
            />

            <StringCategory
              title="Cryptography"
              strings={profile.crypto_strings}
              color="secondary"
            />

            <StringCategory
              title="File I/O"
              strings={profile.file_io_strings}
              color="primary"
            />

            <StringCategory
              title="Dangerous Functions"
              strings={profile.dangerous_functions}
              color="warning"
            />

            <StringCategory
              title="Suspicious Strings"
              strings={profile.suspicious_strings}
              color="error"
            />

            {profile.network_strings.length === 0 &&
              profile.crypto_strings.length === 0 &&
              profile.file_io_strings.length === 0 &&
              profile.dangerous_functions.length === 0 &&
              profile.suspicious_strings.length === 0 && (
                <Typography variant="caption" color="text.secondary">
                  No notable strings detected
                </Typography>
              )}
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default AutoProfilePanel;
