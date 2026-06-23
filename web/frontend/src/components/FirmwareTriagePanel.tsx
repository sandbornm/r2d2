import AccountTreeIcon from '@mui/icons-material/AccountTree';
import DataObjectIcon from '@mui/icons-material/DataObject';
import FolderZipIcon from '@mui/icons-material/FolderZip';
import GpsFixedIcon from '@mui/icons-material/GpsFixed';
import KeyIcon from '@mui/icons-material/Key';
import LanIcon from '@mui/icons-material/Lan';
import SecurityIcon from '@mui/icons-material/Security';
import StorageIcon from '@mui/icons-material/Storage';
import WarningIcon from '@mui/icons-material/Warning';
import { Box, Chip, Grid, Paper, Stack, Tooltip, Typography, alpha, useTheme } from '@mui/material';
import { FC, ReactNode, useMemo } from 'react';
import type { AutoProfileData } from '../types';

interface FirmwareArtifact {
  offset?: number;
  offset_hex?: string;
  kind?: string;
  name?: string;
  description?: string;
  source?: string;
  confidence?: number;
  recommended?: boolean;
  analysis_role?: string;
  fanout_tools?: string[];
  declared_size?: number;
  payload_size?: number;
  image_name?: string;
  entrypoint?: string;
  load_address?: string;
  carved_path?: string;
  carved_size?: number;
  carved_sha256?: string;
  carved_signature?: string;
}

interface FirmwareFanoutTask {
  target?: string;
  offset?: number;
  kind?: string;
  role?: string;
  tools?: string[];
  status?: string;
  reason?: string;
}

interface FirmwareStringSignal {
  category?: string;
  label?: string;
  value?: string;
  offset?: number;
  offset_hex?: string;
  confidence?: number;
}

interface FirmwareStringSignals {
  total_strings?: number;
  matched_count?: number;
  category_counts?: Record<string, number>;
  categories?: Record<string, FirmwareStringSignal[]>;
  top_signals?: FirmwareStringSignal[];
  string_min_length?: number;
}

interface FirmwareEntropyWindow {
  offset?: number;
  offset_hex?: string;
  entropy?: number;
  size?: number;
}

interface FirmwareEntropy {
  window_size?: number;
  sampled_windows?: number;
  average?: number;
  max?: number;
  high_entropy_windows?: FirmwareEntropyWindow[];
  high_entropy_threshold?: number;
}

interface FirmwareData {
  mode?: string;
  size_bytes?: number;
  sha256?: string;
  is_elf?: boolean;
  top_level_format?: string;
  container_type?: string;
  scan?: {
    bytes_scanned?: number;
    truncated?: boolean;
    binwalk_available?: boolean;
    binwalk_used?: boolean;
    signature_count?: number;
  };
  embedded_artifacts?: FirmwareArtifact[];
  recommended_targets?: FirmwareArtifact[];
  carved_targets?: FirmwareArtifact[];
  fanout_tasks?: FirmwareFanoutTask[];
  string_signals?: FirmwareStringSignals;
  entropy?: FirmwareEntropy;
  extraction?: {
    enabled?: boolean;
    output_dir?: string;
    carved_count?: number;
    max_carve_bytes?: number;
    strategy?: string;
  };
  notes?: string[];
}

interface FirmwareChildAnalysis {
  mode?: string;
  analyses?: Array<{
    tool?: string;
    target?: string;
    status?: string;
    error?: string;
  }>;
  skipped?: Array<{
    tool?: string;
    target?: string;
    reason?: string;
  }>;
  reason?: string;
}

interface FirmwareTriagePanelProps {
  firmware: FirmwareData | null;
  profile?: AutoProfileData | null;
  childrenAnalysis?: FirmwareChildAnalysis | null;
  compact?: boolean;
}

const formatBytes = (value: number | undefined): string => {
  if (typeof value !== 'number' || Number.isNaN(value)) return 'unknown';
  if (value < 1024) return `${value} B`;
  const units = ['KB', 'MB', 'GB'];
  let next = value / 1024;
  for (const unit of units) {
    if (next < 1024) return `${next.toFixed(next >= 10 ? 1 : 2)} ${unit}`;
    next /= 1024;
  }
  return `${next.toFixed(1)} TB`;
};

const humanize = (value: string | undefined): string => {
  if (!value) return 'unknown';
  return value.replace(/_/g, ' ');
};

const offsetLabel = (artifact: FirmwareArtifact | FirmwareFanoutTask): string => {
  if ('offset_hex' in artifact && artifact.offset_hex) return artifact.offset_hex;
  return typeof artifact.offset === 'number' ? `0x${artifact.offset.toString(16)}` : 'n/a';
};

const shortPath = (path: string | undefined): string => {
  if (!path) return '';
  const parts = path.split('/');
  return parts.slice(-2).join('/');
};

const formatEntropy = (value: number | undefined): string => {
  if (typeof value !== 'number' || Number.isNaN(value)) return 'n/a';
  return value.toFixed(2);
};

const truncateMiddle = (value: string, limit = 72): string => {
  if (value.length <= limit) return value;
  return `${value.slice(0, Math.max(16, limit - 16))}...${value.slice(-12)}`;
};

const countBy = (items: FirmwareArtifact[], key: keyof FirmwareArtifact): Array<[string, number]> => {
  const counts = new Map<string, number>();
  for (const item of items) {
    const value = String(item[key] || 'unknown');
    counts.set(value, (counts.get(value) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
};

const StatTile: FC<{ icon: ReactNode; label: string; value: string | number; detail?: string; tone?: 'info' | 'warn' | 'ok' }> = ({
  icon,
  label,
  value,
  detail,
  tone = 'info',
}) => {
  const theme = useTheme();
  const color =
    tone === 'ok' ? theme.palette.success.main : tone === 'warn' ? theme.palette.warning.main : theme.palette.info.main;
  return (
    <Paper
      variant="outlined"
      sx={{
        p: 1.25,
        height: '100%',
        bgcolor: alpha(color, theme.palette.mode === 'dark' ? 0.09 : 0.06),
        borderColor: alpha(color, 0.25),
      }}
    >
      <Stack direction="row" spacing={1} alignItems="center">
        <Box sx={{ color, display: 'flex' }}>{icon}</Box>
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
            {label}
          </Typography>
          <Typography variant="body2" fontWeight={700} noWrap>
            {value}
          </Typography>
          {detail && (
            <Typography variant="caption" color="text.secondary" noWrap>
              {detail}
            </Typography>
          )}
        </Box>
      </Stack>
    </Paper>
  );
};

const ArtifactRow: FC<{ artifact: FirmwareArtifact }> = ({ artifact }) => {
  const tools = Array.isArray(artifact.fanout_tools) ? artifact.fanout_tools : [];
  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: { xs: '86px 1fr', md: '90px 150px 1fr 125px' },
        gap: 1,
        alignItems: 'center',
        py: 0.75,
        borderBottom: 1,
        borderColor: 'divider',
      }}
    >
      <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
        {offsetLabel(artifact)}
      </Typography>
      <Typography variant="caption" sx={{ display: { xs: 'none', md: 'block' } }}>
        {humanize(artifact.kind)}
      </Typography>
      <Box sx={{ minWidth: 0 }}>
        <Typography variant="caption" fontWeight={600} noWrap>
          {artifact.name || humanize(artifact.carved_signature) || 'artifact'}
        </Typography>
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }} noWrap>
          {artifact.description || shortPath(artifact.carved_path) || artifact.image_name || artifact.analysis_role || 'signature hit'}
        </Typography>
      </Box>
      <Stack direction="row" spacing={0.5} justifyContent="flex-end" sx={{ display: { xs: 'none', md: 'flex' } }}>
        {artifact.recommended && <Chip size="small" label="target" color="info" variant="outlined" sx={{ height: 20 }} />}
        {tools.slice(0, 2).map((tool) => (
          <Chip key={tool} size="small" label={tool} variant="outlined" sx={{ height: 20, fontSize: '0.65rem' }} />
        ))}
      </Stack>
    </Box>
  );
};

const FirmwareTriagePanel: FC<FirmwareTriagePanelProps> = ({ firmware, profile, childrenAnalysis, compact = false }) => {
  const theme = useTheme();
  const artifacts = Array.isArray(firmware?.embedded_artifacts) ? firmware.embedded_artifacts : [];
  const targets = Array.isArray(firmware?.recommended_targets) ? firmware.recommended_targets : [];
  const carved = Array.isArray(firmware?.carved_targets) ? firmware.carved_targets : [];
  const fanout = Array.isArray(firmware?.fanout_tasks) ? firmware.fanout_tasks : [];
  const profileData = profile?.profile;
  const topFirmwareSignals = Array.isArray(firmware?.string_signals?.top_signals) ? firmware.string_signals.top_signals : [];
  const signalCounts = firmware?.string_signals?.category_counts ?? {};
  const signalCount = firmware?.string_signals?.matched_count ?? topFirmwareSignals.length;
  const highEntropyWindows = Array.isArray(firmware?.entropy?.high_entropy_windows) ? firmware.entropy.high_entropy_windows : [];
  const credentialSignalCount = signalCounts.credential ?? 0;
  const networkSignalCount = signalCounts.network ?? 0;
  const serviceSignalCount = signalCounts.service ?? 0;
  const cryptoSignalCount = signalCounts.crypto ?? 0;
  const filesystemSignalCount = signalCounts.filesystem ?? 0;
  const updateSignalCount = signalCounts.update ?? 0;
  const dangerousApiSignalCount = signalCounts.dangerous_api ?? 0;

  const roleCounts = useMemo(() => countBy(artifacts, 'analysis_role'), [artifacts]);
  const kindCounts = useMemo(() => countBy(artifacts, 'kind'), [artifacts]);
  const codeTargets = targets.filter((target) => target.analysis_role === 'code' || target.kind === 'elf_binary');
  const filesystemTargets = targets.filter((target) => target.analysis_role === 'filesystem' || target.kind?.includes('filesystem'));
  const credentialHits = artifacts.filter(
    (artifact) => artifact.kind === 'credential_material' || /private key|certificate|secret/i.test(artifact.description || artifact.name || '')
  );

  const securitySignals = useMemo(() => {
    const signals: Array<{ label: string; detail: string; tone: 'error' | 'warning' | 'info' | 'success' }> = [];
    if (credentialHits.length) {
      signals.push({ label: 'Credential material', detail: `${credentialHits.length} signature hit(s)`, tone: 'error' });
    }
    if (credentialSignalCount) {
      signals.push({ label: 'Credential strings', detail: `${credentialSignalCount} firmware-native hit(s)`, tone: 'error' });
    }
    if (codeTargets.length) {
      signals.push({ label: 'Executable payloads', detail: `${codeTargets.length} code target(s)`, tone: 'warning' });
    }
    if (filesystemTargets.length) {
      signals.push({ label: 'Filesystem image', detail: `${filesystemTargets.length} extraction target(s)`, tone: 'info' });
    }
    if (networkSignalCount || serviceSignalCount) {
      signals.push({ label: 'Network/service strings', detail: `${networkSignalCount + serviceSignalCount} firmware-native hit(s)`, tone: 'info' });
    }
    if (dangerousApiSignalCount) {
      signals.push({ label: 'Command/API strings', detail: `${dangerousApiSignalCount} firmware-native hit(s)`, tone: 'warning' });
    }
    if (highEntropyWindows.length) {
      signals.push({ label: 'High entropy regions', detail: `${highEntropyWindows.length} sampled window(s)`, tone: 'warning' });
    }
    if (profileData?.network_strings?.length) {
      signals.push({ label: 'Network indicators', detail: `${profileData.network_strings.length} string hit(s)`, tone: 'info' });
    }
    if (profileData?.dangerous_functions?.length) {
      signals.push({ label: 'Dangerous APIs', detail: `${profileData.dangerous_functions.length} string hit(s)`, tone: 'warning' });
    }
    if (profileData?.suspicious_strings?.length) {
      signals.push({ label: 'Suspicious strings', detail: `${profileData.suspicious_strings.length} string hit(s)`, tone: 'warning' });
    }
    if (profileData?.has_encrypted_data) {
      signals.push({ label: 'Encrypted-looking data', detail: 'binwalk/autoprofile indicator', tone: 'warning' });
    }
    if (!signals.length) {
      signals.push({ label: 'No high-signal indicators', detail: 'Review artifacts and strings manually', tone: 'success' });
    }
    return signals;
  }, [
    codeTargets.length,
    credentialHits.length,
    credentialSignalCount,
    dangerousApiSignalCount,
    filesystemTargets.length,
    highEntropyWindows.length,
    networkSignalCount,
    profileData,
    serviceSignalCount,
  ]);

  const nextActions = useMemo(() => {
    const actions: string[] = [];
    if (filesystemTargets.length) actions.push('Extract filesystem targets and inspect init scripts, web roots, configs, and writable paths.');
    if (codeTargets.length) actions.push('Analyze carved ELF/code targets for entry points, imports, unsafe parsing, and update paths.');
    if (credentialHits.length) actions.push('Review credential/certificate hits and determine whether private material ships in the image.');
    if (credentialSignalCount) actions.push('Validate credential-like strings against extracted configs, web handlers, and default login paths.');
    if (dangerousApiSignalCount) actions.push('Trace command/API string leads to call sites and input-controlled paths.');
    if (profileData?.network_strings?.length) actions.push('Trace network endpoints, management interfaces, update URLs, and default service exposure.');
    if (networkSignalCount || serviceSignalCount) actions.push('Map firmware-native network/service strings to daemons, init scripts, and listening sockets.');
    if (profileData?.crypto_strings?.length) actions.push('Check crypto usage, key storage, certificate validation, and custom protocols.');
    if (cryptoSignalCount) actions.push('Review crypto and certificate strings for custom trust stores, weak algorithms, and key reuse.');
    if (highEntropyWindows.length) actions.push('Inspect high-entropy regions for compressed, encrypted, or packed payloads before deeper carving.');
    if (!actions.length && artifacts.length) actions.push('Group artifact kinds and decide which container or code target unlocks the next layer.');
    if (!actions.length) actions.push('Run deeper extraction or entropy/string sweeps; no common firmware signatures were found in the scanned prefix.');
    return actions.slice(0, compact ? 3 : 6);
  }, [
    artifacts.length,
    codeTargets.length,
    compact,
    credentialHits.length,
    credentialSignalCount,
    cryptoSignalCount,
    dangerousApiSignalCount,
    filesystemTargets.length,
    highEntropyWindows.length,
    networkSignalCount,
    profileData,
    serviceSignalCount,
  ]);

  if (!firmware) return null;

  return (
    <Paper variant="outlined" sx={{ p: 1.5 }}>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ xs: 'flex-start', sm: 'center' }} mb={1.25}>
        <SecurityIcon sx={{ color: 'primary.main' }} />
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Typography variant="caption" color="text.secondary" fontWeight={700}>
            Firmware Triage
          </Typography>
          <Typography variant="body2" fontWeight={700} noWrap>
            {humanize(firmware.top_level_format)} · {humanize(firmware.container_type)}
          </Typography>
        </Box>
        <Stack direction="row" spacing={0.5} flexWrap="wrap" gap={0.5}>
          <Chip size="small" label={`${artifacts.length} artifacts`} variant="outlined" />
          <Chip size="small" label={`${targets.length} targets`} variant="outlined" />
          <Chip size="small" label={`${carved.length} carved`} variant="outlined" />
        </Stack>
      </Stack>

      <Grid container spacing={1}>
        <Grid item xs={6} md={3}>
          <StatTile icon={<StorageIcon fontSize="small" />} label="Image Size" value={formatBytes(firmware.size_bytes)} detail={firmware.is_elf ? 'top-level ELF' : 'container/blob'} />
        </Grid>
        <Grid item xs={6} md={3}>
          <StatTile
            icon={<GpsFixedIcon fontSize="small" />}
            label="Scan"
            value={`${firmware.scan?.signature_count ?? artifacts.length} signatures`}
            detail={firmware.scan?.truncated ? `scanned ${formatBytes(firmware.scan.bytes_scanned)}` : 'full prefix scanned'}
            tone={firmware.scan?.truncated ? 'warn' : 'ok'}
          />
        </Grid>
        <Grid item xs={6} md={3}>
          <StatTile
            icon={<DataObjectIcon fontSize="small" />}
            label="Signal Strings"
            value={signalCount}
            detail={`${credentialSignalCount + networkSignalCount + serviceSignalCount} credential/network`}
            tone={credentialSignalCount || dangerousApiSignalCount ? 'warn' : 'info'}
          />
        </Grid>
        <Grid item xs={6} md={3}>
          <StatTile
            icon={<LanIcon fontSize="small" />}
            label="Entropy"
            value={formatEntropy(firmware.entropy?.max)}
            detail={highEntropyWindows.length ? `${highEntropyWindows.length} high window(s)` : `${firmware.entropy?.sampled_windows ?? 0} sampled`}
            tone={highEntropyWindows.length ? 'warn' : 'info'}
          />
        </Grid>
      </Grid>

      <Grid container spacing={1.25} sx={{ mt: 0.25 }}>
        <Grid item xs={12} md={compact ? 12 : 5}>
          <Typography variant="caption" color="text.secondary" fontWeight={700}>
            Security Signals
          </Typography>
          <Stack direction="row" spacing={0.5} flexWrap="wrap" gap={0.5} sx={{ mt: 0.75 }}>
            {securitySignals.map((signal) => (
              <Tooltip key={`${signal.label}:${signal.detail}`} title={signal.detail}>
                <Chip
                  size="small"
                  icon={signal.tone === 'error' || signal.tone === 'warning' ? <WarningIcon /> : undefined}
                  label={signal.label}
                  color={signal.tone}
                  variant={signal.tone === 'success' ? 'outlined' : 'filled'}
                  sx={{ maxWidth: 230 }}
                />
              </Tooltip>
            ))}
          </Stack>
        </Grid>

        <Grid item xs={12} md={compact ? 12 : 7}>
          <Typography variant="caption" color="text.secondary" fontWeight={700}>
            Next Analysis Moves
          </Typography>
          <Box component="ul" sx={{ m: 0, mt: 0.5, pl: 2 }}>
            {nextActions.map((action) => (
              <Typography key={action} component="li" variant="caption" sx={{ lineHeight: 1.7 }}>
                {action}
              </Typography>
            ))}
          </Box>
        </Grid>
      </Grid>

      {!compact && (
        <Grid container spacing={1.25} sx={{ mt: 0.25 }}>
          <Grid item xs={12} md={6}>
            <Typography variant="caption" color="text.secondary" fontWeight={700}>
              Artifact Mix
            </Typography>
            <Stack direction="row" spacing={0.5} flexWrap="wrap" gap={0.5} sx={{ mt: 0.75 }}>
              {kindCounts.slice(0, 8).map(([kind, count]) => (
                <Chip key={kind} size="small" label={`${humanize(kind)} ${count}`} variant="outlined" />
              ))}
              {!kindCounts.length && <Typography variant="caption" color="text.secondary">No embedded signatures found</Typography>}
            </Stack>
          </Grid>
          <Grid item xs={12} md={6}>
            <Typography variant="caption" color="text.secondary" fontWeight={700}>
              Routing
            </Typography>
            <Stack direction="row" spacing={0.5} flexWrap="wrap" gap={0.5} sx={{ mt: 0.75 }}>
              {roleCounts.slice(0, 8).map(([role, count]) => (
                <Chip key={role} size="small" label={`${humanize(role)} ${count}`} variant="outlined" />
              ))}
              {fanout.slice(0, 3).map((task) => (
                <Chip
                  key={`${task.target}:${task.role}`}
                  size="small"
                  icon={<AccountTreeIcon />}
                  label={`${humanize(task.role)} -> ${(task.tools || []).slice(0, 3).join(', ') || 'triage'}`}
                  variant="outlined"
                />
              ))}
            </Stack>
          </Grid>

          {(topFirmwareSignals.length > 0 || Object.keys(signalCounts).length > 0) && (
            <Grid item xs={12}>
              <Typography variant="caption" color="text.secondary" fontWeight={700}>
                Firmware String Signals
              </Typography>
              <Stack direction="row" spacing={0.5} flexWrap="wrap" gap={0.5} sx={{ mt: 0.75 }}>
                {[
                  ['credential', credentialSignalCount],
                  ['network', networkSignalCount],
                  ['service', serviceSignalCount],
                  ['crypto', cryptoSignalCount],
                  ['filesystem', filesystemSignalCount],
                  ['update', updateSignalCount],
                  ['dangerous_api', dangerousApiSignalCount],
                ]
                  .filter(([, count]) => Number(count) > 0)
                  .map(([category, count]) => (
                    <Chip
                      key={category}
                      size="small"
                      label={`${humanize(String(category))} ${count}`}
                      color={category === 'credential' || category === 'dangerous_api' ? 'warning' : 'info'}
                      variant="outlined"
                    />
                  ))}
              </Stack>
              {topFirmwareSignals.length > 0 && (
                <Stack direction="row" spacing={0.5} flexWrap="wrap" gap={0.5} sx={{ mt: 0.75 }}>
                  {topFirmwareSignals.slice(0, 24).map((signal, index) => {
                    const value = signal.value || signal.label || 'signal';
                    const category = signal.category || 'signal';
                    const color = category === 'credential' || category === 'dangerous_api' ? 'warning' : category === 'network' || category === 'service' ? 'info' : 'default';
                    return (
                      <Tooltip
                        key={`${signal.offset}:${category}:${value}:${index}`}
                        title={`${humanize(category)} at ${signal.offset_hex || offsetLabel(signal)}${signal.label ? ` · ${signal.label}` : ''}`}
                      >
                        <Chip
                          size="small"
                          icon={category === 'credential' ? <KeyIcon /> : category === 'network' || category === 'service' ? <LanIcon /> : undefined}
                          label={`${humanize(category)}: ${truncateMiddle(value)}`}
                          color={color}
                          variant="outlined"
                          sx={{ maxWidth: 420, fontFamily: 'monospace', fontSize: '0.65rem' }}
                        />
                      </Tooltip>
                    );
                  })}
                </Stack>
              )}
            </Grid>
          )}

          {highEntropyWindows.length > 0 && (
            <Grid item xs={12}>
              <Typography variant="caption" color="text.secondary" fontWeight={700}>
                High Entropy Windows
              </Typography>
              <Stack direction="row" spacing={0.5} flexWrap="wrap" gap={0.5} sx={{ mt: 0.75 }}>
                {highEntropyWindows.slice(0, 12).map((window, index) => (
                  <Tooltip
                    key={`${window.offset}:${window.entropy}:${index}`}
                    title={`${formatBytes(window.size)} sampled at ${window.offset_hex || offsetLabel(window)}`}
                  >
                    <Chip
                      size="small"
                      icon={<WarningIcon />}
                      label={`${window.offset_hex || offsetLabel(window)} entropy ${formatEntropy(window.entropy)}`}
                      color="warning"
                      variant="outlined"
                    />
                  </Tooltip>
                ))}
              </Stack>
            </Grid>
          )}

          <Grid item xs={12}>
            <Stack direction="row" alignItems="center" spacing={1} mb={0.5}>
              <Typography variant="caption" color="text.secondary" fontWeight={700}>
                Priority Artifacts
              </Typography>
              {firmware.extraction?.output_dir && (
                <Tooltip title={firmware.extraction.output_dir}>
                  <Chip size="small" icon={<FolderZipIcon />} label={`carves: ${shortPath(firmware.extraction.output_dir)}`} variant="outlined" sx={{ height: 20 }} />
                </Tooltip>
              )}
            </Stack>
            <Box
              sx={{
                border: 1,
                borderColor: 'divider',
                borderRadius: 1,
                overflow: 'hidden',
                bgcolor: alpha(theme.palette.background.paper, 0.55),
              }}
            >
              {(targets.length ? targets : artifacts).slice(0, 10).map((artifact) => (
                <ArtifactRow key={`${artifact.offset}:${artifact.kind}:${artifact.name}`} artifact={artifact} />
              ))}
              {!artifacts.length && (
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', p: 1 }}>
                  No common embedded artifact signatures were found.
                </Typography>
              )}
            </Box>
          </Grid>

          {(profileData?.network_strings?.length || profileData?.crypto_strings?.length || profileData?.suspicious_strings?.length) && (
            <Grid item xs={12}>
              <Typography variant="caption" color="text.secondary" fontWeight={700}>
                Indicator Strings
              </Typography>
              <Stack direction="row" spacing={0.5} flexWrap="wrap" gap={0.5} sx={{ mt: 0.75 }}>
                {[
                  ...(profileData.network_strings || []).map((value) => ({ value, tone: 'info' as const, icon: <LanIcon /> })),
                  ...(profileData.crypto_strings || []).map((value) => ({ value, tone: 'secondary' as const, icon: <KeyIcon /> })),
                  ...(profileData.suspicious_strings || []).map((value) => ({ value, tone: 'warning' as const, icon: <WarningIcon /> })),
                ].slice(0, 24).map((item, index) => (
                  <Chip
                    key={`${item.value}:${index}`}
                    size="small"
                    icon={item.icon}
                    label={item.value.length > 56 ? `${item.value.slice(0, 56)}...` : item.value}
                    color={item.tone}
                    variant="outlined"
                    sx={{ maxWidth: 360, fontFamily: 'monospace', fontSize: '0.65rem' }}
                  />
                ))}
              </Stack>
            </Grid>
          )}

          {childrenAnalysis && (
            <Grid item xs={12}>
              <Typography variant="caption" color="text.secondary" fontWeight={700}>
                Child Fanout
              </Typography>
              <Stack direction="row" spacing={0.5} flexWrap="wrap" gap={0.5} sx={{ mt: 0.75 }}>
                {(childrenAnalysis.analyses || []).slice(0, 8).map((analysis) => (
                  <Chip
                    key={`${analysis.tool}:${analysis.target}`}
                    size="small"
                    label={`${analysis.tool || 'tool'} ${analysis.status || 'done'} ${shortPath(analysis.target)}`}
                    color={analysis.status === 'failed' ? 'error' : 'success'}
                    variant="outlined"
                  />
                ))}
                {(childrenAnalysis.skipped || []).slice(0, 6).map((skip) => (
                  <Tooltip key={`${skip.tool}:${skip.target}`} title={skip.reason || ''}>
                    <Chip size="small" label={`${skip.tool || 'tool'} skipped`} color="warning" variant="outlined" />
                  </Tooltip>
                ))}
                {!childrenAnalysis.analyses?.length && !childrenAnalysis.skipped?.length && childrenAnalysis.reason && (
                  <Typography variant="caption" color="text.secondary">{childrenAnalysis.reason}</Typography>
                )}
              </Stack>
            </Grid>
          )}

          {firmware.sha256 && (
            <Grid item xs={12}>
              <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere' }}>
                sha256: {firmware.sha256}
              </Typography>
            </Grid>
          )}
        </Grid>
      )}
    </Paper>
  );
};

export default FirmwareTriagePanel;
