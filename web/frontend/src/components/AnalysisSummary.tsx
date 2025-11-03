import InsightsIcon from '@mui/icons-material/Insights';
import MemoryIcon from '@mui/icons-material/Memory';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import { Chip, Grid, Paper, Stack, Typography } from '@mui/material';
import { FC, useMemo } from 'react';
import type { AnalysisResultPayload, ComplexityLevel } from '../types';

interface AnalysisSummaryProps {
  analysis: AnalysisResultPayload | null;
  complexity: ComplexityLevel;
}

const InfoCard: FC<{ title: string; value: string; icon?: JSX.Element; tone?: 'info' | 'warn' }>
  = ({ title, value, icon, tone = 'info' }) => (
    <Paper
      variant="outlined"
      sx={{
        height: '100%',
        p: 2.5,
        display: 'flex',
        flexDirection: 'column',
        gap: 1,
        borderColor: tone === 'warn' ? 'warning.main' : 'divider',
      }}
    >
      <Stack direction="row" spacing={1} alignItems="center">
        {icon}
        <Typography variant="subtitle2" color="text.secondary">
          {title}
        </Typography>
      </Stack>
      <Typography variant="h6" sx={{ wordBreak: 'break-word' }}>
        {value}
      </Typography>
    </Paper>
  );

export const AnalysisSummary: FC<AnalysisSummaryProps> = ({ analysis, complexity }) => {
  const summary = useMemo(() => {
    if (!analysis) {
      return null;
    }
    const quick = analysis.quick_scan;
    const radareInfo = (quick.radare2 as Record<string, unknown>)?.['info'];
    let architecture: string | undefined;
    let bits: string | undefined;
    let entrypoint: string | undefined;
    if (radareInfo && typeof radareInfo === 'object') {
      const bin = (radareInfo as Record<string, unknown>).bin;
      if (bin && typeof bin === 'object') {
        architecture = String((bin as Record<string, unknown>).arch ?? 'unknown');
        bits = String((bin as Record<string, unknown>).bits ?? 'unknown');
        const entry = (bin as Record<string, unknown>).baddr;
        if (typeof entry === 'number') {
          entrypoint = `0x${entry.toString(16)}`;
        } else if (typeof entry === 'string') {
          entrypoint = entry;
        }
      }
    }

    const deep = analysis.deep_scan;
    const functions = Array.isArray((deep.radare2 as Record<string, unknown>)?.['functions'])
      ? ((deep.radare2 as Record<string, unknown>)?.['functions'] as unknown[])
      : [];
    const instructions = Array.isArray((deep.capstone as Record<string, unknown>)?.['instructions'])
      ? ((deep.capstone as Record<string, unknown>)?.['instructions'] as unknown[])
      : [];

    return {
      architecture: architecture ?? 'unknown',
      bits: bits ?? 'unknown',
      entrypoint: entrypoint ?? 'N/A',
      functionCount: functions.length,
      instructionPreview: instructions.slice(0, 5),
    };
  }, [analysis]);

  if (!analysis || !summary) {
    return (
      <Paper variant="outlined" sx={{ p: 4, textAlign: 'center', color: 'text.secondary' }}>
        <Typography variant="h6" gutterBottom>
          No analysis yet
        </Typography>
        <Typography variant="body2">Kick off an analysis to populate architecture insights.</Typography>
      </Paper>
    );
  }

  return (
    <Stack spacing={2}>
      <Grid container spacing={2}>
        <Grid item xs={12} sm={6} md={3}>
          <InfoCard title="Architecture" value={summary.architecture} icon={<MemoryIcon color="secondary" />} />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <InfoCard title="Bits" value={summary.bits} icon={<MemoryIcon color="primary" />} />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <InfoCard title="Functions" value={summary.functionCount.toString()} icon={<InsightsIcon color="primary" />} />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <InfoCard title="Entrypoint" value={summary.entrypoint} icon={<InsightsIcon color="secondary" />} />
        </Grid>
      </Grid>

      {analysis.issues.length > 0 && (
        <Paper variant="outlined" sx={{ p: 2.5 }}>
          <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
            <WarningAmberIcon color="warning" />
            <Typography variant="subtitle1">Issues flagged</Typography>
          </Stack>
          <Stack direction="row" spacing={1} flexWrap="wrap">
            {analysis.issues.map((issue) => (
              <Chip key={issue} label={issue} color="warning" variant="outlined" />
            ))}
          </Stack>
        </Paper>
      )}

      {complexity !== 'beginner' && summary.instructionPreview.length > 0 && (
        <Paper variant="outlined" sx={{ p: 2.5 }}>
          <Typography variant="subtitle1" gutterBottom>
            Capstone preview
          </Typography>
          <Stack component="ul" spacing={0.5} sx={{ listStyle: 'none', pl: 0 }}>
            {summary.instructionPreview.map((insn, idx) => {
              if (!insn || typeof insn !== 'object') {
                return null;
              }
              const record = insn as Record<string, unknown>;
              const mnemonic = String(record.mnemonic ?? 'unknown');
              const opStr = String(record.op_str ?? '');
              const address = record.address;
              const addressLabel = typeof address === 'number' ? `0x${address.toString(16)}` : String(address ?? '');
              return (
                <li key={`${mnemonic}-${idx}`}>
                  <Typography variant="body2" fontFamily="monospace">
                    {addressLabel}: {mnemonic} {opStr}
                  </Typography>
                </li>
              );
            })}
          </Stack>
        </Paper>
      )}
    </Stack>
  );
};

export default AnalysisSummary;
