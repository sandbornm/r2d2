import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import { Box, Button, Paper, Stack, Typography } from '@mui/material';
import { FC, useMemo } from 'react';
import { rankImports, rankStrings, rankTargets, type Lens } from '../utils/rank';

const copyText = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // ignore
  }
};

const offsetHex = (item: Record<string, unknown>): string => {
  if (typeof item.offset_hex === 'string' && item.offset_hex) return item.offset_hex;
  if (typeof item.offset === 'number') return `0x${item.offset.toString(16)}`;
  return '';
};

const carveCommand = (binary: string, item: Record<string, unknown>): string => {
  const off = offsetHex(item);
  const kind = String(item.kind || '');
  if (kind.includes('squash')) {
    return `dd if=${binary} of=rootfs.squashfs bs=1 skip=$((${off || '0'})) status=none && unsquashfs -d rootfs rootfs.squashfs`;
  }
  if (kind.includes('elf')) {
    return `r2 -A -c 'ii~strcpy; iz~cgi; axt @ sym.imp.popen' ${item.carved_path || binary}`;
  }
  return `dd if=${binary} bs=1 skip=$((${off || '0'})) count=256 | xxd`;
};

export interface AnalysisSteerProps {
  binary: string;
  firmware?: Record<string, unknown> | null;
  imports: string[];
  sniffStrings?: string[];
  lenses?: Lens[];
  goal?: string;
}

const AnalysisSteer: FC<AnalysisSteerProps> = ({
  binary,
  firmware,
  imports,
  sniffStrings = [],
  lenses = ['general'],
  goal = '',
}) => {
  const sinks = useMemo(() => rankImports(imports, lenses), [imports, lenses]);

  const targets = useMemo(() => {
    const raw = [
      ...((Array.isArray(firmware?.recommended_targets) ? firmware.recommended_targets : []) as Record<string, unknown>[]),
      ...((Array.isArray(firmware?.embedded_artifacts) ? firmware.embedded_artifacts : []) as Record<string, unknown>[]),
    ];
    return rankTargets(raw, lenses);
  }, [firmware, lenses]);

  const strings = useMemo(
    () => rankStrings(sniffStrings, lenses, goal),
    [sniffStrings, lenses, goal],
  );

  if (!sinks.length && !targets.length && !strings.length) return null;

  return (
    <Paper variant="outlined" sx={{ p: 1.5 }} data-testid="analysis-steer">
      <Typography variant="overline" sx={{ letterSpacing: '0.08em' }}>
        Steer
      </Typography>
      {targets.length > 0 && (
        <Box sx={{ mt: 1 }}>
          <Typography variant="caption" color="text.disabled">CARVE / OPEN</Typography>
          <Stack spacing={0.5} sx={{ mt: 0.5 }}>
            {targets.map((item) => {
              const cmd = carveCommand(binary, item);
              const label = `${offsetHex(item)}  ${item.name || item.kind}`;
              return (
                <Stack key={label} direction="row" spacing={1} alignItems="center">
                  <Typography variant="caption" sx={{ fontFamily: 'var(--font-mono)', flex: 1 }} noWrap>
                    {label}
                  </Typography>
                  <Button
                    size="small"
                    variant="text"
                    startIcon={<ContentCopyIcon sx={{ fontSize: 12 }} />}
                    onClick={() => void copyText(cmd)}
                    sx={{ minWidth: 0, fontSize: '0.65rem' }}
                  >
                    cmd
                  </Button>
                </Stack>
              );
            })}
          </Stack>
        </Box>
      )}
      {sinks.length > 0 && (
        <Box sx={{ mt: 1.25 }}>
          <Typography variant="caption" color="text.disabled">XREF</Typography>
          <Box sx={{ mt: 0.5, display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
            {sinks.map((name) => (
              <Button
                key={name}
                size="small"
                variant="outlined"
                onClick={() => void copyText(`r2 -c 'aaa; axt @ sym.imp.${name}' ${binary}`)}
                sx={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', py: 0, minHeight: 22 }}
              >
                {name}
              </Button>
            ))}
          </Box>
        </Box>
      )}
      {strings.length > 0 && (
        <Box sx={{ mt: 1.25 }}>
          <Typography variant="caption" color="text.disabled">STRINGS</Typography>
          <Box sx={{ mt: 0.5, fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
            {strings.map((value) => (
              <Typography key={value} variant="caption" display="block" noWrap sx={{ py: 0.2, borderBottom: 1, borderColor: 'divider', fontFamily: 'var(--font-mono)' }}>
                {value}
              </Typography>
            ))}
          </Box>
        </Box>
      )}
    </Paper>
  );
};

export default AnalysisSteer;
