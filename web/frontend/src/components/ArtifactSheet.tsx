import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import { Box, Button, Paper, Stack, Typography } from '@mui/material';
import { FC, useMemo, useState } from 'react';
import type { EvidenceCoverage, ToolScorecardEntry, ToolStatusSummary } from '../types';

export interface ArtifactSheetProps {
  fileName: string;
  format: string;
  arch: string;
  os: string;
  binType?: string;
  compiler?: string;
  firmware?: Record<string, unknown> | null;
  sniff?: Record<string, unknown> | null;
  runtime?: Record<string, unknown> | null;
  briefingSubject?: Record<string, unknown> | null;
  toolStatus: Record<string, ToolStatusSummary>;
  toolScorecard: Record<string, ToolScorecardEntry>;
  evidenceCoverage?: EvidenceCoverage | null;
  functionCount: number;
  importCount: number;
  stringCount: number;
  sha256?: string | null;
}

type FactTone = 'present' | 'partial' | 'missing';

interface FactRow {
  id: string;
  label: string;
  tone: FactTone;
  detail: string;
}

const toneColor: Record<FactTone, string> = {
  present: 'success.main',
  partial: 'warning.main',
  missing: 'text.disabled',
};

const formatBytes = (value: unknown): string => {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return '';
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
};

const asRecord = (value: unknown): Record<string, unknown> | null =>
  value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;

const copyText = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // ignore
  }
};

const ArtifactSheet: FC<ArtifactSheetProps> = ({
  fileName,
  format,
  arch,
  os,
  binType,
  compiler,
  firmware,
  sniff,
  runtime,
  briefingSubject,
  toolStatus,
  functionCount,
  importCount,
  stringCount,
  sha256,
}) => {
  const [showSkipped, setShowSkipped] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  const fileLine = typeof sniff?.file === 'string' ? sniff.file : '';
  const digest = (typeof sniff?.sha256 === 'string' && sniff.sha256) || sha256 || '';
  const sizeLabel = formatBytes(sniff?.size_bytes);
  const hexHead = typeof sniff?.hex_head === 'string' ? sniff.hex_head : '';
  const readelf = typeof sniff?.readelf === 'string' ? sniff.readelf : '';
  const sniffStrings = useMemo(() => {
    const raw = Array.isArray(sniff?.strings) ? sniff.strings : [];
    return raw
      .map((item) => (typeof item === 'string' ? item : asRecord(item)?.value))
      .filter((item): item is string => typeof item === 'string' && item.length > 0)
      .slice(0, 16);
  }, [sniff]);

  const facts = useMemo<FactRow[]>(() => {
    const rows: FactRow[] = [];
    const firmwareFormat = typeof firmware?.top_level_format === 'string' ? firmware.top_level_format : '';
    const container = typeof firmware?.container_type === 'string' ? firmware.container_type : '';
    const artifacts = Array.isArray(firmware?.embedded_artifacts) ? firmware.embedded_artifacts : [];
    const targets = Array.isArray(firmware?.recommended_targets) ? firmware.recommended_targets : [];
    const squashfs = artifacts.find((item) => {
      const rec = asRecord(item);
      const kind = String(rec?.kind ?? rec?.type ?? rec?.name ?? '').toLowerCase();
      return kind.includes('squash');
    });
    const squashRec = asRecord(squashfs);
    const squashOffset = squashRec?.offset ?? squashRec?.start ?? squashRec?.address;

    if (firmwareFormat || container) {
      rows.push({
        id: 'wrapper',
        label: 'wrapper',
        tone: 'present',
        detail: [firmwareFormat, container].filter(Boolean).join(' · '),
      });
    } else if (fileLine && /firmware|data|u-boot|squash/i.test(fileLine)) {
      rows.push({ id: 'wrapper', label: 'wrapper', tone: 'partial', detail: fileLine.slice(0, 80) });
    }

    if (squashRec) {
      rows.push({
        id: 'squashfs',
        label: 'squashfs',
        tone: 'present',
        detail: squashOffset != null ? `carve @ ${String(squashOffset)}` : 'present',
      });
    } else if (firmwareFormat) {
      rows.push({ id: 'squashfs', label: 'squashfs', tone: 'missing', detail: 'not carved' });
    }

    const isElf = /ELF/i.test(fileLine) || format.toLowerCase() === 'elf' || binType === 'elf';
    if (isElf) {
      rows.push({
        id: 'elf',
        label: 'elf',
        tone: functionCount > 0 ? 'present' : 'partial',
        detail: [arch, os, compiler].filter(Boolean).join(' · ') || fileLine.slice(0, 72),
      });
    } else {
      rows.push({
        id: 'elf',
        label: 'elf',
        tone: 'missing',
        detail: targets.length ? `${targets.length} inner target(s) — unpack first` : 'unpack then brief httpd',
      });
    }

    const sinks = Array.isArray(briefingSubject?.dangerous_imports)
      ? briefingSubject.dangerous_imports.map(String)
      : [];
    rows.push({
      id: 'sinks',
      label: 'sinks',
      tone: sinks.length ? 'present' : 'missing',
      detail: sinks.length ? sinks.slice(0, 6).join(', ') : 'none until an ELF is the subject',
    });

    const ranked = sniffStrings.length || stringCount;
    rows.push({
      id: 'strings',
      label: 'strings',
      tone: ranked > 0 ? (sniffStrings.length ? 'present' : 'partial') : 'missing',
      detail: ranked > 0 ? `${ranked} ranked` : 'no interesting hits',
    });

    const needed = Array.isArray(runtime?.needed) ? runtime.needed.map(String) : [];
    if (needed.length || runtime?.interp || runtime?.arch) {
      rows.push({
        id: 'interp',
        label: 'runtime',
        tone: 'present',
        detail: [runtime?.arch, runtime?.interp, needed.slice(0, 3).join(', ')].filter(Boolean).join(' · '),
      });
    }

    rows.push({
      id: 'imports',
      label: 'imports',
      tone: importCount > 0 ? 'present' : 'missing',
      detail: importCount > 0 ? `${importCount}` : 'n/a on a wrapper',
    });

    return rows;
  }, [firmware, fileLine, format, binType, functionCount, arch, os, compiler, briefingSubject, sniffStrings, stringCount, runtime, importCount]);

  const passes = useMemo(() => {
    const entries = Object.entries(toolStatus);
    const visible = entries.filter(([, status]) => showSkipped || status.status !== 'skipped');
    const skipped = entries.filter(([, status]) => status.status === 'skipped').length;
    return { visible, skipped };
  }, [toolStatus, showSkipped]);

  const markCopied = (key: string) => {
    setCopied(key);
    window.setTimeout(() => setCopied((current) => (current === key ? null : current)), 1200);
  };

  return (
    <Paper variant="outlined" data-testid="artifact-sheet" sx={{ p: 1.5, bgcolor: 'background.paper' }}>
      <Stack direction="row" alignItems="baseline" justifyContent="space-between" sx={{ mb: 1 }}>
        <Typography variant="caption" color="text.secondary" fontWeight={600} sx={{ letterSpacing: '0.08em' }}>
          ARTIFACT
        </Typography>
        <Typography variant="caption" color="text.disabled" sx={{ fontFamily: 'var(--font-mono)' }}>
          {fileName}
        </Typography>
      </Stack>

      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: '72px 1fr',
          columnGap: 1.5,
          rowGap: 0.5,
          fontFamily: 'var(--font-mono)',
        }}
      >
        <Typography variant="caption" color="text.disabled">file</Typography>
        <Typography variant="caption" sx={{ wordBreak: 'break-word' }}>
          {fileLine || `${format} · ${arch} · ${os}`}
        </Typography>

        <Typography variant="caption" color="text.disabled">sha256</Typography>
        <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
          <Typography variant="caption" sx={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {digest || '—'}
          </Typography>
          {digest && (
            <Button
              size="small"
              variant="text"
              onClick={() => {
                void copyText(digest);
                markCopied('sha');
              }}
              startIcon={<ContentCopyIcon sx={{ fontSize: 12 }} />}
              sx={{ minWidth: 0, px: 0.5, py: 0, fontSize: '0.65rem' }}
            >
              {copied === 'sha' ? 'copied' : 'copy'}
            </Button>
          )}
          {sizeLabel && (
            <Typography variant="caption" color="text.disabled">{sizeLabel}</Typography>
          )}
        </Stack>
      </Box>

      {hexHead && (
        <Box
          component="pre"
          data-testid="artifact-hex"
          sx={{
            mt: 1.25,
            mb: 0,
            p: 1,
            maxHeight: 148,
            overflow: 'auto',
            bgcolor: 'rgba(200, 169, 106, 0.05)',
            border: '1px solid',
            borderColor: 'divider',
            borderRadius: 0.5,
            fontFamily: 'var(--font-mono)',
            fontSize: '0.68rem',
            lineHeight: 1.45,
            color: 'text.secondary',
          }}
        >
          {hexHead}
        </Box>
      )}

      {sniffStrings.length > 0 && (
        <Box sx={{ mt: 1.25 }}>
          <Typography variant="caption" color="text.disabled" sx={{ letterSpacing: '0.06em' }}>
            STRINGS
          </Typography>
          <Box
            data-testid="artifact-strings"
            sx={{
              mt: 0.5,
              display: 'flex',
              flexWrap: 'wrap',
              gap: 0.5,
              fontFamily: 'var(--font-mono)',
            }}
          >
            {sniffStrings.map((value) => (
              <Typography
                key={value}
                variant="caption"
                sx={{
                  px: 0.75,
                  py: 0.15,
                  border: '1px solid',
                  borderColor: 'divider',
                  borderRadius: 0.5,
                  color: 'text.primary',
                }}
              >
                {value}
              </Typography>
            ))}
          </Box>
        </Box>
      )}

      <Box sx={{ mt: 1.5 }}>
        <Typography variant="caption" color="text.disabled" sx={{ letterSpacing: '0.06em' }}>
          COVERAGE
        </Typography>
        <Box
          data-testid="artifact-coverage"
          sx={{
            mt: 0.75,
            display: 'grid',
            gridTemplateColumns: '76px 64px 1fr',
            columnGap: 1,
            rowGap: 0.4,
            alignItems: 'baseline',
          }}
        >
          {facts.map((fact) => (
            <Box key={fact.id} sx={{ display: 'contents' }}>
              <Typography variant="caption" sx={{ fontFamily: 'var(--font-mono)' }}>{fact.label}</Typography>
              <Typography variant="caption" sx={{ color: toneColor[fact.tone], fontFamily: 'var(--font-mono)' }}>
                {fact.tone}
              </Typography>
              <Typography variant="caption" color="text.secondary" sx={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {fact.detail}
              </Typography>
            </Box>
          ))}
        </Box>
      </Box>

      {readelf && (
        <Box sx={{ mt: 1.25 }}>
          <Typography variant="caption" color="text.disabled" sx={{ letterSpacing: '0.06em' }}>
            READELF
          </Typography>
          <Box
            component="pre"
            data-testid="artifact-readelf"
            sx={{
              mt: 0.5,
              mb: 0,
              p: 1,
              maxHeight: 120,
              overflow: 'auto',
              border: '1px solid',
              borderColor: 'divider',
              borderRadius: 0.5,
              fontFamily: 'var(--font-mono)',
              fontSize: '0.68rem',
              lineHeight: 1.4,
              color: 'text.secondary',
            }}
          >
            {readelf}
          </Box>
        </Box>
      )}

      {passes.visible.length > 0 && (
        <Box sx={{ mt: 1.5 }}>
          <Stack direction="row" alignItems="center" justifyContent="space-between">
            <Typography variant="caption" color="text.disabled" sx={{ letterSpacing: '0.06em' }}>
              PASSES
            </Typography>
            {passes.skipped > 0 && (
              <Button
                size="small"
                variant="text"
                onClick={() => setShowSkipped((value) => !value)}
                sx={{ minHeight: 20, py: 0, px: 0.5, fontSize: '0.65rem' }}
              >
                {showSkipped ? 'hide skipped' : `${passes.skipped} skipped`}
              </Button>
            )}
          </Stack>
          <Stack direction="row" flexWrap="wrap" gap={0.75} sx={{ mt: 0.75 }} data-testid="artifact-passes">
            {passes.visible.map(([name, status]) => (
              <Typography
                key={name}
                variant="caption"
                sx={{
                  fontFamily: 'var(--font-mono)',
                  color:
                    status.status === 'completed'
                      ? 'success.main'
                      : status.status === 'failed'
                        ? 'error.main'
                        : status.status === 'partial'
                          ? 'warning.main'
                          : 'text.disabled',
                }}
              >
                {name}
                {status.duration_ms != null ? ` ${status.duration_ms}ms` : ''}
              </Typography>
            ))}
          </Stack>
        </Box>
      )}
    </Paper>
  );
};

export default ArtifactSheet;
