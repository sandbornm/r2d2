import { Box, Button, Chip, Paper, Stack, Typography } from '@mui/material';
import { FC } from 'react';
import type { AnalysisBriefingPayload, BriefingRegion } from '../types';

interface BriefingPanelProps {
  briefing: AnalysisBriefingPayload;
  onAsk?: (prompt: string) => void;
}

const copyText = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // clipboard can be denied in some test / file:// contexts
  }
};

const subjectClass = (briefing: AnalysisBriefingPayload) =>
  String(briefing.subject?.subject_class || '');

const isWrapper = (briefing: AnalysisBriefingPayload) => {
  const klass = subjectClass(briefing);
  return klass === 'firmware_container' || klass === 'uimage';
};

const RegionCard: FC<{ region: BriefingRegion; index: number; onAsk?: (prompt: string) => void }> = ({
  region,
  index,
  onAsk,
}) => {
  const loc = [region.snippet?.function, region.snippet?.address].filter(Boolean).join(' ');
  return (
    <Paper variant="outlined" sx={{ p: 1.5, bgcolor: 'transparent' }}>
      <Stack direction="row" spacing={1.25} alignItems="baseline" sx={{ mb: 0.5 }}>
        <Typography variant="caption" color="text.secondary" sx={{ width: 16 }}>
          {index}
        </Typography>
        <Typography variant="body2" fontWeight={600} sx={{ flex: 1, minWidth: 0 }} noWrap>
          {region.title}
        </Typography>
        {loc && (
          <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'var(--font-mono)' }}>
            {loc}
          </Typography>
        )}
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1, pl: 3.25 }}>
        {region.why}
      </Typography>
      {region.snippet?.text && (
        <Box
          component="pre"
          sx={{
            m: 0,
            mb: 1,
            ml: 3.25,
            p: 1.25,
            maxHeight: 140,
            overflow: 'auto',
            fontSize: 12,
            fontFamily: 'var(--font-mono)',
            bgcolor: 'rgba(255,255,255,0.03)',
            borderRadius: 1,
            whiteSpace: 'pre-wrap',
          }}
        >
          {region.snippet.text}
        </Box>
      )}
      <Stack direction="row" spacing={1} sx={{ pl: 3.25 }} alignItems="center">
        {onAsk && (
          <Button size="small" variant="contained" onClick={() => onAsk(region.ask)}>
            Ask
          </Button>
        )}
        <Button size="small" variant="text" onClick={() => copyText(region.ask)}>
          Copy ask
        </Button>
        {region.tags.slice(0, 3).map((tag) => (
          <Chip key={tag} size="small" label={tag} variant="outlined" />
        ))}
      </Stack>
    </Paper>
  );
};

const BriefingPanel: FC<BriefingPanelProps> = ({ briefing, onAsk }) => {
  const wrapper = isWrapper(briefing);
  const klass = subjectClass(briefing);
  return (
    <Paper variant="outlined" sx={{ p: 2, bgcolor: 'transparent' }}>
      <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1.25 }}>
        <Typography variant="overline" sx={{ flex: 1, letterSpacing: '0.08em' }}>
          What to ask next
        </Typography>
        {klass && <Chip size="small" label={klass.replace(/_/g, ' ')} variant="outlined" />}
        {onAsk && (
          <Button size="small" variant="contained" onClick={() => onAsk(briefing.overall_ask)}>
            Ask about this image
          </Button>
        )}
      </Stack>
      <Typography variant="body1" sx={{ mb: 1.5, maxWidth: 720 }}>
        {briefing.summary}
      </Typography>
      {wrapper && (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
          This is still a vendor upgrade blob. The useful program is usually
          {' '}<Box component="span" sx={{ fontFamily: 'var(--font-mono)' }}>httpd</Box>
          {' '}(web admin) or tdpServer after unpack — not this file, and not a process on this Pi.
        </Typography>
      )}
      {klass === 'baremetal_elf' && (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
          This is a program ELF (Cortex-M / Thumb), not a squashfs. Rank named
          protocol symbols and <Box component="span" sx={{ fontFamily: 'var(--font-mono)' }}>feed</Box>
          {' '}functions — do not unpack it.
        </Typography>
      )}
      {briefing.next_steps.length > 0 && (
        <Box component="ul" sx={{ m: 0, mb: 2, pl: 2.5 }}>
          {briefing.next_steps.slice(0, 4).map((step) => (
            <Typography key={step} component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
              {step}
            </Typography>
          ))}
        </Box>
      )}
      <Stack spacing={1.25}>
        {briefing.regions.slice(0, 6).map((region, index) => (
          <RegionCard key={region.id || index} region={region} index={index + 1} onAsk={onAsk} />
        ))}
      </Stack>
    </Paper>
  );
};

export default BriefingPanel;
