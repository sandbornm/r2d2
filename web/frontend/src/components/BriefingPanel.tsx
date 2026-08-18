import { Box, Button, Chip, Paper, Stack, Typography } from '@mui/material';
import { FC, useMemo } from 'react';
import type { AnalysisBriefingPayload, BriefingRegion } from '../types';
import { rankRegions, resolveGoal } from '../utils/rank';

interface BriefingPanelProps {
  briefing: AnalysisBriefingPayload;
  onAsk?: (prompt: string) => void;
  compact?: boolean;
  userGoal?: string;
  recordTags?: string[];
}

const copyText = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // clipboard can be denied in some test / file:// contexts
  }
};

const isWrapper = (briefing: AnalysisBriefingPayload) => {
  const format = String(briefing.subject?.format || briefing.summary || '').toLowerCase();
  return format.includes('firmware') || format.includes('container') || (briefing.subject?.firmware_kind != null);
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
        <Button size="small" variant="outlined" onClick={() => copyText(region.next_actions[0] || region.ask)}>
          Copy next
        </Button>
        <Button size="small" variant="text" onClick={() => copyText(region.ask)}>
          Copy ask
        </Button>
        {onAsk && (
          <Button size="small" variant="text" onClick={() => onAsk(region.ask)}>
            Ask Qwen
          </Button>
        )}
        {region.tags.slice(0, 3).map((tag) => (
          <Chip key={tag} size="small" label={tag} variant="outlined" />
        ))}
      </Stack>
    </Paper>
  );
};

const BriefingPanel: FC<BriefingPanelProps> = ({
  briefing,
  onAsk,
  compact = false,
  userGoal,
  recordTags = [],
}) => {
  const wrapper = isWrapper(briefing);
  const ranked = useMemo(() => {
    const resolved = resolveGoal(
      userGoal,
      briefing.inferred_goal,
      briefing.ranking_tags || [],
      recordTags,
      briefing.subject,
    );
    return {
      ...resolved,
      regions: rankRegions(briefing.regions, resolved.lenses, resolved.goal),
    };
  }, [briefing, userGoal, recordTags]);
  const primary = briefing.next_steps[0] || ranked.regions[0]?.next_actions[0] || '';
  return (
    <Paper variant="outlined" sx={{ p: compact ? 1.5 : 2, bgcolor: 'transparent' }} data-testid="briefing-panel">
      <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: compact ? 0.75 : 1.25 }}>
        <Typography variant="overline" sx={{ flex: 1, letterSpacing: '0.08em' }}>
          {compact ? 'Next' : 'Steer'}
        </Typography>
        <Chip
          size="small"
          data-testid="briefing-goal-source"
          label={ranked.source === 'user' ? 'thesis' : 'inferred'}
          variant="outlined"
          sx={{ height: 20, fontSize: '0.65rem' }}
        />
        {primary && (
          <Button size="small" variant="outlined" onClick={() => copyText(primary)}>
            Copy next
          </Button>
        )}
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 0.75, maxWidth: 720 }} data-testid="briefing-goal">
        {ranked.goal}
      </Typography>
      <Typography variant="body2" sx={{ mb: compact ? 0 : 1.25, maxWidth: 720 }}>
        {briefing.summary}
      </Typography>
      {wrapper && !compact && ranked.lenses.includes('unpack') && (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
          Vendor upgrade blob. Brief extracted
          {' '}<Box component="span" sx={{ fontFamily: 'var(--font-mono)' }}>httpd</Box>
          {' '}or tdpServer — not this file.
        </Typography>
      )}
      {!compact && briefing.next_steps.length > 0 && (
        <Box component="ul" sx={{ m: 0, mb: 2, pl: 2.5 }}>
          {briefing.next_steps.slice(0, 3).map((step) => (
            <Typography key={step} component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
              {step}
            </Typography>
          ))}
        </Box>
      )}
      {!compact && (
        <Stack spacing={1.25}>
          {ranked.regions.slice(0, 5).map((region, index) => (
            <RegionCard key={region.id || index} region={region} index={index + 1} onAsk={onAsk} />
          ))}
        </Stack>
      )}
    </Paper>
  );
};

export default BriefingPanel;
