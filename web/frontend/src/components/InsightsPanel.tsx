import { Alert, Box, Button, Chip, Paper, Stack, Typography } from '@mui/material';
import { FC, useEffect, useState } from 'react';
import type { InsightsPayload } from '../types';

interface InsightsPanelProps {
  recordId?: string | null;
}

const InsightsPanel: FC<InsightsPanelProps> = ({ recordId }) => {
  const [data, setData] = useState<InsightsPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const query = recordId ? `?record_id=${encodeURIComponent(recordId)}` : '';
    fetch(`/api/insights${query}`)
      .then((response) => (response.ok ? response.json() : Promise.reject(response)))
      .then((payload) => setData(payload as InsightsPayload))
      .catch(() => setError('Could not load sibling insights'));
  }, [recordId]);

  const saveNote = async () => {
    setSaving(true);
    try {
      const response = await fetch('/api/insights/note', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ record_id: recordId }),
      });
      if (!response.ok) {
        setError('Need two sibling records before a lab note is worth saving.');
        return;
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <Paper variant="outlined" sx={{ p: 1.5 }}>
      <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
        <Typography variant="overline" sx={{ flex: 1, letterSpacing: '0.08em' }}>
          Seen on sibling images
        </Typography>
        {data?.ready && (
          <Button size="small" disabled={saving} onClick={saveNote}>
            Save lab note
          </Button>
        )}
      </Stack>
      {error && <Alert severity="info" sx={{ mb: 1 }}>{error}</Alert>}
      {!data && !error && (
        <Typography variant="caption" color="text.secondary">Looking for sibling records…</Typography>
      )}
      {data && !data.ready && (
        <Typography variant="body2" color="text.secondary">
          {data.reason}
        </Typography>
      )}
      {data?.ready && (
        <Stack spacing={1}>
          <Typography variant="caption" color="text.secondary">
            {data.sibling_count} siblings · not a skill yet
          </Typography>
          {data.patterns.slice(0, 6).map((pattern) => (
            <Box key={pattern.id}>
              <Stack direction="row" spacing={0.5} alignItems="center" sx={{ mb: 0.25 }}>
                <Chip size="small" label={pattern.kind} variant="outlined" />
                <Typography variant="body2" fontWeight={600}>{pattern.title}</Typography>
              </Stack>
              <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
                {pattern.why}
              </Typography>
              <Typography variant="caption" sx={{ fontFamily: 'ui-monospace, monospace' }}>
                {pattern.next_action}
              </Typography>
            </Box>
          ))}
        </Stack>
      )}
    </Paper>
  );
};

export default InsightsPanel;
