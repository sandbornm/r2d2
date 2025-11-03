import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import AutorenewIcon from '@mui/icons-material/Autorenew';
import { Chip, List, ListItem, ListItemIcon, ListItemText, Paper, Stack, Typography } from '@mui/material';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { FC } from 'react';
import type { ProgressEventEntry } from '../types';

dayjs.extend(relativeTime);

interface ProgressLogProps {
entries: ProgressEventEntry[];
}

const LABELS: Record<string, string> = {
  analysis_started: 'Analysis started',
  job_started: 'Job started',
  adapter_started: 'Adapter started',
  adapter_completed: 'Adapter completed',
  adapter_failed: 'Adapter failed',
  adapter_skipped: 'Adapter skipped',
  stage_started: 'Stage started',
  stage_completed: 'Stage completed',
  analysis_result: 'Analysis result received',
  job_completed: 'Job completed',
  job_failed: 'Job failed',
};

const ICONS: Record<string, JSX.Element> = {
  job_started: <PlayArrowIcon color="primary" />,
  adapter_started: <AutorenewIcon color="info" />,
  stage_started: <AutorenewIcon color="info" />,
  adapter_completed: <CheckCircleOutlineIcon color="success" />,
  stage_completed: <CheckCircleOutlineIcon color="success" />,
  analysis_result: <CheckCircleOutlineIcon color="success" />,
  job_completed: <CheckCircleOutlineIcon color="success" />,
  adapter_failed: <ErrorOutlineIcon color="error" />,
  job_failed: <ErrorOutlineIcon color="error" />,
  adapter_skipped: <ErrorOutlineIcon color="warning" />,
  analysis_started: <PlayArrowIcon color="primary" />,
};

export const ProgressLog: FC<ProgressLogProps> = ({ entries }) => {
  if (!entries.length) {
    return (
      <Paper variant="outlined" sx={{ p: 4, textAlign: 'center', color: 'text.secondary' }}>
        <Typography variant="h6" gutterBottom>
          Waiting for analysis events
        </Typography>
        <Typography variant="body2">Submit a binary to stream adapter progress in real time.</Typography>
      </Paper>
    );
  }

  return (
    <Paper variant="outlined" sx={{ maxHeight: 360, overflowY: 'auto' }}>
      <List disablePadding>
        {entries.map((entry) => {
          const icon = ICONS[entry.event] ?? <AutorenewIcon color="info" />;
          const { event, data } = entry;
          return (
            <ListItem key={entry.id} divider alignItems="flex-start" sx={{ py: 1.5, px: 2 }}>
              <ListItemIcon sx={{ minWidth: 40 }}>{icon}</ListItemIcon>
              <ListItemText
                primary={
                  <Stack direction="row" spacing={1} alignItems="center">
                    <Typography variant="subtitle1">{LABELS[event] ?? event}</Typography>
                    {data.stage && <Chip label={`Stage: ${data.stage}`} size="small" color="primary" />}
                    {data.adapter && <Chip label={`Adapter: ${data.adapter}`} size="small" color="secondary" />}
                  </Stack>
                }
                secondary={
                  <Stack spacing={0.5} sx={{ mt: 0.5 }}>
                    <Typography variant="caption" color="text.secondary">
                      {dayjs(entry.timestamp).fromNow()} • {new Date(entry.timestamp).toLocaleTimeString()}
                    </Typography>
                    {data.error && (
                      <Typography variant="body2" color="error.main">
                        Error: {data.error}
                      </Typography>
                    )}
                    {data.reason && (
                      <Typography variant="body2" color="warning.main">
                        Skipped: {data.reason}
                      </Typography>
                    )}
                  </Stack>
                }
              />
            </ListItem>
          );
        })}
      </List>
    </Paper>
  );
};

export default ProgressLog;
