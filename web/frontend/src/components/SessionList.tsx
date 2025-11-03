import HistoryIcon from '@mui/icons-material/History';
import RefreshIcon from '@mui/icons-material/Refresh';
import {
  Box,
  IconButton,
  List,
  ListItemButton,
  ListItemText,
  Paper,
  Stack,
  Tooltip,
  Typography,
} from '@mui/material';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { FC } from 'react';
import type { ChatSessionSummary } from '../types';

dayjs.extend(relativeTime);

interface SessionListProps {
  sessions: ChatSessionSummary[];
  activeSessionId: string | null;
  onSelect: (session: ChatSessionSummary) => void;
  onRefresh: () => void;
}

export const SessionList: FC<SessionListProps> = ({ sessions, activeSessionId, onSelect, onRefresh }) => {
  return (
    <Paper variant="outlined" sx={{ p: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1.5 }}>
        <Stack direction="row" spacing={1} alignItems="center">
          <HistoryIcon color="primary" />
          <Typography variant="h6">Sessions</Typography>
        </Stack>
        <Tooltip title="Refresh sessions">
          <IconButton size="small" onClick={onRefresh} aria-label="refresh sessions">
            <RefreshIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Stack>
      <Box sx={{ flex: 1, overflowY: 'auto' }}>
        <List sx={{ py: 0 }}>
          {sessions.map((session) => (
            <ListItemButton
              key={session.session_id}
              selected={session.session_id === activeSessionId}
              onClick={() => onSelect(session)}
              sx={{ borderRadius: 1, mb: 0.5 }}
            >
              <ListItemText
                primary={<Typography variant="subtitle2">{session.title ?? session.binary_path}</Typography>}
                secondary={
                  <Typography variant="caption" color="text.secondary">
                    Updated {dayjs(session.updated_at).fromNow()} • {session.message_count} messages
                  </Typography>
                }
              />
            </ListItemButton>
          ))}
          {sessions.length === 0 && (
            <Typography variant="body2" color="text.secondary" sx={{ p: 2 }}>
              No sessions yet. Kick off an analysis to create one automatically.
            </Typography>
          )}
        </List>
      </Box>
    </Paper>
  );
};

export default SessionList;
