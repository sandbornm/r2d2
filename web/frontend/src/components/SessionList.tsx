import { alpha, Box, List, ListItemButton, ListItemText, Typography, useTheme } from '@mui/material';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { FC } from 'react';
import type { ChatSessionSummary } from '../types';

dayjs.extend(relativeTime);

interface SessionListProps {
  sessions: ChatSessionSummary[];
  activeSessionId: string | null;
  onSelect: (session: ChatSessionSummary) => void;
}

export const SessionList: FC<SessionListProps> = ({ sessions, activeSessionId, onSelect }) => {
  const theme = useTheme();
  if (sessions.length === 0) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Typography variant="body2" color="text.secondary">
          No sessions yet
        </Typography>
        <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
          Run an analysis to create one
        </Typography>
      </Box>
    );
  }

  return (
    <List sx={{ py: 1, px: 1 }}>
      {sessions.map((session) => {
        const isActive = session.session_id === activeSessionId;
        const fileName = session.title ?? session.binary_path.split('/').pop() ?? 'Unknown';

        return (
          <ListItemButton
            key={session.session_id}
            selected={isActive}
            onClick={() => onSelect(session)}
            sx={{
              mb: 0.5,
              py: 1.2,
              px: 1.5,
              borderRadius: 1.5,
              bgcolor: isActive ? alpha(theme.palette.primary.main, 0.14) : 'transparent',
              border: isActive ? `1px solid ${alpha(theme.palette.primary.main, 0.4)}` : `1px solid ${alpha(theme.palette.primary.main, 0.1)}`,
              transition: 'transform 0.15s ease, background-color 0.2s ease, border-color 0.2s ease',
              transform: isActive ? 'translateX(4px)' : 'translateX(0)',
              '&:hover': {
                bgcolor: alpha(theme.palette.primary.main, 0.18),
                borderColor: alpha(theme.palette.primary.main, 0.5),
              },
            }}
          >
            <ListItemText
              primary={
                <Typography
                  variant="body2"
                  fontWeight={isActive ? 600 : 500}
                  sx={{
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    fontFamily: 'monospace',
                    fontSize: '0.8125rem',
                  }}
                >
                  {fileName}
                </Typography>
              }
              secondary={
                <Typography
                  variant="caption"
                  color={isActive ? theme.palette.primary.light : 'text.secondary'}
                  sx={{ fontWeight: 500 }}
                >
                  {dayjs(session.updated_at).fromNow()}
                </Typography>
              }
            />
          </ListItemButton>
        );
      })}
    </List>
  );
};

export default SessionList;
