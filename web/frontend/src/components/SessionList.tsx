import DeleteIcon from '@mui/icons-material/Delete';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import {
  Box,
  IconButton,
  List,
  ListItemButton,
  ListItemText,
  Menu,
  MenuItem,
  Typography,
  useTheme,
} from '@mui/material';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { FC, MouseEvent, useState } from 'react';
import type { ChatSessionSummary } from '../types';

dayjs.extend(relativeTime);

interface SessionListProps {
  sessions: ChatSessionSummary[];
  activeSessionId: string | null;
  onSelect: (session: ChatSessionSummary) => void;
  onDelete?: (sessionId: string) => void;
}

export const SessionList: FC<SessionListProps> = ({
  sessions,
  activeSessionId,
  onSelect,
  onDelete,
}) => {
  const theme = useTheme();
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);
  const [menuSessionId, setMenuSessionId] = useState<string | null>(null);

  const handleMenuOpen = (event: MouseEvent<HTMLButtonElement>, sessionId: string) => {
    event.stopPropagation();
    setMenuAnchor(event.currentTarget);
    setMenuSessionId(sessionId);
  };

  const handleMenuClose = () => {
    setMenuAnchor(null);
    setMenuSessionId(null);
  };

  const handleDelete = () => {
    if (menuSessionId && onDelete) {
      onDelete(menuSessionId);
    }
    handleMenuClose();
  };

  if (sessions.length === 0) {
    return (
      <Box sx={{ p: 2, textAlign: 'center' }}>
        <Typography variant="caption" color="text.secondary">
          No sessions yet
        </Typography>
      </Box>
    );
  }

  return (
    <>
      <List sx={{ py: 0.5, px: 0.5 }} dense>
        {sessions.map((session) => {
          const isActive = session.session_id === activeSessionId;
          const fileName = session.title ?? session.binary_path.split('/').pop() ?? 'Unknown';

          return (
            <ListItemButton
              key={session.session_id}
              selected={isActive}
              onClick={() => onSelect(session)}
              sx={{
                mb: 0.25,
                py: 0.75,
                px: 1,
                borderRadius: 0.5,
                '&.Mui-selected': {
                  bgcolor: 'action.selected',
                },
              }}
            >
              <ListItemText
                primary={
                  <Typography
                    variant="caption"
                    fontWeight={isActive ? 600 : 400}
                    sx={{
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                      display: 'block',
                    }}
                  >
                    {fileName}
                  </Typography>
                }
                secondary={
                  <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.65rem' }}>
                    {dayjs(session.updated_at).fromNow()}
                  </Typography>
                }
              />
              <IconButton
                size="small"
                onClick={(e) => handleMenuOpen(e, session.session_id)}
                sx={{
                  opacity: 0.5,
                  '&:hover': { opacity: 1 },
                  ml: 0.5,
                }}
              >
                <MoreVertIcon sx={{ fontSize: 14 }} />
              </IconButton>
            </ListItemButton>
          );
        })}
      </List>

      <Menu
        anchorEl={menuAnchor}
        open={Boolean(menuAnchor)}
        onClose={handleMenuClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        <MenuItem onClick={handleDelete} sx={{ fontSize: '0.8125rem', color: 'error.main' }}>
          <DeleteIcon sx={{ fontSize: 16, mr: 1 }} />
          Delete
        </MenuItem>
      </Menu>
    </>
  );
};

export default SessionList;
