import ArticleIcon from '@mui/icons-material/Article';
import BoltIcon from '@mui/icons-material/Bolt';
import PersonIcon from '@mui/icons-material/Person';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Button,
  Chip,
  Divider,
  FormControlLabel,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Paper,
  Stack,
  Switch,
  TextField,
  Typography,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { FC, FormEvent, useState } from 'react';
import type { ChatAttachment, ChatMessageItem, ChatSessionSummary } from '../types';

interface ChatPanelProps {
  session: ChatSessionSummary | null;
  messages: ChatMessageItem[];
  onSend: (content: string, options: { callLLM: boolean }) => Promise<void>;
  sending?: boolean;
  error?: string | null;
}

dayjs.extend(relativeTime);

const roleIcon = (role: ChatMessageItem['role']) => {
  switch (role) {
    case 'assistant':
      return <SmartToyIcon color="secondary" />;
    case 'system':
      return <WarningAmberIcon color="warning" />;
    default:
      return <PersonIcon color="primary" />;
  }
};

const AttachmentView: FC<{ attachment: ChatAttachment }> = ({ attachment }) => {
  if (attachment.type === 'analysis_result') {
    const issues = Array.isArray(attachment.issues) ? attachment.issues : [];
    const notes = Array.isArray(attachment.notes) ? attachment.notes : [];
    return (
      <Accordion disableGutters sx={{ bgcolor: 'background.default' }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Stack direction="row" spacing={1} alignItems="center">
            <ArticleIcon color="primary" fontSize="small" />
            <Typography variant="body2">Analysis snapshot</Typography>
          </Stack>
        </AccordionSummary>
        <AccordionDetails>
          <Stack spacing={1}>
            <Typography variant="body2" color="text.secondary">
              Binary: {attachment.binary as string}
            </Typography>
            {issues.length > 0 && (
              <Stack direction="row" spacing={1} flexWrap="wrap">
                {issues.map((issue) => (
                  <Chip key={issue} label={issue} color="warning" size="small" />
                ))}
              </Stack>
            )}
            {notes.length > 0 && (
              <Stack direction="row" spacing={1} flexWrap="wrap">
                {notes.map((note) => (
                  <Chip key={note} label={note} color="info" size="small" />
                ))}
              </Stack>
            )}
            <Typography component="pre" variant="body2" sx={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
              {JSON.stringify({ quick: attachment.quick_scan, deep: attachment.deep_scan }, null, 2)}
            </Typography>
          </Stack>
        </AccordionDetails>
      </Accordion>
    );
  }

  if (attachment.type === 'llm_response_meta') {
    return (
      <Chip
        size="small"
        color="secondary"
        variant="outlined"
        icon={<BoltIcon />}
        label={`LLM provider: ${(attachment.provider as string) ?? 'unknown'}`}
      />
    );
  }

  return (
    <Chip size="small" variant="outlined" label={`${attachment.type}`} />
  );
};

export const ChatPanel: FC<ChatPanelProps> = ({ session, messages, onSend, sending = false, error }) => {
  const [content, setContent] = useState('');
  const [callLLM, setCallLLM] = useState(true);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!content.trim() || !session) {
      return;
    }
    await onSend(content, { callLLM });
    setContent('');
  };

  if (!session) {
    return (
      <Paper variant="outlined" sx={{ p: 4, textAlign: 'center', color: 'text.secondary' }}>
        <Typography variant="h6" gutterBottom>
          No chat selected
        </Typography>
        <Typography variant="body2">Start an analysis or select an existing session to view chat history.</Typography>
      </Paper>
    );
  }

  return (
    <Paper variant="outlined" sx={{ p: 2.5, display: 'flex', flexDirection: 'column', height: '100%' }}>
      <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5 }}>
        <SmartToyIcon color="secondary" />
        <Typography variant="h6">Analysis Companion</Typography>
        <Chip label={`Messages: ${messages.length}`} size="small" />
      </Stack>
      <Typography variant="caption" color="text.secondary" sx={{ mb: 1 }}>
        Session updated {dayjs(session.updated_at).fromNow()}
      </Typography>

      <Box sx={{ flex: 1, overflowY: 'auto', mb: 2 }}>
        <List sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          {messages.map((message) => (
            <Paper key={message.message_id} variant="outlined" sx={{ p: 1.5, bgcolor: 'background.default' }}>
              <ListItem alignItems="flex-start" disableGutters>
                <ListItemAvatar sx={{ minWidth: 48 }}>{roleIcon(message.role)}</ListItemAvatar>
                <ListItemText
                  primary={
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Typography variant="subtitle2" color="text.secondary">
                        {message.role.toUpperCase()}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {dayjs(message.created_at).format('YYYY-MM-DD HH:mm:ss')}
                      </Typography>
                    </Stack>
                  }
                  secondary={
                    <Stack spacing={1} sx={{ mt: 1 }}>
                      <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                        {message.content}
                      </Typography>
                      {message.attachments.map((attachment, idx) => (
                        <AttachmentView key={`${message.message_id}-att-${idx}`} attachment={attachment} />
                      ))}
                    </Stack>
                  }
                />
              </ListItem>
            </Paper>
          ))}
          {messages.length === 0 && (
            <ListItem>
              <ListItemText
                primary={<Typography color="text.secondary">No messages yet</Typography>}
                secondary="The companion will capture analysis milestones and LLM answers here."
              />
            </ListItem>
          )}
        </List>
      </Box>

      <Divider sx={{ my: 1.5 }} />

      {error && <Alert severity="error" sx={{ mb: 1 }}>{error}</Alert>}

      <Box component="form" onSubmit={handleSubmit} sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
        <TextField
          multiline
          minRows={3}
          value={content}
          onChange={(event) => setContent(event.target.value)}
          placeholder="Ask about the binary, request deeper dives, or add notes..."
          fullWidth
        />
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems={{ xs: 'stretch', sm: 'center' }}>
          <FormControlLabel
            control={
              <Switch
                checked={callLLM}
                onChange={(event) => setCallLLM(event.target.checked)}
                color="secondary"
              />
            }
            label="Ask LLM for a response"
          />
          <Box sx={{ flexGrow: 1 }} />
          <Button
            type="submit"
            variant="contained"
            color="secondary"
            disabled={sending || !content.trim()}
          >
            Send
          </Button>
        </Stack>
      </Box>
    </Paper>
  );
};

export default ChatPanel;
