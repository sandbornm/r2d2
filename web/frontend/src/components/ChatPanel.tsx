import CheckIcon from '@mui/icons-material/Check';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import PersonIcon from '@mui/icons-material/Person';
import SendIcon from '@mui/icons-material/Send';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import {
  Alert,
  alpha,
  Box,
  Button,
  Chip,
  CircularProgress,
  IconButton,
  Paper,
  Stack,
  Switch,
  TextField,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { FC, FormEvent, useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { ChatAttachment, ChatMessageItem, ChatSessionSummary } from '../types';

dayjs.extend(relativeTime);

interface ChatPanelProps {
  session: ChatSessionSummary | null;
  messages: ChatMessageItem[];
  onSend: (content: string, options: { callLLM: boolean }) => Promise<void>;
  sending?: boolean;
  error?: string | null;
}

const CopyButton: FC<{ text: string }> = ({ text }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Tooltip title={copied ? 'Copied!' : 'Copy'}>
      <IconButton size="small" onClick={handleCopy}>
        {copied ? (
          <CheckIcon sx={{ fontSize: 14, color: 'success.main' }} />
        ) : (
          <ContentCopyIcon sx={{ fontSize: 14 }} />
        )}
      </IconButton>
    </Tooltip>
  );
};

const MessageBubble: FC<{ message: ChatMessageItem }> = ({ message }) => {
  const theme = useTheme();
  const isUser = message.role === 'user';
  const isSystem = message.role === 'system';
  const isAssistant = message.role === 'assistant';
  const isPending = message.message_id.startsWith('pending-');

  // Extract analysis info from attachments
  const analysisAttachment = message.attachments.find(
    (a) => a.type === 'analysis_result'
  ) as ChatAttachment | undefined;

  if (isSystem && analysisAttachment) {
    return (
      <Paper
        variant="outlined"
        sx={{
          p: 2,
          bgcolor: alpha(theme.palette.info.main, 0.1),
          borderColor: alpha(theme.palette.info.main, 0.3),
          borderLeft: `3px solid ${theme.palette.info.main}`,
        }}
      >
        <Stack direction="row" spacing={1.5} alignItems="flex-start">
          <InfoOutlinedIcon sx={{ color: 'info.main', fontSize: 20, mt: 0.25 }} />
          <Box sx={{ flex: 1 }}>
            <Typography variant="body2" fontWeight={600} color="info.main">
              Analysis completed
            </Typography>
            <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
              {analysisAttachment.binary as string}
            </Typography>
          </Box>
          <Typography variant="caption" color="text.secondary">
            {dayjs(message.created_at).format('HH:mm')}
          </Typography>
        </Stack>
      </Paper>
    );
  }

  if (isSystem) {
    return (
      <Box sx={{ textAlign: 'center', py: 1.5 }}>
        <Typography variant="caption" color="text.secondary" sx={{ fontStyle: 'italic' }}>
          {message.content}
        </Typography>
      </Box>
    );
  }

  return (
    <Stack
      direction="row"
      spacing={1.5}
      sx={{
        justifyContent: isUser ? 'flex-end' : 'flex-start',
      }}
    >
      {!isUser && (
        <Box
          sx={{
            width: 36,
            height: 36,
            borderRadius: 2,
            bgcolor: alpha(theme.palette.primary.main, 0.15),
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
          }}
        >
          <SmartToyIcon sx={{ fontSize: 20, color: 'primary.main' }} />
        </Box>
      )}

      <Paper
        elevation={0}
        sx={{
          maxWidth: '80%',
          p: 2,
          bgcolor: isUser 
            ? alpha(theme.palette.primary.main, 0.15) 
            : alpha(theme.palette.background.paper, 0.8),
          border: 1,
          borderColor: isUser 
            ? alpha(theme.palette.primary.main, 0.3) 
            : 'divider',
          borderRadius: 2,
          borderTopRightRadius: isUser ? 4 : 16,
          borderTopLeftRadius: isUser ? 16 : 4,
        }}
      >
        <Stack spacing={1}>
          <Stack direction="row" alignItems="center" spacing={1}>
            <Typography variant="caption" color="text.secondary" fontWeight={600}>
              {isUser ? 'You' : 'r2d2'}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {dayjs(message.created_at).format('HH:mm')}
            </Typography>
            {isPending && (
              <Chip
                size="small"
                label="sending"
                sx={{
                  height: 18,
                  fontSize: '0.65rem',
                  bgcolor: alpha(theme.palette.warning.main, 0.15),
                  color: theme.palette.warning.main,
                }}
              />
            )}
            {isAssistant && !isPending && (
              <Box sx={{ ml: 'auto' }}>
                <CopyButton text={message.content} />
              </Box>
            )}
          </Stack>
          <Typography
            variant="body2"
            sx={{
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              lineHeight: 1.7,
              '& code': {
                bgcolor: alpha(theme.palette.primary.main, 0.1),
                px: 0.75,
                py: 0.25,
                borderRadius: 0.5,
                fontFamily: 'monospace',
                fontSize: '0.85em',
              },
              '& pre': {
                bgcolor: alpha('#000', 0.3),
                p: 1.5,
                borderRadius: 1,
                overflow: 'auto',
                fontFamily: 'monospace',
                fontSize: '0.8rem',
                my: 1,
              },
            }}
          >
            {message.content}
          </Typography>
          {message.attachments
            .filter((a) => a.type === 'llm_response_meta')
            .map((a, i) => (
              <Chip
                key={i}
                size="small"
                label={`via ${a.provider}`}
                variant="outlined"
                sx={{ alignSelf: 'flex-start', fontSize: '0.7rem', height: 20 }}
              />
            ))}
        </Stack>
      </Paper>

      {isUser && (
        <Box
          sx={{
            width: 36,
            height: 36,
            borderRadius: 2,
            bgcolor: alpha(theme.palette.secondary.main, 0.15),
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
          }}
        >
          <PersonIcon sx={{ fontSize: 20, color: 'secondary.main' }} />
        </Box>
      )}
    </Stack>
  );
};

export const ChatPanel: FC<ChatPanelProps> = ({
  session,
  messages,
  onSend,
  sending = false,
  error,
}) => {
  const theme = useTheme();
  const [content, setContent] = useState('');
  const [callLLM, setCallLLM] = useState(true);
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const [shouldAutoScroll, setShouldAutoScroll] = useState(true);

  // Check if user is near bottom
  const handleScroll = () => {
    const container = scrollContainerRef.current;
    if (!container) return;
    
    const { scrollTop, scrollHeight, clientHeight } = container;
    const isNearBottom = scrollHeight - scrollTop - clientHeight < 100;
    setShouldAutoScroll(isNearBottom);
  };

  // Auto-scroll to bottom when messages change
  useLayoutEffect(() => {
    if (shouldAutoScroll && messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, shouldAutoScroll]);

  // Scroll to bottom on initial load
  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'auto' });
    }
  }, [session?.session_id]);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!content.trim() || !session) return;
    setShouldAutoScroll(true);
    await onSend(content, { callLLM });
    setContent('');
  };

  if (!session) {
    return (
      <Box
        sx={{
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'text.secondary',
        }}
      >
        <SmartToyIcon sx={{ fontSize: 56, mb: 2, opacity: 0.3 }} />
        <Typography variant="h6" fontWeight={600}>
          No session selected
        </Typography>
        <Typography variant="body2" sx={{ mt: 1, textAlign: 'center', maxWidth: 300 }}>
          Run an analysis or select a session from the sidebar to start chatting
        </Typography>
      </Box>
    );
  }

  // Filter out system messages that aren't analysis completions
  const visibleMessages = messages.filter(msg => {
    if (msg.role === 'system') {
      return msg.attachments.some(a => a.type === 'analysis_result');
    }
    return true;
  });

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Messages */}
      <Box
        ref={scrollContainerRef}
        onScroll={handleScroll}
        sx={{
          flex: 1,
          overflow: 'auto',
          mb: 2,
          pr: 1,
        }}
      >
        <Stack spacing={2} sx={{ py: 1 }}>
          {visibleMessages.length === 0 && (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography variant="body2" color="text.secondary">
                Analysis complete! Ask me anything about the binary.
              </Typography>
              <Stack spacing={1} sx={{ mt: 2 }}>
                <Typography variant="caption" color="text.secondary">
                  Try asking:
                </Typography>
                {[
                  "What does this binary do?",
                  "Are there any security concerns?",
                  "Explain the main function",
                  "What libraries does it use?",
                ].map((q, i) => (
                  <Chip
                    key={i}
                    label={q}
                    size="small"
                    variant="outlined"
                    onClick={() => setContent(q)}
                    sx={{ cursor: 'pointer' }}
                  />
                ))}
              </Stack>
            </Box>
          )}
          {visibleMessages.map((msg) => (
            <MessageBubble key={msg.message_id} message={msg} />
          ))}
          <div ref={messagesEndRef} />
        </Stack>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {/* Input */}
      <Paper
        component="form"
        onSubmit={handleSubmit}
        elevation={0}
        sx={{
          p: 2,
          bgcolor: alpha(theme.palette.background.paper, 0.8),
          border: 1,
          borderColor: 'divider',
          borderRadius: 2,
        }}
      >
        <TextField
          fullWidth
          multiline
          maxRows={4}
          size="small"
          placeholder="Ask about the binary..."
          value={content}
          onChange={(e) => setContent(e.target.value)}
          disabled={sending}
          sx={{ mb: 1.5 }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              if (content.trim()) handleSubmit(e);
            }
          }}
        />
        <Stack direction="row" alignItems="center" spacing={2}>
          <Stack direction="row" alignItems="center" spacing={1}>
            <Switch
              size="small"
              checked={callLLM}
              onChange={(e) => setCallLLM(e.target.checked)}
              color="primary"
            />
            <Typography variant="caption" color="text.secondary">
              AI response
            </Typography>
          </Stack>
          <Box sx={{ flex: 1 }} />
          <Button
            type="submit"
            variant="contained"
            color="primary"
            size="small"
            disabled={sending || !content.trim()}
            endIcon={sending ? <CircularProgress size={14} color="inherit" /> : <SendIcon />}
            sx={{ minWidth: 100 }}
          >
            {sending ? 'Sending' : 'Send'}
          </Button>
        </Stack>
      </Paper>
    </Box>
  );
};

export default ChatPanel;
