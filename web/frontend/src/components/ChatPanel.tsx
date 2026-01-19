import CheckIcon from '@mui/icons-material/Check';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import PersonIcon from '@mui/icons-material/Person';
import SendIcon from '@mui/icons-material/Send';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import TimelineIcon from '@mui/icons-material/Timeline';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
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
import { FC, FormEvent, memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { ChatAttachment, ChatMessageItem, ChatSessionSummary } from '../types';
import MarkdownRenderer from './MarkdownRenderer';

dayjs.extend(relativeTime);

interface ChatPanelProps {
  session: ChatSessionSummary | null;
  messages: ChatMessageItem[];
  onSend: (content: string, options: { callLLM: boolean }) => Promise<void>;
  sending?: boolean;
  error?: string | null;
  disassembly?: string;
  onNavigateToAddress?: (address: string) => void;
  // Trajectory context for LLM
  trajectoryContext?: string;
}

const CopyButton: FC<{ text: string }> = memo(function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [text]);

  return (
    <Tooltip title={copied ? 'Copied!' : 'Copy response'}>
      <IconButton size="small" onClick={handleCopy} sx={{ opacity: 0.7, '&:hover': { opacity: 1 } }}>
        {copied ? (
          <CheckIcon sx={{ fontSize: 14, color: 'success.main' }} />
        ) : (
          <ContentCopyIcon sx={{ fontSize: 14 }} />
        )}
      </IconButton>
    </Tooltip>
  );
});

interface MessageBubbleProps {
  message: ChatMessageItem;
  disassembly?: string;
  onNavigateToAddress?: (address: string) => void;
  isLatest?: boolean;
}

const MessageBubble: FC<MessageBubbleProps> = memo(function MessageBubble({ message, disassembly, onNavigateToAddress, isLatest }) {
  const theme = useTheme();
  const isUser = message.role === 'user';
  const isAssistant = message.role === 'assistant';
  const isPending = message.message_id.startsWith('pending-');

  const analysisAttachment = message.attachments.find(
    (a) => a.type === 'analysis_result'
  ) as ChatAttachment | undefined;

  // System message for analysis completion
  if (message.role === 'system' && analysisAttachment) {
    return (
      <Paper
        variant="outlined"
        sx={{
          p: 2,
          bgcolor: alpha(theme.palette.info.main, 0.08),
          borderColor: alpha(theme.palette.info.main, 0.2),
          borderLeft: `3px solid ${theme.palette.info.main}`,
          borderRadius: 2,
        }}
      >
        <Stack direction="row" spacing={1.5} alignItems="flex-start">
          <InfoOutlinedIcon sx={{ color: 'info.main', fontSize: 20, mt: 0.25 }} />
          <Box sx={{ flex: 1 }}>
            <Typography variant="body2" fontWeight={600} color="info.main">
              Analysis completed
            </Typography>
            <Typography
              variant="caption"
              color="text.secondary"
              sx={{
                fontFamily: '"JetBrains Mono", monospace',
                display: 'block',
                mt: 0.5,
              }}
            >
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

  // Other system messages
  if (message.role === 'system') {
    return (
      <Box sx={{ textAlign: 'center', py: 2 }}>
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
        animation: isLatest ? 'fadeIn 0.3s ease' : undefined,
        '@keyframes fadeIn': {
          from: { opacity: 0, transform: 'translateY(8px)' },
          to: { opacity: 1, transform: 'translateY(0)' },
        },
      }}
    >
      {/* Assistant avatar */}
      {!isUser && (
        <Box
          sx={{
            width: 40,
            height: 40,
            borderRadius: 2,
            bgcolor: alpha(theme.palette.primary.main, 0.12),
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
            border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
          }}
        >
          <SmartToyIcon sx={{ fontSize: 22, color: 'primary.main' }} />
        </Box>
      )}

      {/* Message bubble */}
      <Paper
        elevation={0}
        sx={{
          maxWidth: '75%',
          p: 2,
          bgcolor: isUser
            ? alpha(theme.palette.primary.main, 0.12)
            : alpha(theme.palette.background.paper, 0.9),
          border: 1,
          borderColor: isUser
            ? alpha(theme.palette.primary.main, 0.25)
            : 'divider',
          borderRadius: 2.5,
          borderTopRightRadius: isUser ? 6 : 20,
          borderTopLeftRadius: isUser ? 20 : 6,
        }}
      >
        <Stack spacing={1.5}>
          {/* Header */}
          <Stack direction="row" alignItems="center" spacing={1}>
            <Typography
              variant="caption"
              color={isUser ? 'primary.main' : 'text.secondary'}
              fontWeight={600}
              sx={{ letterSpacing: '0.02em' }}
            >
              {isUser ? 'You' : 'r2d2'}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {dayjs(message.created_at).format('h:mm A')}
            </Typography>
            {isPending && (
              <Chip
                size="small"
                label="sending"
                sx={{
                  height: 18,
                  fontSize: '0.65rem',
                  bgcolor: alpha(theme.palette.warning.main, 0.12),
                  color: theme.palette.warning.main,
                  fontWeight: 500,
                }}
              />
            )}
            {isAssistant && !isPending && (
              <Box sx={{ ml: 'auto' }}>
                <CopyButton text={message.content} />
              </Box>
            )}
          </Stack>

          {/* Content */}
          {isAssistant ? (
            <Box sx={{ '& > *:first-of-type': { mt: 0 }, '& > *:last-child': { mb: 0 } }}>
              <MarkdownRenderer
                content={message.content}
                disassembly={disassembly}
                onNavigateToAddress={onNavigateToAddress}
              />
            </Box>
          ) : (
            <Typography
              variant="body2"
              sx={{
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                lineHeight: 1.7,
                color: 'text.primary',
              }}
            >
              {message.content}
            </Typography>
          )}

          {/* Provider badge */}
          {message.attachments
            .filter((a) => a.type === 'llm_response_meta')
            .map((a, i) => (
              <Chip
                key={i}
                size="small"
                label={`via ${a.provider}`}
                variant="outlined"
                sx={{
                  alignSelf: 'flex-start',
                  fontSize: '0.7rem',
                  height: 20,
                  opacity: 0.7,
                }}
              />
            ))}
        </Stack>
      </Paper>

      {/* User avatar */}
      {isUser && (
        <Box
          sx={{
            width: 40,
            height: 40,
            borderRadius: 2,
            bgcolor: alpha(theme.palette.secondary.main, 0.12),
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
            border: `1px solid ${alpha(theme.palette.secondary.main, 0.2)}`,
          }}
        >
          <PersonIcon sx={{ fontSize: 22, color: 'secondary.main' }} />
        </Box>
      )}
    </Stack>
  );
});

// Trajectory context panel
const TrajectoryPanel: FC<{ context?: string }> = memo(function TrajectoryPanel({ context }) {
  const theme = useTheme();

  if (!context) return null;

  return (
    <Accordion
      elevation={0}
      sx={{
        bgcolor: alpha(theme.palette.info.main, 0.05),
        border: 1,
        borderColor: alpha(theme.palette.info.main, 0.15),
        borderRadius: '8px !important',
        '&:before': { display: 'none' },
        mb: 2,
      }}
    >
      <AccordionSummary
        expandIcon={<ExpandMoreIcon sx={{ fontSize: 18 }} />}
        sx={{ minHeight: 40, '& .MuiAccordionSummary-content': { my: 0.5 } }}
      >
        <Stack direction="row" spacing={1} alignItems="center">
          <TimelineIcon sx={{ fontSize: 16, color: 'info.main' }} />
          <Typography variant="caption" fontWeight={500} color="info.main">
            Analysis Context
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
            What I know about your session
          </Typography>
        </Stack>
      </AccordionSummary>
      <AccordionDetails sx={{ pt: 0 }}>
        <Typography
          variant="caption"
          component="pre"
          sx={{
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: '0.7rem',
            lineHeight: 1.5,
            whiteSpace: 'pre-wrap',
            color: 'text.secondary',
            m: 0,
          }}
        >
          {context}
        </Typography>
      </AccordionDetails>
    </Accordion>
  );
});

// Suggested questions
const SUGGESTED_QUESTIONS = [
  { label: 'Overview', question: 'What does this binary do?' },
  { label: 'Security', question: 'Are there any security concerns?' },
  { label: 'Main function', question: 'Explain the main function' },
  { label: 'Libraries', question: 'What libraries does it use?' },
];

export const ChatPanel: FC<ChatPanelProps> = memo(({
  session,
  messages,
  onSend,
  sending = false,
  error,
  disassembly,
  onNavigateToAddress,
  trajectoryContext,
}) => {
  const theme = useTheme();
  const [content, setContent] = useState('');
  const [callLLM, setCallLLM] = useState(true);
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const [shouldAutoScroll, setShouldAutoScroll] = useState(true);

  const scrollTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const handleScroll = useCallback(() => {
    if (scrollTimeoutRef.current) return;
    scrollTimeoutRef.current = setTimeout(() => {
      const container = scrollContainerRef.current;
      if (container) {
        const { scrollTop, scrollHeight, clientHeight } = container;
        const isNearBottom = scrollHeight - scrollTop - clientHeight < 100;
        setShouldAutoScroll(isNearBottom);
      }
      scrollTimeoutRef.current = null;
    }, 100);
  }, []);

  useLayoutEffect(() => {
    if (shouldAutoScroll && messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, shouldAutoScroll]);

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

  const handleSuggestedQuestion = (question: string) => {
    setContent(question);
  };

  // No session state
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
          p: 4,
        }}
      >
        <SmartToyIcon sx={{ fontSize: 64, mb: 2, opacity: 0.2 }} />
        <Typography variant="h6" fontWeight={500} sx={{ mb: 1 }}>
          No session selected
        </Typography>
        <Typography variant="body2" sx={{ textAlign: 'center', maxWidth: 320, lineHeight: 1.7 }}>
          Run an analysis or select a session from the sidebar to start chatting about your binary.
        </Typography>
      </Box>
    );
  }

  // Filter visible messages
  const visibleMessages = useMemo(() =>
    messages.filter(msg => {
      if (msg.role === 'system') {
        return msg.attachments.some(a => a.type === 'analysis_result');
      }
      return true;
    }),
    [messages]
  );

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Trajectory context panel */}
      {trajectoryContext && <TrajectoryPanel context={trajectoryContext} />}

      {/* Messages area */}
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
        <Stack spacing={2.5} sx={{ py: 1 }}>
          {/* Empty state with suggestions */}
          {visibleMessages.length === 0 && (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Analysis complete. What would you like to know?
              </Typography>
              <Stack
                direction="row"
                spacing={1}
                justifyContent="center"
                flexWrap="wrap"
                gap={1}
              >
                {SUGGESTED_QUESTIONS.map(({ label, question }) => (
                  <Chip
                    key={label}
                    label={label}
                    size="small"
                    variant="outlined"
                    onClick={() => handleSuggestedQuestion(question)}
                    sx={{
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      '&:hover': {
                        bgcolor: alpha(theme.palette.primary.main, 0.08),
                        borderColor: 'primary.main',
                      },
                    }}
                  />
                ))}
              </Stack>
            </Box>
          )}

          {/* Messages */}
          {visibleMessages.map((msg, index) => (
            <MessageBubble
              key={msg.message_id}
              message={msg}
              disassembly={disassembly}
              onNavigateToAddress={onNavigateToAddress}
              isLatest={index === visibleMessages.length - 1}
            />
          ))}
          <div ref={messagesEndRef} />
        </Stack>
      </Box>

      {/* Error alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {/* Input area */}
      <Paper
        component="form"
        onSubmit={handleSubmit}
        elevation={0}
        sx={{
          p: 2,
          bgcolor: alpha(theme.palette.background.paper, 0.9),
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
          sx={{
            mb: 1.5,
            '& .MuiOutlinedInput-root': {
              borderRadius: 1.5,
            },
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              if (content.trim()) handleSubmit(e);
            }
          }}
        />
        <Stack direction="row" alignItems="center" spacing={2}>
          <Tooltip title="When enabled, Claude will analyze your question and provide an intelligent response">
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
          </Tooltip>
          <Box sx={{ flex: 1 }} />
          <Button
            type="submit"
            variant="contained"
            color="primary"
            size="small"
            disabled={sending || !content.trim()}
            endIcon={sending ? <CircularProgress size={14} color="inherit" /> : <SendIcon />}
            sx={{ minWidth: 100, fontWeight: 500 }}
          >
            {sending ? 'Sending' : 'Send'}
          </Button>
        </Stack>
      </Paper>
    </Box>
  );
});

export default ChatPanel;
