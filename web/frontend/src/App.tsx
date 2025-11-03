import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import TroubleshootIcon from '@mui/icons-material/Troubleshoot';
import {
  Alert,
  Box,
  Button,
  Chip,
  Container,
  Grid,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { FormEvent, useCallback, useEffect, useRef, useState } from 'react';
import ChatPanel from './components/ChatPanel';
import ComplexitySlider from './components/ComplexitySlider';
import ProgressLog from './components/ProgressLog';
import ResultViewer from './components/ResultViewer';
import SessionList from './components/SessionList';
import type {
  AnalysisResultPayload,
  ApiAnalysisResponse,
  ChatDetailResponse,
  ChatMessageItem,
  ChatPostResponse,
  ChatSessionSummary,
  ComplexityLevel,
  HealthStatus,
  ProgressEventEntry,
  ProgressEventName,
  ProgressEventPayload,
} from './types';

const EVENT_NAMES: ProgressEventName[] = [
  'analysis_started',
  'job_started',
  'stage_started',
  'stage_completed',
  'adapter_started',
  'adapter_completed',
  'adapter_failed',
  'adapter_skipped',
  'analysis_result',
  'job_completed',
  'job_failed',
];

type JobStatus = 'idle' | 'running' | 'done' | 'error';

type AnalysisResponseEvent = AnalysisResultPayload & { session_id?: string };

type SSEHandlers = Partial<Record<ProgressEventName, (payload: ProgressEventPayload) => void>>;

const App = () => {
  const [binaryPath, setBinaryPath] = useState('');
  const [status, setStatus] = useState<JobStatus>('idle');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [events, setEvents] = useState<ProgressEventEntry[]>([]);
  const [result, setResult] = useState<AnalysisResultPayload | null>(null);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [sessions, setSessions] = useState<ChatSessionSummary[]>([]);
  const [activeSession, setActiveSession] = useState<ChatSessionSummary | null>(null);
  const [messages, setMessages] = useState<ChatMessageItem[]>([]);
  const [complexity, setComplexity] = useState<ComplexityLevel>('beginner');
  const [sendingMessage, setSendingMessage] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);

  const sourceRef = useRef<EventSource | null>(null);

  const recordEvent = useCallback((event: ProgressEventName, data: ProgressEventPayload) => {
    setEvents((prev) => [
      ...prev,
      {
        id: `${event}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        event,
        data,
        timestamp: Date.now(),
      },
    ]);
  }, []);

  const fetchHealth = useCallback(async () => {
    try {
      const response = await fetch('/api/health');
      const data: HealthStatus = await response.json();
      setHealth(data);
    } catch (error) {
      console.error('Failed to fetch health', error);
      setHealth({ status: 'error', model: 'unknown', ghidra_ready: false });
    }
  }, []);

  const refreshSessions = useCallback(async () => {
    try {
      const response = await fetch('/api/chats?limit=50');
      const data: ChatSessionSummary[] = await response.json();
      setSessions(data);
      if (activeSession) {
        const updated = data.find((session) => session.session_id === activeSession.session_id);
        if (updated) {
          setActiveSession(updated);
        }
      }
    } catch (error) {
      console.error('Failed to fetch sessions', error);
    }
  }, [activeSession]);

  const loadSessionMessages = useCallback(async (sessionId: string) => {
    try {
      const response = await fetch(`/api/chats/${sessionId}?limit=250`);
      if (!response.ok) {
        throw new Error('Failed to load chat history');
      }
      const data: ChatDetailResponse = await response.json();
      setActiveSession(data.session);
      setMessages(data.messages);
    } catch (error) {
      console.error(error);
      setMessages([]);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    refreshSessions();
    return () => {
      if (sourceRef.current) {
        sourceRef.current.close();
      }
    };
  }, [fetchHealth, refreshSessions]);

  useEffect(() => {
    if (activeSession) {
      loadSessionMessages(activeSession.session_id).catch((error) => console.error(error));
    } else {
      setMessages([]);
    }
  }, [activeSession, loadSessionMessages]);

  const closeSource = () => {
    if (sourceRef.current) {
      sourceRef.current.close();
      sourceRef.current = null;
    }
  };

  const attachEventHandlers = useCallback((source: EventSource, handlers: SSEHandlers) => {
    EVENT_NAMES.forEach((name) => {
      source.addEventListener(name, (event) => {
        const message = event as MessageEvent<string>;
        let payload: ProgressEventPayload = {};
        if (message.data) {
          try {
            payload = JSON.parse(message.data) as ProgressEventPayload;
          } catch (error) {
            console.error('Failed to parse SSE payload', error);
          }
        }
        recordEvent(name, payload);
        handlers[name]?.(payload);
      });
    });

    source.onerror = () => {
      setStatus('error');
      setStatusMessage('Progress stream interrupted.');
      closeSource();
    };
  }, [recordEvent]);

  const handleAnalyze = async (event: FormEvent) => {
    event.preventDefault();
    if (!binaryPath.trim()) {
      setStatus('error');
      setStatusMessage('Provide a path to the binary you want to analyze.');
      return;
    }

    closeSource();
    setStatus('running');
    setStatusMessage('Dispatching analysis job...');
    setEvents([]);
    setResult(null);
    setJobId(null);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ binary: binaryPath }),
      });

      if (!response.ok) {
        const errorBody = await response.json();
        throw new Error(errorBody.error ?? 'Analysis request failed');
      }

      const data: ApiAnalysisResponse = await response.json();
      setJobId(data.job_id);
      setStatusMessage('Job queued. Listening for progress...');

      if (data.session_id) {
        refreshSessions();
        loadSessionMessages(data.session_id).catch((error) => console.error(error));
      }

      const source = new EventSource(`/api/jobs/${data.job_id}/stream`);
      sourceRef.current = source;

      const handlers: SSEHandlers = {
        job_started: (payload) => {
          setStatus('running');
          setStatusMessage(`Analysis started for ${payload.binary ?? binaryPath}`);
        },
        stage_started: (payload) => {
          if (payload.stage) {
            setStatusMessage(`Running ${payload.stage} stage...`);
          }
        },
        job_failed: (payload) => {
          setStatus('error');
          setStatusMessage(payload.error ?? 'Analysis failed');
          closeSource();
        },
        job_completed: (payload) => {
          setStatus('done');
          setStatusMessage('Analysis completed successfully.');
          if (payload.session_id) {
            refreshSessions();
            loadSessionMessages(payload.session_id).catch((error) => console.error(error));
          }
          closeSource();
        },
        analysis_result: (payload) => {
          const analysis = payload as unknown as AnalysisResponseEvent;
          setResult(analysis);
          if (analysis.session_id) {
            refreshSessions();
            loadSessionMessages(analysis.session_id).catch((error) => console.error(error));
          }
        },
      };

      attachEventHandlers(source, handlers);
    } catch (error) {
      console.error(error);
      setStatus('error');
      setStatusMessage(error instanceof Error ? error.message : 'Failed to start analysis');
    }
  };

  const handleSessionSelect = (session: ChatSessionSummary) => {
    setActiveSession(session);
  };

  const handleSendMessage = async (content: string, options: { callLLM: boolean }) => {
    if (!activeSession) {
      return;
    }
    setSendingMessage(true);
    setChatError(null);
    try {
      const response = await fetch(`/api/chats/${activeSession.session_id}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, call_llm: options.callLLM }),
      });
      if (!response.ok) {
        const errorBody = await response.json();
        throw new Error(errorBody.error ?? 'Failed to send message');
      }
      const data: ChatPostResponse = await response.json();
      setActiveSession(data.session);
      setMessages(data.messages);
      setSessions((prev) => {
        const next = prev.filter((session) => session.session_id !== data.session.session_id);
        return [data.session, ...next];
      });
      if (data.error) {
        setChatError(data.error);
      }
    } catch (error) {
      console.error(error);
      setChatError(error instanceof Error ? error.message : 'Failed to send message');
    } finally {
      setSendingMessage(false);
    }
  };

  return (
    <Box sx={{ minHeight: '100vh', py: 4 }}>
      <Container maxWidth="xl">
        <Stack spacing={3}>
          <Stack spacing={1}>
            <Typography variant="h3" fontWeight={700} gutterBottom>
              r2d2 analyzer
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Stream binary insights, pivot into deeper stages, and keep a conversational trail for every ELF you touch.
            </Typography>
            {health && (
              <Stack direction="row" spacing={1} flexWrap="wrap">
                <Chip label={`LLM: ${health.model}`} color={health.status === 'ok' ? 'success' : 'error'} />
                <Chip
                  label={`Ghidra ready: ${health.ghidra_ready ? 'yes' : 'no'}`}
                  color={health.ghidra_ready ? 'success' : 'warning'}
                  variant="outlined"
                />
              </Stack>
            )}
          </Stack>

          <Grid container spacing={2}>
            <Grid item xs={12} md={3}>
              <SessionList
                sessions={sessions}
                activeSessionId={activeSession?.session_id ?? null}
                onSelect={handleSessionSelect}
                onRefresh={refreshSessions}
              />
            </Grid>

            <Grid item xs={12} md={9}>
              <Stack spacing={2}>
                <Paper variant="outlined" sx={{ p: 3 }}>
                  <Stack component="form" spacing={2} onSubmit={handleAnalyze}>
                    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems={{ xs: 'stretch', sm: 'center' }}>
                      <TextField
                        fullWidth
                        label="Binary path"
                        placeholder="/path/to/binary"
                        value={binaryPath}
                        onChange={(event) => setBinaryPath(event.target.value)}
                        autoComplete="off"
                      />
                      <Button
                        type="submit"
                        variant="contained"
                        startIcon={<PlayArrowIcon />}
                        color="secondary"
                        disabled={status === 'running'}
                      >
                        Analyze
                      </Button>
                    </Stack>
                    {statusMessage && (
                      <Alert severity={status === 'error' ? 'error' : status === 'done' ? 'success' : 'info'}>
                        {statusMessage}
                        {jobId && <Chip label={`Job: ${jobId}`} size="small" sx={{ ml: 1 }} />}
                      </Alert>
                    )}
                  </Stack>
                </Paper>

                <Paper variant="outlined" sx={{ p: 2 }}>
                  <ComplexitySlider value={complexity} onChange={setComplexity} />
                </Paper>

                <Grid container spacing={2}>
                  <Grid item xs={12} md={5}>
                    <ProgressLog entries={events} />
                  </Grid>
                  <Grid item xs={12} md={7}>
                    <ResultViewer result={result} complexity={complexity} />
                  </Grid>
                </Grid>

                <ChatPanel
                  session={activeSession}
                  messages={messages}
                  onSend={handleSendMessage}
                  sending={sendingMessage}
                  error={chatError}
                />
              </Stack>
            </Grid>
          </Grid>
        </Stack>
      </Container>

      <Stack spacing={1} alignItems="center" sx={{ mt: 6, color: 'text.secondary' }}>
        <Typography variant="caption">Powered by r2d2 • multi-arch ELF triage with radare2, capstone, and angr.</Typography>
        <Stack direction="row" spacing={1}>
          <Chip icon={<TroubleshootIcon />} label={`Complexity: ${complexity}`} size="small" variant="outlined" />
        </Stack>
      </Stack>
    </Box>
  );
};

export default App;
