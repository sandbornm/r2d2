import AssessmentIcon from '@mui/icons-material/Assessment';
import ChatIcon from '@mui/icons-material/Chat';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import HistoryIcon from '@mui/icons-material/History';
import InsertDriveFileIcon from '@mui/icons-material/InsertDriveFile';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import RefreshIcon from '@mui/icons-material/Refresh';
import SettingsIcon from '@mui/icons-material/Settings';
import TerminalIcon from '@mui/icons-material/Terminal';
import {
  Alert,
  alpha,
  Box,
  Button,
  Chip,
  CircularProgress,
  IconButton,
  Stack,
  Tab,
  Tabs,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import {
  DragEvent,
  FormEvent,
  SyntheticEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import ChatPanel from './components/ChatPanel';
import ProgressLog from './components/ProgressLog';
import ResultViewer from './components/ResultViewer';
import SessionList from './components/SessionList';
import SettingsDrawer, { AnalysisSettings } from './components/SettingsDrawer';
import { useThemeMode } from './main';
import type {
  AnalysisResultPayload,
  ApiAnalysisResponse,
  ChatDetailResponse,
  ChatMessageItem,
  ChatPostResponse,
  ChatSessionSummary,
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
type TabValue = 'results' | 'chat' | 'logs';

type AnalysisResponseEvent = AnalysisResultPayload & { session_id?: string };
type SSEHandlers = Partial<Record<ProgressEventName, (payload: ProgressEventPayload) => void>>;

const DEFAULT_SETTINGS: AnalysisSettings = {
  quickScanOnly: false,
  enableAngr: true,
  autoAskLLM: false,
};

const loadSettings = (): AnalysisSettings => {
  try {
    const stored = localStorage.getItem('r2d2-settings');
    if (stored) return { ...DEFAULT_SETTINGS, ...JSON.parse(stored) };
  } catch {
    // ignore
  }
  return DEFAULT_SETTINGS;
};

const App = () => {
  const theme = useTheme();
  const { mode, toggleTheme } = useThemeMode();
  const isDark = mode === 'dark';

  const [binaryPath, setBinaryPath] = useState('');
  const [fileName, setFileName] = useState<string | null>(null);
  const [status, setStatus] = useState<JobStatus>('idle');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [events, setEvents] = useState<ProgressEventEntry[]>([]);
  const [result, setResult] = useState<AnalysisResultPayload | null>(null);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [sessions, setSessions] = useState<ChatSessionSummary[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessageItem[]>([]);
  const [sendingMessage, setSendingMessage] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabValue>('results');
  const [isDragging, setIsDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settings, setSettings] = useState<AnalysisSettings>(loadSettings);

  const sourceRef = useRef<EventSource | null>(null);
  const activeSessionIdRef = useRef<string | null>(null);
  const lastSyncedSessionIdRef = useRef<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const activeSession = useMemo(
    () => sessions.find((session) => session.session_id === activeSessionId) ?? null,
    [sessions, activeSessionId],
  );

  useEffect(() => {
    activeSessionIdRef.current = activeSessionId;
  }, [activeSessionId]);

  // Save settings when changed
  useEffect(() => {
    localStorage.setItem('r2d2-settings', JSON.stringify(settings));
  }, [settings]);

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

      const selectedId = activeSessionIdRef.current;
      if (selectedId) {
        const stillExists = data.some((session) => session.session_id === selectedId);
        if (!stillExists) {
          lastSyncedSessionIdRef.current = null;
          setActiveSessionId(data.length ? data[0].session_id : null);
        }
      } else if (data.length) {
        lastSyncedSessionIdRef.current = null;
        setActiveSessionId(data[0].session_id);
      } else {
        lastSyncedSessionIdRef.current = null;
        setActiveSessionId(null);
      }
    } catch (error) {
      console.error('Failed to fetch sessions', error);
    }
  }, []);

  const loadSessionMessages = useCallback(async (sessionId: string) => {
    try {
      const response = await fetch(`/api/chats/${sessionId}?limit=250`);
      if (!response.ok) throw new Error('Failed to load chat history');
      const data: ChatDetailResponse = await response.json();
      setMessages(data.messages);
      setSessions((prev) => {
        const exists = prev.some((session) => session.session_id === data.session.session_id);
        if (!exists) return prev;
        return prev.map((session) =>
          session.session_id === data.session.session_id ? data.session : session,
        );
      });
    } catch (error) {
      console.error(error);
      setMessages([]);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    refreshSessions();
    return () => {
      if (sourceRef.current) sourceRef.current.close();
    };
  }, [fetchHealth, refreshSessions]);

  useEffect(() => {
    if (activeSessionId) {
      loadSessionMessages(activeSessionId).catch(console.error);
    } else {
      setMessages([]);
    }
  }, [activeSessionId, loadSessionMessages]);

  useEffect(() => {
    if (activeSession && lastSyncedSessionIdRef.current !== activeSession.session_id) {
      setBinaryPath(activeSession.binary_path);
      setFileName(activeSession.title ?? activeSession.binary_path.split('/').pop() ?? null);
      lastSyncedSessionIdRef.current = activeSession.session_id;
    }
  }, [activeSession]);

  const closeSource = () => {
    if (sourceRef.current) {
      sourceRef.current.close();
      sourceRef.current = null;
    }
  };

  const attachEventHandlers = useCallback(
    (source: EventSource, handlers: SSEHandlers) => {
      EVENT_NAMES.forEach((name) => {
        source.addEventListener(name, (event) => {
          const message = event as MessageEvent<string>;
          let payload: ProgressEventPayload = {};
          if (message.data) {
            try {
              payload = JSON.parse(message.data) as ProgressEventPayload;
            } catch {
              console.error('Failed to parse SSE payload');
            }
          }
          recordEvent(name, payload);
          handlers[name]?.(payload);
        });
      });

      source.onerror = () => {
        setStatus('error');
        setStatusMessage('Connection lost. Try again.');
        closeSource();
      };
    },
    [recordEvent]
  );

  // File upload handler
  const handleFileUpload = async (file: File) => {
    setUploading(true);
    setStatusMessage('Uploading file...');
    setStatus('running');

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorBody = await response.json();
        throw new Error(errorBody.error ?? 'Upload failed');
      }

      const data = await response.json();
      setBinaryPath(data.path);
      setFileName(data.filename);
      setStatus('idle');
      setStatusMessage(null);
      lastSyncedSessionIdRef.current = null;
    } catch (error) {
      console.error(error);
      setStatus('error');
      setStatusMessage(error instanceof Error ? error.message : 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  // Drag and drop handlers
  const handleDragOver = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDragEnter = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = async (e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      await handleFileUpload(files[0]);
    }
  };

  const handleFileInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      await handleFileUpload(files[0]);
    }
  };

  const handleAnalyze = async (event: FormEvent) => {
    event.preventDefault();
    if (!binaryPath.trim()) {
      setStatus('error');
      setStatusMessage('Upload a binary file first');
      return;
    }

    closeSource();
    setStatus('running');
    setStatusMessage('Starting analysis...');
    setEvents([]);
    setResult(null);
    setActiveTab('logs');

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          binary: binaryPath,
          quick_only: settings.quickScanOnly,
          enable_angr: settings.enableAngr,
        }),
      });

      if (!response.ok) {
        const errorBody = await response.json();
        throw new Error(errorBody.error ?? 'Analysis request failed');
      }

      const data: ApiAnalysisResponse = await response.json();
      setStatusMessage('Analyzing...');

      if (data.session_id) {
        lastSyncedSessionIdRef.current = null;
        setActiveSessionId(data.session_id);
        activeSessionIdRef.current = data.session_id;
        refreshSessions();
        loadSessionMessages(data.session_id).catch(console.error);
      }

      const source = new EventSource(`/api/jobs/${data.job_id}/stream`);
      sourceRef.current = source;

      const handlers: SSEHandlers = {
        job_started: (payload) => {
          setStatus('running');
          setStatusMessage(`Analyzing ${payload.binary ?? fileName ?? 'binary'}`);
        },
        stage_started: (payload) => {
          if (payload.stage) setStatusMessage(`Running ${payload.stage} stage...`);
        },
        job_failed: (payload) => {
          setStatus('error');
          setStatusMessage(payload.error ?? 'Analysis failed');
          closeSource();
        },
        job_completed: (payload) => {
          setStatus('done');
          setStatusMessage('Analysis complete');
          setActiveTab('results');
          if (payload.session_id) {
            lastSyncedSessionIdRef.current = null;
            setActiveSessionId(payload.session_id);
            activeSessionIdRef.current = payload.session_id;
            refreshSessions();
            loadSessionMessages(payload.session_id).catch(console.error);
          }
          closeSource();
          
          // Auto-ask LLM if enabled
          if (settings.autoAskLLM && payload.session_id) {
            setTimeout(() => {
              handleAutoAskLLM(payload.session_id!);
            }, 500);
          }
        },
        analysis_result: (payload) => {
          const analysis = payload as unknown as AnalysisResponseEvent;
          setResult(analysis);
          if (analysis.session_id) {
            lastSyncedSessionIdRef.current = null;
            setActiveSessionId(analysis.session_id);
            activeSessionIdRef.current = analysis.session_id;
            refreshSessions();
            loadSessionMessages(analysis.session_id).catch(console.error);
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

  const handleAutoAskLLM = async (sessionId: string) => {
    try {
      await fetch(`/api/chats/${sessionId}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: 'Provide a brief summary of this binary: what it does, notable functions, and any security concerns.',
          call_llm: true,
        }),
      });
      setActiveSessionId(sessionId);
      activeSessionIdRef.current = sessionId;
      lastSyncedSessionIdRef.current = null;
      loadSessionMessages(sessionId);
      setActiveTab('chat');
    } catch (error) {
      console.error('Auto-ask LLM failed:', error);
    }
  };

  const handleSessionSelect = (session: ChatSessionSummary) => {
    setActiveSessionId(session.session_id);
    activeSessionIdRef.current = session.session_id;
    setBinaryPath(session.binary_path);
    setFileName(session.title ?? session.binary_path.split('/').pop() ?? null);
    lastSyncedSessionIdRef.current = session.session_id;
  };

  const handleSendMessage = async (content: string, options: { callLLM: boolean }) => {
    if (!activeSessionId) return;
    setSendingMessage(true);
    setChatError(null);
    const optimisticId = `pending-${Date.now()}`;
    const timestamp = new Date().toISOString();
    const optimisticMessage: ChatMessageItem = {
      message_id: optimisticId,
      session_id: activeSessionId,
      role: 'user',
      content,
      attachments: [],
      created_at: timestamp,
    };
    setMessages((prev) => [...prev, optimisticMessage]);

    try {
      const response = await fetch(`/api/chats/${activeSessionId}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, call_llm: options.callLLM }),
      });
      if (!response.ok) {
        setMessages((prev) => prev.filter((msg) => msg.message_id !== optimisticId));
        const errorBody = await response.json();
        throw new Error(errorBody.error ?? 'Failed to send message');
      }
      const data: ChatPostResponse = await response.json();
      setActiveSessionId(data.session.session_id);
      activeSessionIdRef.current = data.session.session_id;
      setMessages(data.messages);
      setSessions((prev) => {
        const next = prev.filter((s) => s.session_id !== data.session.session_id);
        return [data.session, ...next];
      });
      if (data.error) setChatError(data.error);
    } catch (error) {
      console.error(error);
      setChatError(error instanceof Error ? error.message : 'Failed to send message');
      setMessages((prev) => prev.filter((msg) => msg.message_id !== optimisticId));
    } finally {
      setSendingMessage(false);
    }
  };

  const handleTabChange = (_: SyntheticEvent, value: TabValue) => {
    setActiveTab(value);
  };

  const clearFile = () => {
    setBinaryPath('');
    setFileName(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <Box
      sx={{
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        bgcolor: 'background.default',
        color: 'text.primary',
      }}
    >
      {/* Header */}
      <Box
        component="header"
        sx={{
          px: 3,
          py: 2,
          borderBottom: 1,
          borderColor: 'divider',
          display: 'flex',
          alignItems: 'center',
          gap: 2,
          flexShrink: 0,
          bgcolor: alpha(theme.palette.background.paper, 0.9),
          backdropFilter: 'blur(12px)',
          borderBottomLeftRadius: 16,
          borderBottomRightRadius: 16,
          boxShadow: `0 6px 18px -12px ${alpha(theme.palette.primary.main, 0.6)}`,
        }}
      >
        <Stack direction="row" alignItems="center" spacing={1.5}>
          <TerminalIcon sx={{ color: 'secondary.main', fontSize: 28 }} />
          <Typography variant="h5" fontWeight={700} sx={{ letterSpacing: '-0.02em' }}>
            r2d2
          </Typography>
        </Stack>

        <Box sx={{ flex: 1 }} />

        {health && (
          <Chip
            size="small"
            label={health.model}
            sx={{
              bgcolor: health.status === 'ok' 
                ? alpha(theme.palette.secondary.main, 0.15) 
                : alpha(theme.palette.error.main, 0.15),
              color: health.status === 'ok' ? 'secondary.main' : 'error.main',
              fontWeight: 500,
            }}
          />
        )}

        <Tooltip title="Settings">
          <IconButton onClick={() => setSettingsOpen(true)} size="small">
            <SettingsIcon />
          </IconButton>
        </Tooltip>
      </Box>

      {/* Settings Drawer */}
      <SettingsDrawer
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        isDarkMode={isDark}
        onToggleTheme={toggleTheme}
        settings={settings}
        onSettingsChange={setSettings}
      />

      {/* Main content */}
      <Box sx={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* Sidebar */}
        <Box
          component="aside"
          sx={{
            width: 280,
            borderRight: 1,
            borderColor: 'divider',
            display: 'flex',
            flexDirection: 'column',
            flexShrink: 0,
            bgcolor: alpha(theme.palette.background.paper, 0.75),
            backdropFilter: 'blur(10px)',
          }}
        >
          <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
            <Stack direction="row" alignItems="center" justifyContent="space-between">
              <Stack direction="row" alignItems="center" spacing={1}>
                <HistoryIcon sx={{ fontSize: 18, color: 'text.secondary' }} />
                <Typography variant="body2" fontWeight={600} color="text.secondary">
                  Sessions
                </Typography>
              </Stack>
              <Tooltip title="Refresh">
                <IconButton size="small" onClick={refreshSessions}>
                  <RefreshIcon sx={{ fontSize: 16 }} />
                </IconButton>
              </Tooltip>
            </Stack>
          </Box>
          <Box sx={{ flex: 1, overflow: 'auto' }}>
            <SessionList
              sessions={sessions}
              activeSessionId={activeSessionId}
              onSelect={handleSessionSelect}
            />
          </Box>
        </Box>

        {/* Main panel */}
        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {/* Upload / Analyze area */}
          <Box
            component="form"
            onSubmit={handleAnalyze}
            onDragOver={handleDragOver}
            onDragEnter={handleDragEnter}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            sx={{
              p: 3,
              borderBottom: 1,
              borderColor: alpha(theme.palette.primary.main, 0.15),
              bgcolor: isDragging
                ? alpha(theme.palette.primary.main, 0.12)
                : alpha(theme.palette.background.paper, 0.92),
              transition: 'background-color 0.2s, border-color 0.2s',
            }}
          >
            <input
              ref={fileInputRef}
              type="file"
              onChange={handleFileInputChange}
              style={{ display: 'none' }}
              accept="*/*"
            />

            {!fileName ? (
              // Drop zone
              <Box
                onClick={() => fileInputRef.current?.click()}
                sx={{
                  border: 2,
                  borderStyle: 'dashed',
                  borderColor: isDragging ? 'secondary.main' : 'divider',
                  borderRadius: 2,
                  p: 4,
                  textAlign: 'center',
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                  '&:hover': {
                    borderColor: 'primary.main',
                    bgcolor: alpha(theme.palette.primary.main, 0.04),
                  },
                }}
              >
                <CloudUploadIcon
                  sx={{
                    fontSize: 48,
                    color: isDragging ? 'secondary.main' : 'text.secondary',
                    mb: 1,
                  }}
                />
                <Typography variant="body1" fontWeight={500}>
                  {isDragging ? 'Drop binary here' : 'Drag & drop a binary file'}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                  or click to browse
                </Typography>
              </Box>
            ) : (
              // File selected
              <Stack spacing={2}>
                <Stack direction="row" spacing={2} alignItems="center">
                  <Box
                    sx={{
                      width: 48,
                      height: 48,
                      borderRadius: 1.5,
                      bgcolor: alpha(theme.palette.primary.main, 0.1),
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <InsertDriveFileIcon sx={{ color: 'primary.main' }} />
                  </Box>
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Typography
                      variant="body1"
                      fontWeight={600}
                      sx={{
                        fontFamily: 'monospace',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {fileName}
                    </Typography>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        sx={{ fontFamily: 'monospace' }}
                      >
                        {settings.quickScanOnly ? 'Quick scan' : 'Full analysis'}
                        {!settings.quickScanOnly && settings.enableAngr && ' + angr'}
                      </Typography>
                    </Stack>
                  </Box>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={clearFile}
                    disabled={status === 'running'}
                  >
                    Change
                  </Button>
                  <Button
                    type="submit"
                    variant="contained"
                    color="secondary"
                    disabled={status === 'running' || uploading}
                    startIcon={
                      status === 'running' ? (
                        <CircularProgress size={16} color="inherit" />
                      ) : (
                        <PlayArrowIcon />
                      )
                    }
                    sx={{ minWidth: 120 }}
                  >
                    {status === 'running' ? 'Running' : 'Analyze'}
                  </Button>
                </Stack>

                {statusMessage && (
                  <Alert
                    severity={status === 'error' ? 'error' : status === 'done' ? 'success' : 'info'}
                    icon={false}
                  >
                    {statusMessage}
                  </Alert>
                )}
              </Stack>
            )}
          </Box>

          {/* Tabs */}
          <Box sx={{ borderBottom: 1, borderColor: 'divider', px: 2 }}>
            <Tabs value={activeTab} onChange={handleTabChange}>
              <Tab
                value="results"
                label="Results"
                icon={<AssessmentIcon sx={{ fontSize: 18 }} />}
                iconPosition="start"
              />
              <Tab
                value="chat"
                label="Chat"
                icon={<ChatIcon sx={{ fontSize: 18 }} />}
                iconPosition="start"
              />
              <Tab
                value="logs"
                label={
                  <Stack direction="row" alignItems="center" spacing={1}>
                    <span>Logs</span>
                    {events.length > 0 && (
                      <Chip
                        size="small"
                        label={events.length}
                        sx={{
                          height: 18,
                          fontSize: '0.7rem',
                          '& .MuiChip-label': { px: 0.75 },
                        }}
                      />
                    )}
                  </Stack>
                }
                icon={<TerminalIcon sx={{ fontSize: 18 }} />}
                iconPosition="start"
              />
            </Tabs>
          </Box>

          {/* Tab content */}
          <Box sx={{ flex: 1, overflow: 'auto', p: 3 }}>
            {activeTab === 'results' && <ResultViewer result={result} />}
            {activeTab === 'chat' && (
              <ChatPanel
                session={activeSession}
                messages={messages}
                onSend={handleSendMessage}
                sending={sendingMessage}
                error={chatError}
              />
            )}
            {activeTab === 'logs' && <ProgressLog entries={events} />}
          </Box>
        </Box>
      </Box>
    </Box>
  );
};

export default App;
