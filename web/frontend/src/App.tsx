import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import SettingsIcon from '@mui/icons-material/Settings';
import DarkModeIcon from '@mui/icons-material/DarkMode';
import LightModeIcon from '@mui/icons-material/LightMode';
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  FormControl,
  IconButton,
  MenuItem,
  Select,
  SelectChangeEvent,
  Stack,
  Tab,
  Tabs,
  TextField,
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
import SettingsDrawer, { AI_MODELS, AnalysisSettings, ModelId } from './components/SettingsDrawer';
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
  selectedModel: 'claude-sonnet-4-5',
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
  const [userGoal, setUserGoal] = useState('');
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
      setHealth({ status: 'error', model: 'unknown', ghidra_ready: false, available_models: [] });
    }
  }, []);

  const handleModelChange = useCallback(async (event: SelectChangeEvent<string>) => {
    const newModel = event.target.value;
    try {
      const response = await fetch('/api/models', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: newModel }),
      });
      if (response.ok) {
        setHealth((prev) => prev ? { ...prev, model: newModel } : null);
      }
    } catch (error) {
      console.error('Failed to change model', error);
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
        setStatusMessage('Connection lost');
        closeSource();
      };
    },
    [recordEvent]
  );

  const handleFileUpload = async (file: File) => {
    setUploading(true);
    setStatusMessage('Uploading...');
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
      setStatusMessage('Upload a binary first');
      return;
    }

    closeSource();
    setStatus('running');
    setStatusMessage('Analyzing...');
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
          user_goal: userGoal.trim() || undefined,
        }),
      });

      if (!response.ok) {
        const errorBody = await response.json();
        throw new Error(errorBody.error ?? 'Analysis failed');
      }

      const data: ApiAnalysisResponse = await response.json();

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
          if (payload.stage) setStatusMessage(`${payload.stage} stage...`);
        },
        job_failed: (payload) => {
          setStatus('error');
          setStatusMessage(payload.error ?? 'Failed');
          closeSource();
        },
        job_completed: (payload) => {
          setStatus('done');
          setStatusMessage('Done');
          if (payload.session_id) {
            lastSyncedSessionIdRef.current = null;
            setActiveSessionId(payload.session_id);
            activeSessionIdRef.current = payload.session_id;
            refreshSessions();
            loadSessionMessages(payload.session_id).catch(console.error);
          }
          closeSource();
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
            
            // Auto-ask with the actual analysis data for context
            setTimeout(() => {
              handleAutoAskLLM(analysis.session_id!, analysis);
            }, 300);
          }
        },
      };

      attachEventHandlers(source, handlers);
    } catch (error) {
      console.error(error);
      setStatus('error');
      setStatusMessage(error instanceof Error ? error.message : 'Failed');
    }
  };

  const handleAutoAskLLM = async (sessionId: string, analysisResult?: AnalysisResultPayload) => {
    setActiveTab('chat');
    setSendingMessage(true);
    
    // Extract key info from analysis if available
    const quickScan = analysisResult?.quick_scan ?? result?.quick_scan ?? {};
    const deepScan = analysisResult?.deep_scan ?? result?.deep_scan ?? {};
    const r2Quick = (quickScan.radare2 ?? {}) as Record<string, any>;
    const r2Deep = (deepScan.radare2 ?? {}) as Record<string, any>;
    const binInfo = (r2Quick.info?.bin ?? {}) as Record<string, any>;
    
    const arch = binInfo.arch ?? 'unknown';
    const bits = binInfo.bits ?? '?';
    const funcCount = Array.isArray(r2Deep.functions) ? r2Deep.functions.length : 0;
    const importCount = Array.isArray(r2Quick.imports) ? r2Quick.imports.length : 0;
    const fileName = analysisResult?.binary?.split('/').pop() ?? 'this binary';
    
    // Build a simple, friendly intro prompt
    let prompt: string;
    
    if (userGoal.trim()) {
      // User has a specific goal
      prompt = `My goal: ${userGoal.trim()}

What can you tell me about ${fileName}? Keep it brief.`;
    } else {
      // Simple intro - just ask for a quick summary
      prompt = `Give me a quick intro to ${fileName}.

In 2-3 sentences: what is it and what does it do? I'm ${funcCount > 0 ? 'seeing ' + funcCount + ' functions' : 'just getting started'}.`;
    }
    
    try {
      const response = await fetch(`/api/chats/${sessionId}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: prompt,
          call_llm: true,
        }),
      });
      
      if (response.ok) {
        const data = await response.json();
        setMessages(data.messages);
      }
    } catch (error) {
      console.error('Auto-ask failed:', error);
    } finally {
      setSendingMessage(false);
    }
  };

  const handleSessionSelect = (session: ChatSessionSummary) => {
    setActiveSessionId(session.session_id);
    activeSessionIdRef.current = session.session_id;
    setBinaryPath(session.binary_path);
    setFileName(session.title ?? session.binary_path.split('/').pop() ?? null);
    lastSyncedSessionIdRef.current = session.session_id;
  };

  const handleDeleteSession = async (sessionId: string) => {
    try {
      const response = await fetch(`/api/chats/${sessionId}`, {
        method: 'DELETE',
      });
      if (response.ok) {
        // Remove from local state
        setSessions((prev) => prev.filter((s) => s.session_id !== sessionId));
        // If we deleted the active session, select the next one
        if (activeSessionId === sessionId) {
          const remaining = sessions.filter((s) => s.session_id !== sessionId);
          if (remaining.length > 0) {
            setActiveSessionId(remaining[0].session_id);
          } else {
            setActiveSessionId(null);
            setResult(null);
          }
        }
      }
    } catch (error) {
      console.error('Delete failed:', error);
    }
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
        throw new Error(errorBody.error ?? 'Failed');
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
      setChatError(error instanceof Error ? error.message : 'Failed');
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
    setUserGoal('');
    setResult(null);
    setEvents([]);
    setStatus('idle');
    setStatusMessage(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <Box
      sx={{
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        bgcolor: 'background.default',
        color: 'text.primary',
      }}
    >
      {/* Header */}
      <Box
        component="header"
        sx={{
          px: 2,
          py: 1,
          borderBottom: 1,
          borderColor: 'divider',
          display: 'flex',
          alignItems: 'center',
          gap: 2,
          bgcolor: 'background.paper',
        }}
      >
        <Typography variant="h6" fontWeight={600} sx={{ fontFamily: 'var(--font-sans)' }}>
          r2d2
        </Typography>

        <Box sx={{ flex: 1 }} />

        {health && health.available_models && health.available_models.length > 0 && (
          <FormControl size="small" sx={{ minWidth: 180 }}>
            <Select
              value={health.model}
              onChange={handleModelChange}
              sx={{
                fontSize: '0.8rem',
                transition: 'all 0.2s ease',
                '& .MuiSelect-select': {
                  py: 0.75,
                  px: 1.5,
                },
                '&:hover': {
                  bgcolor: 'action.hover',
                },
              }}
            >
              {health.available_models.map((modelId) => (
                <MenuItem key={modelId} value={modelId} sx={{ fontSize: '0.8rem' }}>
                  {health.model_names?.[modelId] || modelId}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        )}

        {health && (!health.available_models || health.available_models.length === 0) && (
          <Typography variant="caption" color="text.secondary">
            {health.model_names?.[health.model] || health.model}
          </Typography>
        )}

        <Tooltip title={isDark ? 'Light mode' : 'Dark mode'}>
          <IconButton size="small" onClick={toggleTheme}>
            {isDark ? <LightModeIcon sx={{ fontSize: 18 }} /> : <DarkModeIcon sx={{ fontSize: 18 }} />}
          </IconButton>
        </Tooltip>

        <Tooltip title="Settings">
          <IconButton size="small" onClick={() => setSettingsOpen(true)}>
            <SettingsIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>
      </Box>

      <SettingsDrawer
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        isDarkMode={isDark}
        onToggleTheme={toggleTheme}
        settings={settings}
        onSettingsChange={setSettings}
      />

      {/* Main */}
      <Box sx={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* Sidebar */}
        <Box
          component="aside"
          sx={{
            width: 240,
            borderRight: 1,
            borderColor: 'divider',
            display: 'flex',
            flexDirection: 'column',
            bgcolor: 'background.paper',
          }}
        >
          <Box sx={{ p: 1.5, borderBottom: 1, borderColor: 'divider' }}>
            <Typography variant="caption" color="text.secondary" fontWeight={500}>
              Sessions
            </Typography>
          </Box>
          <Box sx={{ flex: 1, overflow: 'auto' }}>
            <SessionList
              sessions={sessions}
              activeSessionId={activeSessionId}
              onSelect={handleSessionSelect}
              onDelete={handleDeleteSession}
            />
          </Box>
        </Box>

        {/* Main panel */}
        <Box
          sx={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}
          onDragOver={handleDragOver}
          onDragEnter={handleDragEnter}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <input
            ref={fileInputRef}
            type="file"
            onChange={handleFileInputChange}
            style={{ display: 'none' }}
            accept="*/*"
          />

          {/* No file selected - show full drop zone */}
          {!fileName && !result ? (
            <Box
              onClick={() => fileInputRef.current?.click()}
              sx={{
                flex: 1,
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                bgcolor: isDragging ? 'action.hover' : 'transparent',
                border: isDragging ? 2 : 0,
                borderStyle: 'dashed',
                borderColor: 'primary.main',
                m: isDragging ? 2 : 0,
                borderRadius: isDragging ? 2 : 0,
                transition: 'all 0.2s',
              }}
            >
              <CloudUploadIcon sx={{ fontSize: 56, color: 'text.disabled', mb: 2 }} />
              <Typography variant="body1" color="text.secondary" fontWeight={500}>
                {isDragging ? 'Drop binary here' : 'Drop a binary file to analyze'}
              </Typography>
              <Typography variant="caption" color="text.disabled" sx={{ mt: 0.5 }}>
                or click anywhere to browse
              </Typography>
            </Box>
          ) : (
            <>
              {/* File selected - show controls */}
              <Box
                component="form"
                onSubmit={handleAnalyze}
                sx={{
                  p: 2,
                  borderBottom: 1,
                  borderColor: 'divider',
                  bgcolor: 'background.paper',
                }}
              >
                <Stack spacing={1.5}>
                  <Stack direction="row" spacing={2} alignItems="center">
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Typography variant="body2" fontWeight={600} sx={{ fontFamily: 'monospace' }}>
                        {fileName || result?.binary.split('/').pop()}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {settings.quickScanOnly ? 'Quick scan' : 'Full analysis'}
                        {settings.enableAngr && ' + angr'}
                      </Typography>
                    </Box>
                    <Button variant="text" size="small" onClick={clearFile} disabled={status === 'running'}>
                      Clear
                    </Button>
                    <Button
                      type="submit"
                      variant="contained"
                      size="small"
                      disabled={status === 'running' || uploading || !fileName}
                      startIcon={status === 'running' ? <CircularProgress size={14} color="inherit" /> : <PlayArrowIcon />}
                    >
                      {status === 'running' ? 'Running' : 'Analyze'}
                    </Button>
                  </Stack>

                  {/* User goal input */}
                  <TextField
                    size="small"
                    placeholder="What are you looking for? (e.g., find C2 callbacks, identify crypto)"
                    value={userGoal}
                    onChange={(e) => setUserGoal(e.target.value)}
                    fullWidth
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        fontSize: '0.8125rem',
                      },
                    }}
                  />

                  {statusMessage && (
                    <Alert
                      severity={status === 'error' ? 'error' : status === 'done' ? 'success' : 'info'}
                      sx={{ py: 0.5 }}
                    >
                      {statusMessage}
                    </Alert>
                  )}
                </Stack>
              </Box>

              {/* Tabs */}
              <Box sx={{ borderBottom: 1, borderColor: 'divider', px: 2 }}>
                <Tabs value={activeTab} onChange={handleTabChange}>
                  <Tab value="results" label="Results" />
                  <Tab value="chat" label="Chat" />
                  <Tab value="logs" label={`Logs${events.length ? ` (${events.length})` : ''}`} />
                </Tabs>
              </Box>

              {/* Content */}
              <Box sx={{ flex: 1, overflow: 'auto', p: 2 }}>
                {activeTab === 'results' && (
                  <ResultViewer 
                    result={result} 
                    sessionId={activeSessionId}
                    onAskAboutCode={(codeOrQuestion) => {
                      // Switch to chat tab and send the code/question
                      setActiveTab('chat');
                      
                      // Check if the input already contains a user question (has text before the code block)
                      const hasUserQuestion = codeOrQuestion.includes('```') && 
                        codeOrQuestion.indexOf('```') > 10; // User wrote something before the code block
                      
                      let prompt: string;
                      if (hasUserQuestion) {
                        // User provided their own question with the code
                        prompt = codeOrQuestion;
                      } else {
                        // Just code, use boilerplate analysis
                        const archName = (result?.quick_scan?.radare2 as any)?.info?.bin?.arch || 'assembly';
                        prompt = `Explain this ${archName} code:\n\n\`\`\`asm\n${codeOrQuestion}\n\`\`\`\n\nWhat does it do? Walk me through each instruction. Are there any security concerns or interesting patterns?`;
                      }
                      
                      handleSendMessage(prompt, { callLLM: true });
                    }}
                  />
                )}
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
            </>
          )}
        </Box>
      </Box>
    </Box>
  );
};

export default App;
