/**
 * GhidraScriptingPanel - Interactive Ghidra script generation and execution
 *
 * Allows users to describe analysis tasks in natural language, generates
 * Python/Java scripts for Ghidra, and executes them with full trajectory tracking.
 */

import AutoFixHighIcon from '@mui/icons-material/AutoFixHigh';
import CodeIcon from '@mui/icons-material/Code';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import DownloadIcon from '@mui/icons-material/Download';
import HistoryIcon from '@mui/icons-material/History';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import TerminalIcon from '@mui/icons-material/Terminal';
import {
  Alert,
  alpha,
  Box,
  Button,
  Chip,
  CircularProgress,
  Divider,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Stack,
  TextField,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import { FC, memo, useCallback, useMemo, useState } from 'react';

// Script language options
type ScriptLanguage = 'python' | 'java';

interface ScriptTask {
  id: string;
  description: string;
  language: ScriptLanguage;
  script: string;
  status: 'pending' | 'generating' | 'ready' | 'running' | 'completed' | 'failed';
  result?: string;
  error?: string;
  createdAt: string;
  executedAt?: string;
}

interface GhidraScriptingPanelProps {
  sessionId?: string | null;
  binaryPath?: string | null;
  onScriptExecuted?: (task: ScriptTask) => void;
}

// Example task templates
const TASK_TEMPLATES = [
  { label: 'Find all string references', description: 'Find all defined strings and their cross-references in the binary' },
  { label: 'Analyze function calls', description: 'List all function calls and build a call graph for the main function' },
  { label: 'Find crypto constants', description: 'Search for common cryptographic constants (AES S-box, SHA magic numbers, etc.)' },
  { label: 'Extract imported functions', description: 'List all imported functions grouped by library' },
  { label: 'Find dangerous patterns', description: 'Identify potentially dangerous function calls (strcpy, sprintf, system, etc.)' },
  { label: 'Decompile all functions', description: 'Decompile all functions and save to a file' },
  { label: 'Find indirect calls', description: 'Identify all indirect calls and jumps that might indicate function pointers' },
  { label: 'Analyze data sections', description: 'List all data sections with their contents and cross-references' },
];

const GhidraScriptingPanel: FC<GhidraScriptingPanelProps> = memo(({
  sessionId,
  binaryPath,
  onScriptExecuted,
}) => {
  const theme = useTheme();
  const [taskDescription, setTaskDescription] = useState('');
  const [language, setLanguage] = useState<ScriptLanguage>('python');
  const [generating, setGenerating] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [currentScript, setCurrentScript] = useState<string | null>(null);
  const [executionResult, setExecutionResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [taskHistory, setTaskHistory] = useState<ScriptTask[]>([]);
  const [showHistory, setShowHistory] = useState(false);

  // Generate script from task description
  const handleGenerateScript = useCallback(async () => {
    if (!taskDescription.trim() || !sessionId) return;

    setGenerating(true);
    setError(null);
    setCurrentScript(null);
    setExecutionResult(null);

    try {
      const response = await fetch('/api/ghidra/generate-script', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: sessionId,
          task_description: taskDescription,
          language,
          binary_path: binaryPath,
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to generate script');
      }

      const data = await response.json();
      setCurrentScript(data.script);

      // Add to history
      const newTask: ScriptTask = {
        id: `task-${Date.now()}`,
        description: taskDescription,
        language,
        script: data.script,
        status: 'ready',
        createdAt: new Date().toISOString(),
      };
      setTaskHistory(prev => [newTask, ...prev].slice(0, 20)); // Keep last 20
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate script');
    } finally {
      setGenerating(false);
    }
  }, [taskDescription, language, sessionId, binaryPath]);

  // Execute the current script
  const handleExecuteScript = useCallback(async () => {
    if (!currentScript || !sessionId) return;

    setExecuting(true);
    setError(null);
    setExecutionResult(null);

    try {
      const response = await fetch('/api/ghidra/execute-script', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: sessionId,
          script: currentScript,
          language,
          binary_path: binaryPath,
          task_description: taskDescription,
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to execute script');
      }

      const data = await response.json();
      setExecutionResult(data.output);

      // Update history with result
      setTaskHistory(prev => {
        const updated = [...prev];
        const idx = updated.findIndex(t => t.script === currentScript);
        if (idx >= 0) {
          updated[idx] = {
            ...updated[idx],
            status: 'completed',
            result: data.output,
            executedAt: new Date().toISOString(),
          };
        }
        return updated;
      });

      // Notify parent
      if (onScriptExecuted) {
        onScriptExecuted({
          id: `task-${Date.now()}`,
          description: taskDescription,
          language,
          script: currentScript,
          status: 'completed',
          result: data.output,
          createdAt: new Date().toISOString(),
          executedAt: new Date().toISOString(),
        });
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to execute script';
      setError(errorMessage);
      setExecutionResult(null);

      // Update history with error
      setTaskHistory(prev => {
        const updated = [...prev];
        const idx = updated.findIndex(t => t.script === currentScript);
        if (idx >= 0) {
          updated[idx] = {
            ...updated[idx],
            status: 'failed',
            error: errorMessage,
          };
        }
        return updated;
      });
    } finally {
      setExecuting(false);
    }
  }, [currentScript, language, sessionId, binaryPath, taskDescription, onScriptExecuted]);

  // Copy script to clipboard
  const handleCopyScript = useCallback(() => {
    if (currentScript) {
      navigator.clipboard.writeText(currentScript);
    }
  }, [currentScript]);

  // Download script
  const handleDownloadScript = useCallback(() => {
    if (!currentScript) return;

    const ext = language === 'python' ? 'py' : 'java';
    const filename = `ghidra_script_${Date.now()}.${ext}`;
    const blob = new Blob([currentScript], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }, [currentScript, language]);

  // Load a task from history
  const handleLoadFromHistory = useCallback((task: ScriptTask) => {
    setTaskDescription(task.description);
    setLanguage(task.language);
    setCurrentScript(task.script);
    setExecutionResult(task.result || null);
    setShowHistory(false);
  }, []);

  // Apply a template
  const handleApplyTemplate = useCallback((template: typeof TASK_TEMPLATES[0]) => {
    setTaskDescription(template.description);
  }, []);

  // Syntax highlighting theme
  const codeStyle = useMemo(() => ({
    fontFamily: 'JetBrains Mono, Fira Code, Monaco, Consolas, monospace',
    fontSize: '0.8rem',
    lineHeight: 1.6,
    bgcolor: theme.palette.mode === 'dark' ? '#1e1e1e' : '#f5f5f5',
    color: theme.palette.mode === 'dark' ? '#d4d4d4' : '#333',
    p: 2,
    borderRadius: 1,
    overflow: 'auto',
    whiteSpace: 'pre-wrap' as const,
    wordBreak: 'break-word' as const,
  }), [theme.palette.mode]);

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Header */}
      <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
        <Stack direction="row" alignItems="center" justifyContent="space-between">
          <Stack direction="row" alignItems="center" spacing={1}>
            <TerminalIcon sx={{ color: 'primary.main' }} />
            <Typography variant="h6" fontWeight={600}>
              Ghidra Scripting
            </Typography>
            <Chip
              size="small"
              label={language === 'python' ? 'Python' : 'Java'}
              color="primary"
              variant="outlined"
            />
          </Stack>
          <Stack direction="row" spacing={1}>
            <Tooltip title="Task History">
              <IconButton
                size="small"
                onClick={() => setShowHistory(!showHistory)}
                sx={{ bgcolor: showHistory ? alpha(theme.palette.primary.main, 0.1) : 'transparent' }}
              >
                <HistoryIcon />
              </IconButton>
            </Tooltip>
          </Stack>
        </Stack>
      </Box>

      {/* Main Content */}
      <Box sx={{ flex: 1, overflow: 'auto', p: 2 }}>
        {showHistory ? (
          // History View
          <Stack spacing={2}>
            <Typography variant="subtitle2" color="text.secondary">
              Recent Tasks ({taskHistory.length})
            </Typography>
            {taskHistory.length === 0 ? (
              <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
                No tasks yet. Generate a script to see it here.
              </Typography>
            ) : (
              taskHistory.map(task => (
                <Paper
                  key={task.id}
                  variant="outlined"
                  sx={{
                    p: 2,
                    cursor: 'pointer',
                    '&:hover': { bgcolor: alpha(theme.palette.primary.main, 0.05) },
                  }}
                  onClick={() => handleLoadFromHistory(task)}
                >
                  <Stack spacing={1}>
                    <Stack direction="row" alignItems="center" justifyContent="space-between">
                      <Typography variant="body2" fontWeight={500} sx={{ flex: 1 }}>
                        {task.description.slice(0, 100)}{task.description.length > 100 ? '...' : ''}
                      </Typography>
                      <Chip
                        size="small"
                        label={task.status}
                        color={
                          task.status === 'completed' ? 'success' :
                          task.status === 'failed' ? 'error' :
                          'default'
                        }
                        sx={{ ml: 1 }}
                      />
                    </Stack>
                    <Stack direction="row" spacing={1}>
                      <Chip size="small" label={task.language} variant="outlined" />
                      <Typography variant="caption" color="text.secondary">
                        {new Date(task.createdAt).toLocaleString()}
                      </Typography>
                    </Stack>
                  </Stack>
                </Paper>
              ))
            )}
          </Stack>
        ) : (
          // Main Script Generation View
          <Stack spacing={3}>
            {/* Task Description Input */}
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Describe Your Task
              </Typography>
              <TextField
                fullWidth
                multiline
                rows={3}
                placeholder="e.g., Find all functions that call malloc and analyze their memory handling patterns"
                value={taskDescription}
                onChange={(e) => setTaskDescription(e.target.value)}
                disabled={generating}
              />

              {/* Quick Templates */}
              <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: 'wrap', gap: 1 }}>
                {TASK_TEMPLATES.slice(0, 4).map((template, i) => (
                  <Chip
                    key={i}
                    label={template.label}
                    size="small"
                    variant="outlined"
                    onClick={() => handleApplyTemplate(template)}
                    sx={{ cursor: 'pointer' }}
                  />
                ))}
              </Stack>
            </Box>

            {/* Language Selection and Generate Button */}
            <Stack direction="row" spacing={2} alignItems="center">
              <FormControl size="small" sx={{ minWidth: 120 }}>
                <InputLabel>Language</InputLabel>
                <Select
                  value={language}
                  label="Language"
                  onChange={(e) => setLanguage(e.target.value as ScriptLanguage)}
                  disabled={generating}
                >
                  <MenuItem value="python">Python</MenuItem>
                  <MenuItem value="java">Java</MenuItem>
                </Select>
              </FormControl>
              <Button
                variant="contained"
                startIcon={generating ? <CircularProgress size={16} color="inherit" /> : <AutoFixHighIcon />}
                onClick={handleGenerateScript}
                disabled={!taskDescription.trim() || generating || !sessionId}
              >
                {generating ? 'Generating...' : 'Generate Script'}
              </Button>
            </Stack>

            {error && (
              <Alert severity="error" onClose={() => setError(null)}>
                {error}
              </Alert>
            )}

            {/* Generated Script */}
            {currentScript && (
              <Box>
                <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
                  <Typography variant="subtitle2">
                    Generated Script
                  </Typography>
                  <Stack direction="row" spacing={1}>
                    <Tooltip title="Copy to clipboard">
                      <IconButton size="small" onClick={handleCopyScript}>
                        <ContentCopyIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Download script">
                      <IconButton size="small" onClick={handleDownloadScript}>
                        <DownloadIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Button
                      size="small"
                      variant="contained"
                      color="success"
                      startIcon={executing ? <CircularProgress size={14} color="inherit" /> : <PlayArrowIcon />}
                      onClick={handleExecuteScript}
                      disabled={executing || !sessionId}
                    >
                      {executing ? 'Running...' : 'Execute'}
                    </Button>
                  </Stack>
                </Stack>
                <Paper variant="outlined" sx={codeStyle}>
                  <Box component="code">
                    {currentScript}
                  </Box>
                </Paper>
              </Box>
            )}

            {/* Execution Result */}
            {executionResult && (
              <Box>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                  Execution Result
                </Typography>
                <Paper
                  variant="outlined"
                  sx={{
                    ...codeStyle,
                    maxHeight: 300,
                    bgcolor: alpha(theme.palette.success.main, 0.05),
                    borderColor: alpha(theme.palette.success.main, 0.3),
                  }}
                >
                  <Box component="pre" sx={{ m: 0 }}>
                    {executionResult}
                  </Box>
                </Paper>
              </Box>
            )}

            {/* Help Text */}
            {!currentScript && !generating && (
              <Paper
                variant="outlined"
                sx={{
                  p: 3,
                  textAlign: 'center',
                  bgcolor: alpha(theme.palette.info.main, 0.05),
                  borderColor: alpha(theme.palette.info.main, 0.2),
                }}
              >
                <CodeIcon sx={{ fontSize: 48, color: 'text.secondary', opacity: 0.5, mb: 2 }} />
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Describe what you want to analyze in plain English.
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  r2d2 will generate a Ghidra {language === 'python' ? 'Python' : 'Java'} script
                  tailored to your task. Scripts are tracked for trajectory recording.
                </Typography>
              </Paper>
            )}
          </Stack>
        )}
      </Box>

      {/* Footer Status */}
      {sessionId && binaryPath && (
        <Box sx={{ p: 1, borderTop: 1, borderColor: 'divider', bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
          <Stack direction="row" alignItems="center" spacing={1}>
            <Chip
              size="small"
              label="Session Active"
              color="success"
              variant="outlined"
              sx={{ height: 20, fontSize: '0.65rem' }}
            />
            <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
              {binaryPath.split('/').pop()}
            </Typography>
          </Stack>
        </Box>
      )}
    </Box>
  );
});

export default GhidraScriptingPanel;
