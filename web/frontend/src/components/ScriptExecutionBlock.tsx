import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CodeIcon from '@mui/icons-material/Code';
import ErrorIcon from '@mui/icons-material/Error';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ReplayIcon from '@mui/icons-material/Replay';
import TimerIcon from '@mui/icons-material/Timer';
import WarningIcon from '@mui/icons-material/Warning';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  alpha,
  Box,
  Chip,
  IconButton,
  Paper,
  Stack,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import { FC, memo, useState } from 'react';
import { toolColors } from '../theme';

// Validation error type
interface ValidationError {
  message: string;
  location?: string;
  severity: string;
  suggestion?: string;
}

// Types matching backend models
interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationError[];
  error_summary: string;
}

interface ExecutionResult {
  status: 'success' | 'error' | 'timeout' | 'connection_lost';
  duration_ms: number;
  stdout?: string;
  stderr?: string;
  exception?: string;
  traceback?: string;
}

interface ScriptExecutionBlockProps {
  tool: string;
  language: string;
  script: string;
  validation: ValidationResult | null;
  execution: ExecutionResult | null;
  intent?: string;
  onRetry?: () => void;
  compact?: boolean;
}

const ScriptExecutionBlock: FC<ScriptExecutionBlockProps> = memo(function ScriptExecutionBlock({
  tool,
  language,
  script,
  validation,
  execution,
  intent,
  onRetry,
  compact = false,
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === 'dark';
  const [expanded, setExpanded] = useState(false);

  const toolColor = toolColors[tool as keyof typeof toolColors] || theme.palette.grey[500];

  // Determine overall status
  const getStatus = () => {
    if (!validation?.valid) return 'invalid';
    if (!execution) return 'pending';
    return execution.status;
  };

  const status = getStatus();

  const getStatusInfo = () => {
    switch (status) {
      case 'success':
        return { icon: <CheckCircleIcon />, color: 'success', label: 'Success' };
      case 'error':
        return { icon: <ErrorIcon />, color: 'error', label: 'Error' };
      case 'timeout':
        return { icon: <TimerIcon />, color: 'warning', label: 'Timeout' };
      case 'connection_lost':
        return { icon: <WarningIcon />, color: 'warning', label: 'Disconnected' };
      case 'invalid':
        return { icon: <ErrorIcon />, color: 'error', label: 'Invalid' };
      default:
        return { icon: <CodeIcon />, color: 'info', label: 'Pending' };
    }
  };

  const statusInfo = getStatusInfo();

  return (
    <Paper
      variant="outlined"
      sx={{
        overflow: 'hidden',
        bgcolor: isDark ? alpha(theme.palette.background.paper, 0.5) : theme.palette.background.paper,
        border: `1px solid ${alpha(toolColor, 0.3)}`,
        borderLeft: `3px solid ${toolColor}`,
      }}
    >
      {/* Header */}
      <Box
        sx={{
          px: 1.5,
          py: 1,
          bgcolor: alpha(toolColor, 0.08),
          borderBottom: `1px solid ${alpha(toolColor, 0.15)}`,
        }}
      >
        <Stack direction="row" alignItems="center" justifyContent="space-between">
          <Stack direction="row" alignItems="center" spacing={1}>
            <CodeIcon sx={{ fontSize: 18, color: toolColor }} />
            <Chip
              size="small"
              label={tool}
              sx={{
                height: 20,
                fontSize: '0.65rem',
                fontWeight: 600,
                bgcolor: alpha(toolColor, 0.15),
                color: toolColor,
                border: 'none',
              }}
            />
            <Chip
              size="small"
              label={language}
              variant="outlined"
              sx={{
                height: 18,
                fontSize: '0.6rem',
                borderColor: 'divider',
              }}
            />
          </Stack>
          <Stack direction="row" alignItems="center" spacing={0.5}>
            {execution?.duration_ms && (
              <Typography variant="caption" color="text.secondary">
                {execution.duration_ms}ms
              </Typography>
            )}
            <Chip
              size="small"
              icon={statusInfo.icon}
              label={statusInfo.label}
              color={statusInfo.color as 'success' | 'error' | 'warning' | 'info'}
              sx={{
                height: 20,
                fontSize: '0.6rem',
                '& .MuiChip-icon': { fontSize: 14 },
              }}
            />
            {onRetry && (
              <Tooltip title="Rerun script">
                <IconButton size="small" onClick={onRetry} aria-label="retry">
                  <ReplayIcon sx={{ fontSize: 16 }} />
                </IconButton>
              </Tooltip>
            )}
          </Stack>
        </Stack>
        {intent && (
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
            {intent}
          </Typography>
        )}
      </Box>

      {/* Validation Errors */}
      {validation && !validation.valid && validation.errors.length > 0 && (
        <Box sx={{ px: 1.5, py: 1, bgcolor: alpha(theme.palette.error.main, 0.08) }}>
          <Typography variant="caption" color="error" fontWeight={600}>
            Validation Failed
          </Typography>
          {validation.errors.map((error, i) => (
            <Box key={i} sx={{ mt: 0.5 }}>
              <Typography
                variant="caption"
                sx={{
                  fontFamily: 'monospace',
                  display: 'block',
                  color: 'error.main',
                }}
              >
                {error.location && `${error.location}: `}
                {error.message}
              </Typography>
              {error.suggestion && (
                <Typography variant="caption" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                  Suggestion: {error.suggestion}
                </Typography>
              )}
            </Box>
          ))}
        </Box>
      )}

      {/* Script (Expandable) */}
      <Accordion
        expanded={expanded}
        onChange={() => setExpanded(!expanded)}
        disableGutters
        elevation={0}
        sx={{
          '&:before': { display: 'none' },
          bgcolor: 'transparent',
        }}
      >
        <AccordionSummary
          expandIcon={<ExpandMoreIcon />}
          aria-label={expanded ? 'Hide script' : 'Show script'}
          sx={{
            minHeight: 36,
            px: 1.5,
            '& .MuiAccordionSummary-content': { my: 0.5 },
          }}
        >
          <Typography variant="caption" color="text.secondary">
            {expanded ? 'Hide script' : 'Show script'} ({script.split('\n').length} lines)
          </Typography>
        </AccordionSummary>
        <AccordionDetails sx={{ px: 1.5, py: 1, bgcolor: alpha(theme.palette.common.black, 0.03) }}>
          <Box
            component="pre"
            sx={{
              m: 0,
              p: 1,
              borderRadius: 1,
              bgcolor: alpha(theme.palette.common.black, isDark ? 0.3 : 0.05),
              fontFamily: '"JetBrains Mono", monospace',
              fontSize: '0.75rem',
              lineHeight: 1.5,
              overflow: 'auto',
              maxHeight: 200,
            }}
          >
            <code>{script}</code>
          </Box>
        </AccordionDetails>
      </Accordion>

      {/* Execution Output */}
      {execution && (
        <Box sx={{ px: 1.5, py: 1 }}>
          {execution.stdout && (
            <Box sx={{ mb: 1 }}>
              <Typography variant="caption" color="text.secondary" fontWeight={600}>
                Output
              </Typography>
              <Box
                component="pre"
                sx={{
                  m: 0,
                  mt: 0.5,
                  p: 1,
                  borderRadius: 1,
                  bgcolor: alpha(theme.palette.success.main, 0.08),
                  fontFamily: '"JetBrains Mono", monospace',
                  fontSize: '0.7rem',
                  lineHeight: 1.4,
                  overflow: 'auto',
                  maxHeight: compact ? 100 : 200,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                }}
              >
                {execution.stdout}
              </Box>
            </Box>
          )}

          {execution.stderr && (
            <Box>
              <Typography variant="caption" color="error" fontWeight={600}>
                Error Output
              </Typography>
              <Box
                component="pre"
                sx={{
                  m: 0,
                  mt: 0.5,
                  p: 1,
                  borderRadius: 1,
                  bgcolor: alpha(theme.palette.error.main, 0.08),
                  color: 'error.main',
                  fontFamily: '"JetBrains Mono", monospace',
                  fontSize: '0.7rem',
                  lineHeight: 1.4,
                  overflow: 'auto',
                  maxHeight: compact ? 80 : 150,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                }}
              >
                {execution.stderr}
              </Box>
            </Box>
          )}

          {execution.exception && execution.traceback && (
            <Accordion
              disableGutters
              elevation={0}
              sx={{
                mt: 1,
                '&:before': { display: 'none' },
                bgcolor: alpha(theme.palette.error.main, 0.05),
                border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`,
              }}
            >
              <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ minHeight: 32 }}>
                <Typography variant="caption" color="error" fontWeight={600}>
                  {execution.exception}
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Box
                  component="pre"
                  sx={{
                    m: 0,
                    fontFamily: 'monospace',
                    fontSize: '0.65rem',
                    color: 'error.main',
                    whiteSpace: 'pre-wrap',
                  }}
                >
                  {execution.traceback}
                </Box>
              </AccordionDetails>
            </Accordion>
          )}
        </Box>
      )}
    </Paper>
  );
});

export default ScriptExecutionBlock;
