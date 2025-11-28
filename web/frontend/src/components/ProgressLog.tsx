import {
  alpha,
  Box,
  Chip,
  CircularProgress,
  keyframes,
  LinearProgress,
  Paper,
  Stack,
  Typography,
  useTheme,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import PlayCircleIcon from '@mui/icons-material/PlayCircle';
import SkipNextIcon from '@mui/icons-material/SkipNext';
import TerminalIcon from '@mui/icons-material/Terminal';
import BugReportIcon from '@mui/icons-material/BugReport';
import SearchIcon from '@mui/icons-material/Search';
import MemoryIcon from '@mui/icons-material/Memory';
import CodeIcon from '@mui/icons-material/Code';
import { FC } from 'react';
import type { ProgressEventEntry } from '../types';

// Pulse animation for active items
const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.6; }
`;

const glow = keyframes`
  0%, 100% { box-shadow: 0 0 5px currentColor; }
  50% { box-shadow: 0 0 20px currentColor, 0 0 30px currentColor; }
`;

interface ProgressLogProps {
  entries: ProgressEventEntry[];
}

// Quirky messages explaining what's happening
const STAGE_MESSAGES: Record<string, { active: string; done: string }> = {
  quick: {
    active: "🔍 Quick recon — gathering file signatures, headers, and first impressions...",
    done: "✓ Quick scan complete — got the basics locked down",
  },
  deep: {
    active: "🔬 Deep dive — disassembling functions, tracing control flow, hunting patterns...",
    done: "✓ Deep analysis complete — found all the secrets",
  },
};

const ADAPTER_MESSAGES: Record<string, { active: string; done: string; icon: JSX.Element }> = {
  libmagic: {
    active: "Sniffing file magic bytes — what are you, little binary?",
    done: "File type identified",
    icon: <SearchIcon sx={{ fontSize: 18 }} />,
  },
  radare2: {
    active: "r2 is doing its thing — parsing headers, finding functions, mapping memory...",
    done: "Radare2 analysis complete",
    icon: <TerminalIcon sx={{ fontSize: 18 }} />,
  },
  capstone: {
    active: "Disassembling instructions — turning bytes into assembly...",
    done: "Disassembly complete",
    icon: <CodeIcon sx={{ fontSize: 18 }} />,
  },
  angr: {
    active: "Symbolic execution in progress — exploring all possible paths (grab a coffee ☕)",
    done: "Symbolic analysis complete",
    icon: <BugReportIcon sx={{ fontSize: 18 }} />,
  },
  ghidra: {
    active: "Ghidra is decompiling — turning machine code back into C...",
    done: "Decompilation complete",
    icon: <MemoryIcon sx={{ fontSize: 18 }} />,
  },
};

const getAdapterInfo = (adapter: string) => {
  return ADAPTER_MESSAGES[adapter.toLowerCase()] ?? {
    active: `Running ${adapter}...`,
    done: `${adapter} complete`,
    icon: <TerminalIcon sx={{ fontSize: 18 }} />,
  };
};

const ActiveIndicator: FC<{ color: string }> = ({ color }) => (
  <Box
    sx={{
      width: 10,
      height: 10,
      borderRadius: '50%',
      bgcolor: color,
      animation: `${glow} 1.5s ease-in-out infinite`,
      color: color,
    }}
  />
);

const LogEntry: FC<{ entry: ProgressEventEntry; isLatest: boolean }> = ({ entry, isLatest }) => {
  const theme = useTheme();
  const { event, data } = entry;

  const isActive = isLatest && !['job_completed', 'job_failed', 'stage_completed', 'adapter_completed'].includes(event);
  const isError = event.includes('failed');
  const isSkipped = event.includes('skipped');
  const isComplete = event.includes('completed');

  // Determine colors
  let accentColor = theme.palette.primary.main;
  if (isError) accentColor = theme.palette.error.main;
  else if (isSkipped) accentColor = theme.palette.warning.main;
  else if (isComplete) accentColor = theme.palette.success.main;
  else if (isActive) accentColor = theme.palette.primary.main;

  // Get message and icon
  let message = '';
  let icon = <PlayCircleIcon sx={{ fontSize: 18 }} />;

  if (event === 'job_started') {
    message = "🚀 Analysis initiated — let's see what we're dealing with...";
    icon = <PlayCircleIcon sx={{ fontSize: 18 }} />;
  } else if (event === 'job_completed') {
    message = "🎉 All done! Your binary has been thoroughly examined.";
    icon = <CheckCircleIcon sx={{ fontSize: 18 }} />;
  } else if (event === 'job_failed') {
    message = `💥 Analysis failed: ${data.error ?? 'Unknown error'}`;
    icon = <ErrorIcon sx={{ fontSize: 18 }} />;
  } else if (event === 'stage_started' && data.stage) {
    const stageInfo = STAGE_MESSAGES[data.stage] ?? { active: `Running ${data.stage} stage...`, done: '' };
    message = stageInfo.active;
  } else if (event === 'stage_completed' && data.stage) {
    const stageInfo = STAGE_MESSAGES[data.stage] ?? { active: '', done: `${data.stage} stage complete` };
    message = stageInfo.done;
    icon = <CheckCircleIcon sx={{ fontSize: 18 }} />;
  } else if (event === 'adapter_started' && data.adapter) {
    const adapterInfo = getAdapterInfo(data.adapter);
    message = adapterInfo.active;
    icon = adapterInfo.icon;
  } else if (event === 'adapter_completed' && data.adapter) {
    const adapterInfo = getAdapterInfo(data.adapter);
    message = adapterInfo.done;
    icon = <CheckCircleIcon sx={{ fontSize: 18 }} />;
  } else if (event === 'adapter_failed' && data.adapter) {
    message = `${data.adapter} failed: ${data.error ?? 'Unknown error'}`;
    icon = <ErrorIcon sx={{ fontSize: 18 }} />;
  } else if (event === 'adapter_skipped' && data.adapter) {
    message = `Skipped ${data.adapter}: ${data.reason ?? 'Not available'}`;
    icon = <SkipNextIcon sx={{ fontSize: 18 }} />;
  } else if (event === 'analysis_result') {
    message = "📊 Results are in — check the Results tab!";
    icon = <CheckCircleIcon sx={{ fontSize: 18 }} />;
  } else {
    message = event.replace(/_/g, ' ');
  }

  return (
    <Paper
      variant="outlined"
      sx={{
        p: 2,
        bgcolor: isActive ? alpha(accentColor, 0.08) : alpha(theme.palette.background.paper, 0.5),
        borderColor: isActive ? alpha(accentColor, 0.3) : 'divider',
        borderLeft: `3px solid ${accentColor}`,
        animation: isActive ? `${pulse} 2s ease-in-out infinite` : 'none',
        transition: 'all 0.3s ease',
      }}
    >
      <Stack spacing={1.5}>
        <Stack direction="row" spacing={1.5} alignItems="center">
          {isActive ? (
            <CircularProgress size={18} sx={{ color: accentColor }} />
          ) : (
            <Box sx={{ color: accentColor, display: 'flex' }}>{icon}</Box>
          )}

          <Box sx={{ flex: 1 }}>
            <Typography
              variant="body2"
              fontWeight={isActive ? 600 : 500}
              sx={{ color: isActive ? accentColor : 'text.primary' }}
            >
              {message}
            </Typography>
          </Box>

          <Stack direction="row" spacing={1} alignItems="center">
            {data.stage && (
              <Chip
                size="small"
                label={data.stage}
                sx={{
                  height: 22,
                  fontSize: '0.7rem',
                  fontWeight: 600,
                  bgcolor: alpha(theme.palette.info.main, 0.2),
                  color: theme.palette.info.main,
                }}
              />
            )}
            {data.adapter && (
              <Chip
                size="small"
                label={data.adapter}
                sx={{
                  height: 22,
                  fontSize: '0.7rem',
                  fontWeight: 600,
                  bgcolor: alpha(theme.palette.warning.main, 0.2),
                  color: theme.palette.warning.main,
                }}
              />
            )}
            {isActive && <ActiveIndicator color={accentColor} />}
          </Stack>
        </Stack>

        {isActive && (
          <LinearProgress
            sx={{
              height: 2,
              borderRadius: 1,
              bgcolor: alpha(accentColor, 0.2),
              '& .MuiLinearProgress-bar': {
                bgcolor: accentColor,
              },
            }}
          />
        )}
      </Stack>
    </Paper>
  );
};

export const ProgressLog: FC<ProgressLogProps> = ({ entries }) => {
  const theme = useTheme();

  if (!entries.length) {
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
        <TerminalIcon sx={{ fontSize: 56, mb: 2, opacity: 0.3 }} />
        <Typography variant="h6" fontWeight={600} color="text.secondary">
          Waiting for action
        </Typography>
        <Typography variant="body2" sx={{ mt: 1, textAlign: 'center', maxWidth: 300 }}>
          Drop a binary and hit Analyze to see the magic happen in real-time
        </Typography>
      </Box>
    );
  }

  // Find if there's an active operation
  const lastEntry = entries[entries.length - 1];
  const isRunning = !['job_completed', 'job_failed'].includes(lastEntry.event);

  return (
    <Stack spacing={1.5}>
      {isRunning && (
        <Paper
          sx={{
            p: 2,
            bgcolor: alpha(theme.palette.primary.main, 0.1),
            border: `1px solid ${alpha(theme.palette.primary.main, 0.3)}`,
            borderRadius: 2,
          }}
        >
          <Stack direction="row" spacing={2} alignItems="center">
            <CircularProgress size={24} sx={{ color: theme.palette.primary.main }} />
            <Box>
              <Typography variant="body2" fontWeight={600} color="primary.main">
                Analysis in progress...
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {entries.length} events processed
              </Typography>
            </Box>
          </Stack>
        </Paper>
      )}

      {entries.map((entry, index) => (
        <LogEntry key={entry.id} entry={entry} isLatest={index === entries.length - 1} />
      ))}
    </Stack>
  );
};

export default ProgressLog;
