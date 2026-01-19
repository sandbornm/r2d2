/**
 * TrajectoryPanel - A collapsible panel showing the user's analysis journey.
 *
 * Helps users orient themselves by showing what they've explored and done
 * during their current analysis session.
 */

import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExploreIcon from '@mui/icons-material/Explore';
import FunctionsIcon from '@mui/icons-material/Functions';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import NavigationIcon from '@mui/icons-material/Navigation';
import QuestionAnswerIcon from '@mui/icons-material/QuestionAnswer';
import RouteIcon from '@mui/icons-material/Route';
import TimelineIcon from '@mui/icons-material/Timeline';
import {
  alpha,
  Box,
  Chip,
  Collapse,
  IconButton,
  LinearProgress,
  Paper,
  Stack,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import { FC, memo, useState } from 'react';
import { TrajectorySnapshot } from '../trajectory/TrajectoryStore';

interface TrajectoryPanelProps {
  snapshot: TrajectorySnapshot | null;
  compact?: boolean;
}

// Map depth levels to progress values
const DEPTH_PROGRESS: Record<string, number> = {
  overview: 20,
  investigating: 55,
  deep_dive: 90,
};

// Map depth levels to colors
const DEPTH_COLORS: Record<string, string> = {
  overview: '#64B5F6', // Light blue
  investigating: '#FFB74D', // Orange
  deep_dive: '#81C784', // Green
};

const TrajectoryPanel: FC<TrajectoryPanelProps> = memo(({ snapshot, compact = false }) => {
  const theme = useTheme();
  const isDark = theme.palette.mode === 'dark';
  const [expanded, setExpanded] = useState(false);

  if (!snapshot) {
    return null;
  }

  const depthProgress = DEPTH_PROGRESS[snapshot.depth_level] || 20;
  const depthColor = DEPTH_COLORS[snapshot.depth_level] || theme.palette.primary.main;

  // Format duration
  const formatDuration = (seconds: number): string => {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${mins}m`;
  };

  // Get icon for action type
  const getActionIcon = (action: string) => {
    if (action.includes('viewed') || action.includes('browsed')) {
      return <ExploreIcon sx={{ fontSize: 12 }} />;
    }
    if (action.includes('asked')) {
      return <QuestionAnswerIcon sx={{ fontSize: 12 }} />;
    }
    if (action.includes('jumped') || action.includes('navigat')) {
      return <NavigationIcon sx={{ fontSize: 12 }} />;
    }
    if (action.includes('function')) {
      return <FunctionsIcon sx={{ fontSize: 12 }} />;
    }
    return <TimelineIcon sx={{ fontSize: 12 }} />;
  };

  // Compact header (always visible)
  const Header = (
    <Box
      onClick={() => setExpanded(!expanded)}
      sx={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        cursor: 'pointer',
        p: compact ? 0.75 : 1,
        '&:hover': {
          bgcolor: alpha(theme.palette.action.hover, 0.5),
        },
        borderRadius: 1,
        transition: 'background-color 0.15s ease',
      }}
    >
      <Stack direction="row" alignItems="center" spacing={1}>
        <RouteIcon sx={{ fontSize: 16, color: depthColor }} />
        <Typography variant="caption" fontWeight={600} sx={{ color: 'text.secondary' }}>
          Trajectory
        </Typography>
        <Chip
          size="small"
          label={snapshot.depth_level.replace('_', ' ')}
          sx={{
            height: 18,
            fontSize: '0.65rem',
            bgcolor: alpha(depthColor, isDark ? 0.2 : 0.15),
            color: depthColor,
            fontWeight: 500,
            textTransform: 'capitalize',
          }}
        />
      </Stack>

      <Stack direction="row" alignItems="center" spacing={0.5}>
        <Tooltip title={`${snapshot.actions_count} actions in ${formatDuration(snapshot.session_duration_s)}`}>
          <Chip
            size="small"
            label={`${snapshot.actions_count} actions`}
            variant="outlined"
            sx={{
              height: 18,
              fontSize: '0.6rem',
              borderColor: 'divider',
            }}
          />
        </Tooltip>
        <IconButton size="small" sx={{ p: 0.25 }}>
          {expanded ? <ExpandLessIcon sx={{ fontSize: 16 }} /> : <ExpandMoreIcon sx={{ fontSize: 16 }} />}
        </IconButton>
      </Stack>
    </Box>
  );

  // Expanded content
  const ExpandedContent = (
    <Collapse in={expanded}>
      <Box sx={{ px: compact ? 0.75 : 1, pb: compact ? 0.75 : 1 }}>
        {/* Depth Progress */}
        <Box sx={{ mb: 1.5 }}>
          <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">
              Analysis Depth
            </Typography>
            <Tooltip title="How deep you've gone into the analysis">
              <HelpOutlineIcon sx={{ fontSize: 12, color: 'text.disabled', cursor: 'help' }} />
            </Tooltip>
          </Stack>
          <LinearProgress
            variant="determinate"
            value={depthProgress}
            sx={{
              height: 6,
              borderRadius: 1,
              bgcolor: alpha(depthColor, 0.15),
              '& .MuiLinearProgress-bar': {
                bgcolor: depthColor,
                borderRadius: 1,
              },
            }}
          />
          <Stack direction="row" justifyContent="space-between" sx={{ mt: 0.25 }}>
            <Typography variant="caption" color="text.disabled" sx={{ fontSize: '0.6rem' }}>
              Overview
            </Typography>
            <Typography variant="caption" color="text.disabled" sx={{ fontSize: '0.6rem' }}>
              Investigating
            </Typography>
            <Typography variant="caption" color="text.disabled" sx={{ fontSize: '0.6rem' }}>
              Deep Dive
            </Typography>
          </Stack>
        </Box>

        {/* Current State */}
        <Paper
          variant="outlined"
          sx={{
            p: 1,
            mb: 1.5,
            bgcolor: alpha(theme.palette.primary.main, isDark ? 0.05 : 0.03),
            borderColor: alpha(theme.palette.primary.main, 0.2),
          }}
        >
          <Typography variant="caption" fontWeight={600} sx={{ display: 'block', mb: 0.5 }}>
            Current State
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" gap={0.5}>
            <Chip
              size="small"
              label={`View: ${snapshot.current_view}`}
              sx={{ height: 20, fontSize: '0.65rem' }}
            />
            {snapshot.current_function && (
              <Chip
                size="small"
                label={`Fn: ${snapshot.current_function}`}
                sx={{ height: 20, fontSize: '0.65rem', fontFamily: 'monospace' }}
              />
            )}
            {snapshot.current_address && (
              <Chip
                size="small"
                label={snapshot.current_address}
                sx={{ height: 20, fontSize: '0.65rem', fontFamily: 'monospace' }}
              />
            )}
            {snapshot.focus_area && (
              <Chip
                size="small"
                label={`Focus: ${snapshot.focus_area}`}
                color="primary"
                variant="outlined"
                sx={{ height: 20, fontSize: '0.65rem' }}
              />
            )}
          </Stack>
        </Paper>

        {/* Recent Actions Timeline */}
        {snapshot.recent_actions.length > 0 && (
          <Box sx={{ mb: 1.5 }}>
            <Typography variant="caption" fontWeight={600} sx={{ display: 'block', mb: 0.5 }}>
              Recent Activity
            </Typography>
            <Stack spacing={0.25}>
              {snapshot.recent_actions.slice(-5).map((action, idx) => (
                <Stack
                  key={idx}
                  direction="row"
                  alignItems="center"
                  spacing={0.5}
                  sx={{
                    py: 0.25,
                    px: 0.5,
                    borderRadius: 0.5,
                    bgcolor: idx === snapshot.recent_actions.length - 1
                      ? alpha(theme.palette.success.main, isDark ? 0.1 : 0.08)
                      : 'transparent',
                  }}
                >
                  {getActionIcon(action)}
                  <Typography
                    variant="caption"
                    sx={{
                      fontSize: '0.65rem',
                      color: idx === snapshot.recent_actions.length - 1 ? 'text.primary' : 'text.secondary',
                    }}
                  >
                    {action}
                  </Typography>
                </Stack>
              ))}
            </Stack>
          </Box>
        )}

        {/* Functions Explored */}
        {snapshot.functions_explored.length > 0 && (
          <Box sx={{ mb: 1.5 }}>
            <Typography variant="caption" fontWeight={600} sx={{ display: 'block', mb: 0.5 }}>
              Functions Explored ({snapshot.functions_explored.length})
            </Typography>
            <Stack direction="row" spacing={0.5} flexWrap="wrap" gap={0.5}>
              {snapshot.functions_explored.slice(-6).map((fn, idx) => (
                <Chip
                  key={idx}
                  size="small"
                  label={fn}
                  variant="outlined"
                  sx={{
                    height: 18,
                    fontSize: '0.6rem',
                    fontFamily: 'monospace',
                    borderColor: alpha(theme.palette.info.main, 0.3),
                    color: 'text.secondary',
                  }}
                />
              ))}
            </Stack>
          </Box>
        )}

        {/* Questions Asked */}
        {snapshot.questions.length > 0 && (
          <Box>
            <Typography variant="caption" fontWeight={600} sx={{ display: 'block', mb: 0.5 }}>
              Questions Asked ({snapshot.questions.length})
            </Typography>
            <Stack spacing={0.25}>
              {snapshot.questions.slice(-3).map((q, idx) => (
                <Typography
                  key={idx}
                  variant="caption"
                  sx={{
                    fontSize: '0.65rem',
                    color: 'text.secondary',
                    fontStyle: 'italic',
                    pl: 1,
                    borderLeft: `2px solid ${alpha(theme.palette.primary.main, 0.3)}`,
                  }}
                >
                  "{q.q}"
                </Typography>
              ))}
            </Stack>
          </Box>
        )}

        {/* Session Stats */}
        <Box
          sx={{
            mt: 1.5,
            pt: 1,
            borderTop: 1,
            borderColor: 'divider',
          }}
        >
          <Stack direction="row" justifyContent="space-between">
            <Typography variant="caption" color="text.disabled" sx={{ fontSize: '0.6rem' }}>
              Session: {formatDuration(snapshot.session_duration_s)}
            </Typography>
            <Typography variant="caption" color="text.disabled" sx={{ fontSize: '0.6rem' }}>
              {snapshot.addresses_visited.length} addresses visited
            </Typography>
          </Stack>
        </Box>
      </Box>
    </Collapse>
  );

  return (
    <Paper
      variant="outlined"
      sx={{
        borderColor: expanded ? alpha(depthColor, 0.3) : 'divider',
        transition: 'border-color 0.2s ease',
        overflow: 'hidden',
      }}
    >
      {Header}
      {ExpandedContent}
    </Paper>
  );
});

export default TrajectoryPanel;
