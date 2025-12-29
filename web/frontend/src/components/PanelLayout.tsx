import React, { useState, useCallback, useRef, useEffect } from 'react';
import { Box, IconButton, Tooltip, Typography, Chip, Stack } from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import DragIndicatorIcon from '@mui/icons-material/DragIndicator';

export interface PanelConfig {
  id: string;
  title: string;
  icon?: React.ReactNode;
  content: React.ReactNode;
  minWidth?: number;
  defaultWidth?: number;
}

interface PanelLayoutProps {
  panels: PanelConfig[];
  activePanels: string[];
  onPanelClose: (id: string) => void;
  height?: string;
}

interface ResizeState {
  panelIndex: number;
  startX: number;
  startWidths: number[];
}

export default function PanelLayout({
  panels,
  activePanels,
  onPanelClose,
  height = '100%',
}: PanelLayoutProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [widths, setWidths] = useState<number[]>([]);
  const resizeRef = useRef<ResizeState | null>(null);

  const visiblePanels = panels.filter((p) => activePanels.includes(p.id));

  // Initialize widths when panels change
  useEffect(() => {
    if (visiblePanels.length === 0) {
      setWidths([]);
      return;
    }

    const containerWidth = containerRef.current?.offsetWidth || 800;
    const totalMinWidth = visiblePanels.reduce((sum, p) => sum + (p.minWidth || 200), 0);
    const availableWidth = Math.max(containerWidth - (visiblePanels.length - 1) * 6, totalMinWidth);

    // Distribute width equally or based on defaults
    const totalDefault = visiblePanels.reduce((sum, p) => sum + (p.defaultWidth || 1), 0);
    const newWidths = visiblePanels.map((p) => {
      const ratio = (p.defaultWidth || 1) / totalDefault;
      return Math.max(availableWidth * ratio, p.minWidth || 200);
    });

    setWidths(newWidths);
  }, [activePanels.join(','), panels.length]);

  const handleMouseDown = useCallback(
    (e: React.MouseEvent, panelIndex: number) => {
      e.preventDefault();
      resizeRef.current = {
        panelIndex,
        startX: e.clientX,
        startWidths: [...widths],
      };

      const handleMouseMove = (e: MouseEvent) => {
        if (!resizeRef.current) return;

        const { panelIndex, startX, startWidths } = resizeRef.current;
        const delta = e.clientX - startX;

        const leftPanel = visiblePanels[panelIndex];
        const rightPanel = visiblePanels[panelIndex + 1];

        const leftMinWidth = leftPanel?.minWidth || 150;
        const rightMinWidth = rightPanel?.minWidth || 150;

        const newLeftWidth = Math.max(startWidths[panelIndex] + delta, leftMinWidth);
        const newRightWidth = Math.max(startWidths[panelIndex + 1] - delta, rightMinWidth);

        // Only apply if both are above minimum
        if (newLeftWidth >= leftMinWidth && newRightWidth >= rightMinWidth) {
          const newWidths = [...startWidths];
          newWidths[panelIndex] = newLeftWidth;
          newWidths[panelIndex + 1] = newRightWidth;
          setWidths(newWidths);
        }
      };

      const handleMouseUp = () => {
        resizeRef.current = null;
        document.removeEventListener('mousemove', handleMouseMove);
        document.removeEventListener('mouseup', handleMouseUp);
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
      };

      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
    },
    [widths, visiblePanels]
  );

  if (visiblePanels.length === 0) {
    return (
      <Box
        sx={{
          height,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'text.disabled',
          bgcolor: 'background.paper',
          borderRadius: 1,
          border: '1px dashed',
          borderColor: 'divider',
        }}
      >
        <Typography variant="body2">Select panels to display</Typography>
      </Box>
    );
  }

  return (
    <Box
      ref={containerRef}
      sx={{
        height,
        display: 'flex',
        gap: 0,
        overflow: 'hidden',
      }}
    >
      {visiblePanels.map((panel, idx) => (
        <React.Fragment key={panel.id}>
          {/* Panel */}
          <Box
            sx={{
              width: widths[idx] || 'auto',
              minWidth: panel.minWidth || 150,
              display: 'flex',
              flexDirection: 'column',
              bgcolor: 'background.paper',
              borderRadius: 1,
              border: '1px solid',
              borderColor: 'divider',
              overflow: 'hidden',
              flexShrink: idx === visiblePanels.length - 1 ? 1 : 0,
              flexGrow: idx === visiblePanels.length - 1 ? 1 : 0,
            }}
          >
            {/* Panel header */}
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                px: 1,
                py: 0.5,
                borderBottom: '1px solid',
                borderColor: 'divider',
                bgcolor: 'action.hover',
                minHeight: 32,
              }}
            >
              {panel.icon && (
                <Box sx={{ mr: 0.5, display: 'flex', color: 'text.secondary' }}>{panel.icon}</Box>
              )}
              <Typography
                variant="caption"
                fontWeight={600}
                color="text.secondary"
                sx={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
              >
                {panel.title}
              </Typography>
              <Tooltip title="Close panel">
                <IconButton
                  size="small"
                  onClick={() => onPanelClose(panel.id)}
                  sx={{ p: 0.25, opacity: 0.5, '&:hover': { opacity: 1 } }}
                >
                  <CloseIcon sx={{ fontSize: 14 }} />
                </IconButton>
              </Tooltip>
            </Box>

            {/* Panel content */}
            <Box sx={{ flex: 1, overflow: 'auto' }}>{panel.content}</Box>
          </Box>

          {/* Resize handle (between panels) */}
          {idx < visiblePanels.length - 1 && (
            <Box
              onMouseDown={(e) => handleMouseDown(e, idx)}
              sx={{
                width: 6,
                flexShrink: 0,
                cursor: 'col-resize',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                bgcolor: 'transparent',
                transition: 'background-color 0.15s',
                '&:hover': {
                  bgcolor: 'action.hover',
                },
                '&:active': {
                  bgcolor: 'primary.main',
                },
              }}
            >
              <DragIndicatorIcon
                sx={{
                  fontSize: 12,
                  color: 'text.disabled',
                  transform: 'rotate(90deg)',
                }}
              />
            </Box>
          )}
        </React.Fragment>
      ))}
    </Box>
  );
}

// Panel selector component for toggling panels
interface PanelSelectorProps {
  panels: { id: string; title: string; icon?: React.ReactNode }[];
  activePanels: string[];
  onToggle: (id: string) => void;
}

export function PanelSelector({ panels, activePanels, onToggle }: PanelSelectorProps) {
  return (
    <Stack direction="row" spacing={0.5} alignItems="center">
      <Typography variant="caption" color="text.disabled" sx={{ mr: 0.5 }}>
        Views:
      </Typography>
      {panels.map((panel) => {
        const isActive = activePanels.includes(panel.id);
        return (
          <Chip
            key={panel.id}
            label={panel.title}
            size="small"
            icon={panel.icon as React.ReactElement}
            onClick={() => onToggle(panel.id)}
            variant={isActive ? 'filled' : 'outlined'}
            color={isActive ? 'primary' : 'default'}
            sx={{
              height: 24,
              fontSize: '0.7rem',
              '& .MuiChip-icon': {
                fontSize: 14,
                ml: 0.5,
              },
              opacity: isActive ? 1 : 0.6,
              '&:hover': {
                opacity: 1,
              },
            }}
          />
        );
      })}
    </Stack>
  );
}

