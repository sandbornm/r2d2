import MemoryIcon from '@mui/icons-material/Memory';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import TimelineIcon from '@mui/icons-material/Timeline';
import {
  Alert,
  Box,
  Chip,
  Paper,
  Stack,
  Tab,
  Tabs,
  Typography,
  useTheme,
} from '@mui/material';
import { FC, useState } from 'react';
import type { GEFData, GEFMemoryRegion, RegisterSnapshot } from '../types';

interface GEFPanelProps {
  data: GEFData | null;
}

const formatHex = (value: number | undefined, pad: number = 8) => {
  if (value === undefined) return '?';
  return '0x' + value.toString(16).padStart(pad, '0');
};

const RegistersView: FC<{ snapshots: RegisterSnapshot[] }> = ({ snapshots }) => {
  const theme = useTheme();
  const [selectedIndex, setSelectedIndex] = useState(snapshots.length - 1);

  if (snapshots.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary">
        No register snapshots captured
      </Typography>
    );
  }

  const snapshot = snapshots[selectedIndex] || snapshots[snapshots.length - 1];
  const registers = snapshot?.registers || {};

  // Group registers by category
  const generalRegs = Object.entries(registers).filter(([name]) =>
    /^(r\d+|x\d+|w\d+|a\d+|v\d+|t\d+|s\d+|fp|lr|ra|gp|tp)$/i.test(name)
  );
  const specialRegs = Object.entries(registers).filter(([name]) =>
    /^(pc|sp|rip|rsp|eip|esp|cpsr|pstate|flags)$/i.test(name)
  );
  const otherRegs = Object.entries(registers).filter(([name]) =>
    !generalRegs.some(([n]) => n === name) && !specialRegs.some(([n]) => n === name)
  );

  const RegisterSection: FC<{ title: string; regs: [string, number][] }> = ({ title, regs }) => {
    if (regs.length === 0) return null;
    return (
      <Box sx={{ mb: 2 }}>
        <Typography variant="caption" color="text.secondary" fontWeight={600} sx={{ mb: 0.5, display: 'block' }}>
          {title}
        </Typography>
        <Box
          sx={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))',
            gap: 0.5,
          }}
        >
          {regs.map(([name, value]) => (
            <Box
              key={name}
              sx={{
                display: 'flex',
                justifyContent: 'space-between',
                px: 1,
                py: 0.25,
                borderRadius: 0.5,
                bgcolor: theme.palette.mode === 'dark' ? 'grey.900' : 'grey.100',
                fontFamily: 'monospace',
                fontSize: '0.7rem',
              }}
            >
              <Typography variant="caption" color="text.secondary" fontFamily="monospace">
                {name}
              </Typography>
              <Typography variant="caption" fontFamily="monospace">
                {formatHex(value)}
              </Typography>
            </Box>
          ))}
        </Box>
      </Box>
    );
  };

  return (
    <Box>
      {/* Timeline slider */}
      <Box sx={{ mb: 2 }}>
        <Typography variant="caption" color="text.secondary">
          Snapshot {selectedIndex + 1} of {snapshots.length}
        </Typography>
        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mt: 0.5 }}>
          {snapshots.map((_, i) => (
            <Chip
              key={i}
              label={i + 1}
              size="small"
              variant={i === selectedIndex ? 'filled' : 'outlined'}
              color={i === selectedIndex ? 'primary' : 'default'}
              onClick={() => setSelectedIndex(i)}
              sx={{ cursor: 'pointer', minWidth: 32 }}
            />
          ))}
        </Box>
      </Box>

      {/* Program Counter and Stack Pointer */}
      <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
        <Chip label={`PC: ${formatHex(snapshot.pc)}`} color="primary" />
        <Chip label={`SP: ${formatHex(snapshot.sp)}`} color="secondary" />
      </Stack>

      <RegisterSection title="Special Registers" regs={specialRegs} />
      <RegisterSection title="General Purpose Registers" regs={generalRegs.slice(0, 32)} />
      {otherRegs.length > 0 && (
        <RegisterSection title="Other Registers" regs={otherRegs.slice(0, 16)} />
      )}
    </Box>
  );
};

const MemoryMapView: FC<{ regions: GEFMemoryRegion[] }> = ({ regions }) => {
  const theme = useTheme();

  if (regions.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary">
        No memory map information captured
      </Typography>
    );
  }

  // Permission colors
  const getPermColor = (perm: string) => {
    if (perm.includes('x')) return 'error';
    if (perm.includes('w')) return 'warning';
    if (perm.includes('r')) return 'info';
    return 'default';
  };

  return (
    <Box
      component="table"
      sx={{
        width: '100%',
        borderCollapse: 'collapse',
        fontFamily: 'monospace',
        fontSize: '0.7rem',
      }}
    >
      <thead>
        <tr>
          <th style={{ textAlign: 'left', padding: '4px 8px', borderBottom: `1px solid ${theme.palette.divider}` }}>
            Start
          </th>
          <th style={{ textAlign: 'left', padding: '4px 8px', borderBottom: `1px solid ${theme.palette.divider}` }}>
            End
          </th>
          <th style={{ textAlign: 'center', padding: '4px 8px', borderBottom: `1px solid ${theme.palette.divider}` }}>
            Perms
          </th>
          <th style={{ textAlign: 'left', padding: '4px 8px', borderBottom: `1px solid ${theme.palette.divider}` }}>
            Name
          </th>
        </tr>
      </thead>
      <tbody>
        {regions.map((region, i) => (
          <tr key={i}>
            <td style={{ padding: '4px 8px' }}>{region.start}</td>
            <td style={{ padding: '4px 8px' }}>{region.end}</td>
            <td style={{ padding: '4px 8px', textAlign: 'center' }}>
              <Chip
                label={region.permissions || '---'}
                size="small"
                color={getPermColor(region.permissions)}
                variant="outlined"
                sx={{ fontSize: '0.6rem', height: 18 }}
              />
            </td>
            <td style={{ padding: '4px 8px', color: theme.palette.text.secondary }}>
              {region.name || '-'}
            </td>
          </tr>
        ))}
      </tbody>
    </Box>
  );
};

const ExecutionSummary: FC<{ data: GEFData }> = ({ data }) => {
  const trace = data.trace;

  return (
    <Box>
      <Stack spacing={1.5}>
        {/* Entry point */}
        <Paper variant="outlined" sx={{ p: 1.5 }}>
          <Typography variant="caption" color="text.secondary" fontWeight={600}>
            Entry Point
          </Typography>
          <Typography variant="body2" fontFamily="monospace" sx={{ mt: 0.5 }}>
            {trace.entry_point || 'Unknown'}
          </Typography>
        </Paper>

        {/* Stats */}
        <Stack direction="row" spacing={1.5}>
          <Paper variant="outlined" sx={{ p: 1.5, flex: 1 }}>
            <Typography variant="caption" color="text.secondary" fontWeight={600}>
              Instructions Traced
            </Typography>
            <Typography variant="h6" sx={{ mt: 0.5 }}>
              {trace.instruction_count.toLocaleString()}
            </Typography>
          </Paper>

          <Paper variant="outlined" sx={{ p: 1.5, flex: 1 }}>
            <Typography variant="caption" color="text.secondary" fontWeight={600}>
              Register Snapshots
            </Typography>
            <Typography variant="h6" sx={{ mt: 0.5 }}>
              {trace.register_snapshots.length}
            </Typography>
          </Paper>

          <Paper variant="outlined" sx={{ p: 1.5, flex: 1 }}>
            <Typography variant="caption" color="text.secondary" fontWeight={600}>
              Exit Code
            </Typography>
            <Typography variant="h6" sx={{ mt: 0.5 }}>
              {trace.exit_code ?? data.returncode ?? '?'}
            </Typography>
          </Paper>
        </Stack>

        {/* Memory regions count */}
        <Paper variant="outlined" sx={{ p: 1.5 }}>
          <Typography variant="caption" color="text.secondary" fontWeight={600}>
            Memory Regions
          </Typography>
          <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
            <Chip
              label={`${trace.memory_maps.length} mapped`}
              size="small"
              variant="outlined"
            />
            <Chip
              label={`${trace.memory_maps.filter((r) => r.permissions.includes('x')).length} executable`}
              size="small"
              color="error"
              variant="outlined"
            />
            <Chip
              label={`${trace.memory_maps.filter((r) => r.permissions.includes('w')).length} writable`}
              size="small"
              color="warning"
              variant="outlined"
            />
          </Stack>
        </Paper>
      </Stack>
    </Box>
  );
};

type GEFViewTab = 'overview' | 'registers' | 'memory';

const GEFPanel: FC<GEFPanelProps> = ({ data }) => {
  const [view, setView] = useState<GEFViewTab>('overview');

  if (!data) {
    return (
      <Box
        sx={{
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'text.secondary',
          p: 3,
        }}
      >
        <PlayArrowIcon sx={{ fontSize: 40, mb: 1.5, opacity: 0.4 }} />
        <Typography variant="body2">No dynamic analysis data</Typography>
        <Typography variant="caption" color="text.secondary" sx={{ textAlign: 'center', mt: 1 }}>
          Enable GEF in config and build the Docker image to trace binary execution
        </Typography>
      </Box>
    );
  }

  if (data.error) {
    return (
      <Box sx={{ p: 2 }}>
        <Alert severity="error">
          Dynamic analysis failed: {data.error}
        </Alert>
      </Box>
    );
  }

  const trace = data.trace;

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <Box sx={{ p: 1, borderBottom: 1, borderColor: 'divider' }}>
        <Stack direction="row" alignItems="center" justifyContent="space-between">
          <Typography variant="body2" fontWeight={600}>
            Dynamic Analysis
          </Typography>
          <Stack direction="row" spacing={0.5}>
            <Chip
              label={`${trace.instruction_count.toLocaleString()} instr`}
              size="small"
              color="primary"
              variant="outlined"
            />
            <Chip
              label={`${trace.register_snapshots.length} snapshots`}
              size="small"
              variant="outlined"
            />
          </Stack>
        </Stack>
      </Box>

      {/* Tabs */}
      <Tabs
        value={view}
        onChange={(_, v) => setView(v)}
        sx={{ borderBottom: 1, borderColor: 'divider', minHeight: 36 }}
      >
        <Tab
          value="overview"
          label="Overview"
          icon={<PlayArrowIcon sx={{ fontSize: 16 }} />}
          iconPosition="start"
          sx={{ minHeight: 36, py: 0 }}
        />
        <Tab
          value="registers"
          label="Registers"
          icon={<TimelineIcon sx={{ fontSize: 16 }} />}
          iconPosition="start"
          sx={{ minHeight: 36, py: 0 }}
        />
        <Tab
          value="memory"
          label="Memory"
          icon={<MemoryIcon sx={{ fontSize: 16 }} />}
          iconPosition="start"
          sx={{ minHeight: 36, py: 0 }}
        />
      </Tabs>

      {/* Content */}
      <Box sx={{ flex: 1, overflow: 'auto', p: 1.5 }}>
        {view === 'overview' && <ExecutionSummary data={data} />}
        {view === 'registers' && <RegistersView snapshots={trace.register_snapshots} />}
        {view === 'memory' && <MemoryMapView regions={trace.memory_maps} />}
      </Box>
    </Box>
  );
};

export default GEFPanel;
