import CodeIcon from '@mui/icons-material/Code';
import FunctionsIcon from '@mui/icons-material/Functions';
import StorageIcon from '@mui/icons-material/Storage';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Chip,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import { FC, useMemo } from 'react';
import type { AnalysisResultPayload, ComplexityLevel } from '../types';

interface AnalysisDetailsProps {
  analysis: AnalysisResultPayload | null;
  complexity: ComplexityLevel;
}

interface FunctionRow {
  name: string;
  offset: string;
  size: string;
}

const renderJson = (data: unknown) => JSON.stringify(data, null, 2);

export const AnalysisDetails: FC<AnalysisDetailsProps> = ({ analysis, complexity }) => {
  const functionRows = useMemo<FunctionRow[]>(() => {
    if (!analysis) {
      return [];
    }
    const functions = (analysis.deep_scan.radare2 as Record<string, unknown>)?.['functions'];
    if (!Array.isArray(functions)) {
      return [];
    }
    return functions.slice(0, complexity === 'expert' ? 100 : 20).map((fn) => {
      const record = (fn as Record<string, unknown>) ?? {};
      const name = String(record.name ?? 'sub');
      const offset = typeof record.offset === 'number' ? `0x${record.offset.toString(16)}` : String(record.offset ?? '?');
      const size = typeof record.size === 'number' ? `${record.size} bytes` : String(record.size ?? '?');
      return { name, offset, size };
    });
  }, [analysis, complexity]);

  if (!analysis) {
    return null;
  }

  return (
    <Stack spacing={2}>
      {functionRows.length > 0 && (
        <Paper variant="outlined" sx={{ p: 2.5 }}>
          <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5 }}>
            <FunctionsIcon color="secondary" />
            <Typography variant="h6">Hot functions</Typography>
            <Chip label={`${functionRows.length} shown`} size="small" />
          </Stack>

          <Table size="small" sx={{ '& td, & th': { borderColor: 'rgba(255,255,255,0.08)' } }}>
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Offset</TableCell>
                <TableCell>Size</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {functionRows.map((row) => (
                <TableRow key={`${row.name}-${row.offset}`}>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{row.name}</TableCell>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{row.offset}</TableCell>
                  <TableCell>{row.size}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      )}

      {complexity !== 'beginner' && (
        <Paper variant="outlined" sx={{ p: 2.5 }}>
          <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5 }}>
            <StorageIcon color="primary" />
            <Typography variant="h6">Resource tree snapshot</Typography>
          </Stack>
          <Typography variant="body2" color="text.secondary">
            Trajectory ID: {analysis.trajectory_id ?? 'N/A'}
          </Typography>
          <Typography variant="body2" sx={{ mt: 1 }}>
            Plan: quick={analysis.plan.quick ? 'yes' : 'no'}, deep={analysis.plan.deep ? 'yes' : 'no'}, angr=
            {analysis.plan.run_angr ? 'enabled' : 'disabled'}
          </Typography>
        </Paper>
      )}

      {complexity === 'expert' && (
        <Box>
          <Accordion defaultExpanded disableGutters>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Stack direction="row" spacing={1} alignItems="center">
                <CodeIcon color="primary" />
                <Typography variant="subtitle1">Quick scan payload</Typography>
              </Stack>
            </AccordionSummary>
            <AccordionDetails>
              <Typography component="pre" sx={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                {renderJson(analysis.quick_scan)}
              </Typography>
            </AccordionDetails>
          </Accordion>
          <Accordion disableGutters>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Stack direction="row" spacing={1} alignItems="center">
                <CodeIcon color="secondary" />
                <Typography variant="subtitle1">Deep scan payload</Typography>
              </Stack>
            </AccordionSummary>
            <AccordionDetails>
              <Typography component="pre" sx={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                {renderJson(analysis.deep_scan)}
              </Typography>
            </AccordionDetails>
          </Accordion>
        </Box>
      )}
    </Stack>
  );
};

export default AnalysisDetails;
