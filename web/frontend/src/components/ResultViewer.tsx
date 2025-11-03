import { Grid, Paper, Typography } from '@mui/material';
import { FC } from 'react';
import AnalysisDetails from './AnalysisDetails';
import AnalysisSummary from './AnalysisSummary';
import type { AnalysisResultPayload, ComplexityLevel } from '../types';

interface ResultViewerProps {
  result: AnalysisResultPayload | null;
  complexity: ComplexityLevel;
}

const ResultViewer: FC<ResultViewerProps> = ({ result, complexity }) => {
  if (!result) {
    return (
      <Paper variant="outlined" sx={{ p: 4, textAlign: 'center', color: 'text.secondary' }}>
        <Typography variant="h6" gutterBottom>
          Awaiting analysis
        </Typography>
        <Typography variant="body2">Results will appear once the pipeline completes.</Typography>
      </Paper>
    );
  }

  return (
    <Grid container spacing={2}>
      <Grid item xs={12}>
        <AnalysisSummary analysis={result} complexity={complexity} />
      </Grid>
      <Grid item xs={12}>
        <AnalysisDetails analysis={result} complexity={complexity} />
      </Grid>
    </Grid>
  );
};

export default ResultViewer;
