import { FC } from 'react';
import type { ProgressEventEntry } from '../types';

interface ProgressLogProps {
  entries: ProgressEventEntry[];
}

const LABELS: Record<string, string> = {
  job_started: 'Job started',
  adapter_started: 'Adapter started',
  adapter_completed: 'Adapter completed',
  adapter_failed: 'Adapter failed',
  adapter_skipped: 'Adapter skipped',
  stage_started: 'Stage started',
  stage_completed: 'Stage completed',
  analysis_result: 'Analysis result received',
  job_completed: 'Job completed',
  job_failed: 'Job failed',
};

export const ProgressLog: FC<ProgressLogProps> = ({ entries }) => {
  if (!entries.length) {
    return (
      <div className="empty-state">
        <strong>No progress yet</strong>
        <span>Kick off an analysis to watch adapters stream in real time.</span>
      </div>
    );
  }

  return (
    <ul className="progress-log">
      {entries.map((entry) => {
        const { event, data } = entry;
        return (
          <li key={entry.id} className="progress-entry">
            <strong>{LABELS[event] ?? event}</strong>
            <small>{new Date(entry.timestamp).toLocaleTimeString()}</small>
            <div>
              {data.stage && (
                <div>
                  <span className="badge" data-tone="info">
                    Stage: {data.stage}
                  </span>
                </div>
              )}
              {data.adapter && (
                <div>
                  <span className="badge" data-tone="ok">
                    Adapter: {data.adapter}
                  </span>
                </div>
              )}
              {data.error && (
                <div className="badge" data-tone="warn">
                  Error: {data.error}
                </div>
              )}
              {data.reason && (
                <div className="badge" data-tone="warn">
                  Skipped: {data.reason}
                </div>
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
};

export default ProgressLog;
