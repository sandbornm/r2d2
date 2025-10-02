import { FormEvent, useEffect, useRef, useState } from 'react';
import ProgressLog from './components/ProgressLog';
import ResultViewer from './components/ResultViewer';
import type {
  ApiAnalysisResponse,
  HealthStatus,
  ProgressEventEntry,
  ProgressEventName,
  ProgressEventPayload,
} from './types';

const EVENT_NAMES: ProgressEventName[] = [
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

const App = () => {
  const [binaryPath, setBinaryPath] = useState('');
  const [status, setStatus] = useState<JobStatus>('idle');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [events, setEvents] = useState<ProgressEventEntry[]>([]);
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [health, setHealth] = useState<HealthStatus | null>(null);

  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    fetch('/api/health')
      .then((response) => response.json())
      .then((data: HealthStatus) => {
        setHealth(data);
      })
      .catch(() => {
        setHealth({ status: 'error', model: 'unknown', ghidra_ready: false });
      });

    return () => {
      if (sourceRef.current) {
        sourceRef.current.close();
      }
    };
  }, []);

  const recordEvent = (event: ProgressEventName, data: ProgressEventPayload) => {
    setEvents((prev) => [
      ...prev,
      {
        id: `${event}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        event,
        data,
        timestamp: Date.now(),
      },
    ]);
  };

  const handleSubmit = async (evt: FormEvent) => {
    evt.preventDefault();
    if (!binaryPath.trim()) {
      setStatus('error');
      setStatusMessage('Provide a path to the binary you want to analyze.');
      return;
    }

    setStatus('running');
    setStatusMessage('Dispatching analysis job...');
    setEvents([]);
    setResult(null);

    if (sourceRef.current) {
      sourceRef.current.close();
      sourceRef.current = null;
    }

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ binary: binaryPath }),
      });

      if (!response.ok) {
        const errorBody = await response.json();
        throw new Error(errorBody.error ?? 'Request failed');
      }

      const data: ApiAnalysisResponse = await response.json();
      const source = new EventSource(`/api/jobs/${data.job_id}/stream`);
      sourceRef.current = source;

      EVENT_NAMES.forEach((name) => {
        source.addEventListener(name, (event) => {
          const message = event as MessageEvent<string>;
          const payload = message.data ? (JSON.parse(message.data) as ProgressEventPayload) : {};
          recordEvent(name, payload);

          if (name === 'analysis_result') {
            setResult(payload as Record<string, unknown>);
          }

          if (name === 'job_failed') {
            setStatus('error');
            setStatusMessage(payload.error ?? 'Analysis failed');
            source.close();
            sourceRef.current = null;
          }

          if (name === 'job_completed') {
            setStatus('done');
            setStatusMessage('Analysis completed successfully.');
            source.close();
            sourceRef.current = null;
          }
        });
      });

      source.onerror = () => {
        setStatus('error');
        setStatusMessage('Connection lost while streaming progress.');
        source.close();
        sourceRef.current = null;
      };
    } catch (error) {
      setStatus('error');
      setStatusMessage(error instanceof Error ? error.message : 'Failed to start analysis');
    }
  };

  const statusTone =
    status === 'running' ? 'info' : status === 'error' ? 'error' : status === 'done' ? 'ok' : 'info';

  return (
    <div className="app-shell">
      <header className="header">
        <h1>r2d2 analyzer</h1>
        <p>
          Kick off binary analysis, watch adapters report progress, and review quick/deep payloads with
          LLM-ready context.
        </p>
      </header>

      <section className="card">
        <form className="form" onSubmit={handleSubmit}>
          <label htmlFor="binary">Binary path</label>
          <input
            id="binary"
            type="text"
            placeholder="/path/to/binary"
            value={binaryPath}
            onChange={(event) => setBinaryPath(event.target.value)}
            autoComplete="off"
          />
          <button type="submit">Analyze</button>
        </form>

        {statusMessage && (
          <div className="status-banner" data-status={statusTone}>
            {statusMessage}
          </div>
        )}

        {health && (
          <div className="badges" style={{ marginTop: '16px' }}>
            <span className="badge" data-tone={health.status === 'ok' ? 'ok' : 'warn'}>
              Model: {health.model}
            </span>
            <span className="badge" data-tone={health.ghidra_ready ? 'ok' : 'warn'}>
              Ghidra ready: {health.ghidra_ready ? 'yes' : 'no'}
            </span>
          </div>
        )}
      </section>

      <section className="card">
        <h2>Progress</h2>
        <ProgressLog entries={events} />
      </section>

      <section className="card">
        <h2>Result</h2>
        <ResultViewer result={result} />
      </section>

      <footer>
        Powered by r2d2 • Streams quick + deep analysis stages with the `gpt-5-mini-2025-08-07` LLM on demand.
      </footer>
    </div>
  );
};

export default App;
