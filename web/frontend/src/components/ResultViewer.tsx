import { FC } from 'react';

interface ResultViewerProps {
  result: Record<string, unknown> | null;
}

const ResultViewer: FC<ResultViewerProps> = ({ result }) => {
  if (!result) {
    return (
      <div className="empty-state">
        <strong>No analysis yet</strong>
        <span>Results will appear here once the job completes.</span>
      </div>
    );
  }

  const quick = (result.quick_scan ?? {}) as Record<string, unknown>;
  const deep = (result.deep_scan ?? {}) as Record<string, unknown>;
  const notes = (result.notes ?? []) as string[];
  const issues = (result.issues ?? []) as string[];

  return (
    <div className="result-grid">
      <section className="result-section">
        <h3>Quick scan</h3>
        <pre>{JSON.stringify(quick, null, 2)}</pre>
      </section>

      <section className="result-section">
        <h3>Deep scan</h3>
        <pre>{JSON.stringify(deep, null, 2)}</pre>
      </section>

      <section className="result-section">
        <h3>Notes & Issues</h3>
        <div className="badges">
          {issues.map((issue) => (
            <span key={issue} className="badge" data-tone="warn">
              ⚠ {issue}
            </span>
          ))}
          {notes.map((note) => (
            <span key={note} className="badge" data-tone="info">
              ℹ {note}
            </span>
          ))}
          {!notes.length && !issues.length && <span>No notes recorded.</span>}
        </div>
      </section>
    </div>
  );
};

export default ResultViewer;
