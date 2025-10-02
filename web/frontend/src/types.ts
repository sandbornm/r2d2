export type ProgressEventName =
  | 'job_started'
  | 'adapter_started'
  | 'adapter_completed'
  | 'adapter_failed'
  | 'adapter_skipped'
  | 'stage_started'
  | 'stage_completed'
  | 'analysis_result'
  | 'job_completed'
  | 'job_failed';

export interface ProgressEventPayload {
  stage?: string;
  adapter?: string;
  payload?: unknown;
  error?: string;
  reason?: string;
  binary?: string;
  issues?: string[];
  notes?: string[];
}

export interface ProgressEventEntry {
  id: string;
  event: ProgressEventName;
  data: ProgressEventPayload;
  timestamp: number;
}

export interface AnalysisResultSummary {
  quick_scan: Record<string, unknown>;
  deep_scan: Record<string, unknown>;
  notes: string[];
  issues: string[];
}

export interface HealthStatus {
  status: 'ok' | 'error';
  model: string;
  ghidra_ready: boolean;
}

export interface ApiAnalysisResponse {
  job_id: string;
}
