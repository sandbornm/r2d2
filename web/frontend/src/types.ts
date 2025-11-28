export type ProgressEventName =
  | 'analysis_started'
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
  session_id?: string;
  trajectory_id?: string;
}

export interface ProgressEventEntry {
  id: string;
  event: ProgressEventName;
  data: ProgressEventPayload;
  timestamp: number;
}

export interface AnalysisPlanPayload {
  quick: boolean;
  deep: boolean;
  run_angr: boolean;
  persist_trajectory: boolean;
}

export interface AnalysisResultPayload {
  binary: string;
  plan: AnalysisPlanPayload;
  quick_scan: Record<string, unknown>;
  deep_scan: Record<string, unknown>;
  notes: string[];
  issues: string[];
  session_id?: string;
  trajectory_id?: string;
}

export interface HealthStatus {
  status: 'ok' | 'error';
  model: string;
  ghidra_ready: boolean;
}

export interface ApiAnalysisResponse {
  job_id: string;
  session_id: string;
}

export interface ChatAttachment {
  type: string;
  [key: string]: unknown;
}

export interface ChatMessageItem {
  message_id: string;
  session_id: string;
  role: 'system' | 'user' | 'assistant';
  content: string;
  attachments: ChatAttachment[];
  created_at: string;
}

export interface ChatSessionSummary {
  session_id: string;
  binary_path: string;
  trajectory_id?: string | null;
  title?: string | null;
  created_at: string;
  updated_at: string;
  message_count: number;
}

export interface ChatDetailResponse {
  session: ChatSessionSummary;
  messages: ChatMessageItem[];
}

export interface ChatPostResponse {
  session: ChatSessionSummary;
  messages: ChatMessageItem[];
  message: ChatMessageItem;
  assistant?: ChatMessageItem;
  provider?: string | null;
  error?: string;
}
