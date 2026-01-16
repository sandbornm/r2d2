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
  provider?: string;
  available_models?: string[];
  model_names?: Record<string, string>;
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

// Assembly annotation for persisting notes on disassembly lines
export interface AssemblyAnnotation {
  address: string;
  note: string;
  createdAt: string;
}

// Function naming types for LLM-suggested or human-overridden names
export interface FunctionName {
  id: string;
  address: string;
  originalName: string;
  displayName: string;
  reasoning?: string;
  confidence?: number;
  source: 'llm' | 'user';
  createdAt: string;
  updatedAt: string;
}

export interface FunctionNameSuggestion {
  address: string;
  name: string;
  confidence: number;
  reasoning: string;
}

export interface SuggestNamesResponse {
  suggestions: FunctionNameSuggestion[];
  provider?: string;
  message?: string;
  error?: string;
}

// Compiler-related types
export interface CompileResult {
  success: boolean;
  stdout: string;
  stderr: string;
  command: string;
  return_code: number;
  architecture: string;
  compiler: string;
  output_path?: string;
  output_name?: string;
  assembly?: string;
  asm_path?: string;
  asm_name?: string;
}

export interface CompilerInfo {
  name: string;
  path: string;
  version: string;
  is_clang: boolean;
}

export interface CompilersResponse {
  compilers: Record<string, CompilerInfo[]>;
  available_architectures: string[];
  error?: string;
}

// Activity tracking types for context engineering
export type ActivityEventType =
  | 'tab_switch'
  | 'function_view'
  | 'address_hover'
  | 'code_select'
  | 'annotation_add'
  | 'search_query'
  | 'cfg_navigate'
  | 'disassembly_scroll'
  | 'ask_claude'
  | 'dwarf_view'          // Viewing DWARF panel
  | 'dwarf_function_view' // Viewing a specific DWARF function
  | 'dwarf_type_view'     // Viewing a specific DWARF type
  | 'dwarf_ask_claude';   // Asking Claude about DWARF info

export interface ActivityEvent {
  event_id?: string;
  event_type: ActivityEventType;
  event_data: Record<string, unknown>;
  created_at: string;
  duration_ms?: number;  // Time spent on this activity
}

export interface ActivityContext {
  recent_events: ActivityEvent[];
  current_tab: string;
  last_viewed_function?: string;
  last_viewed_address?: string;
  session_duration_ms: number;
  event_count: number;
}

// Code citation for linking LLM responses to disassembly
export interface CodeCitation {
  address: string;
  function_name?: string;
  instruction?: string;
  bytes?: string;
  context_lines?: string[];  // Surrounding disassembly lines
}

// DWARF debug information types
export interface DWARFFunction {
  name: string;
  offset: number;
  low_pc: number | null;
  high_pc: number | null;
  size?: number;
  is_external: boolean;
  is_inline: boolean;
  decl_file?: number;
  decl_line?: number;
  parameters: DWARFParameter[];
  local_variables: DWARFVariable[];
}

export interface DWARFParameter {
  name: string;
  offset: number;
  type_offset?: number;
  location?: string;
}

export interface DWARFVariable {
  name: string;
  offset: number;
  is_local: boolean;
  type_offset?: number;
  decl_file?: number;
  decl_line?: number;
  location?: string;
  is_external: boolean;
}

export interface DWARFType {
  name?: string;
  offset: number;
  tag: string;
  byte_size?: number;
  encoding?: number;
  base_type_offset?: number;
  members?: DWARFTypeMember[];
  enumerators?: DWARFEnumerator[];
}

export interface DWARFTypeMember {
  name?: string;
  offset?: number;
  type_offset?: number;
}

export interface DWARFEnumerator {
  name?: string;
  value?: number;
}

export interface DWARFCompilationUnit {
  offset: number;
  version?: number;
  unit_length?: number;
  name?: string;
  producer?: string;
  language?: number;
  comp_dir?: string;
  source_files: string[];
  functions: DWARFFunction[];
  variables: DWARFVariable[];
  types: DWARFType[];
}

export interface DWARFLineEntry {
  address: number;
  file: number;
  line: number;
  column: number;
  is_stmt: boolean;
  end_sequence: boolean;
}

export interface DWARFLineProgram {
  cu_offset: number;
  entries: DWARFLineEntry[];
  total_entries: number;
}

export interface DWARFData {
  has_dwarf: boolean;
  dwarf_version?: number;
  compilation_units: DWARFCompilationUnit[];
  functions: DWARFFunction[];
  variables: DWARFVariable[];
  types: DWARFType[];
  source_files: string[];
  line_programs: DWARFLineProgram[];
  error?: string;
}
