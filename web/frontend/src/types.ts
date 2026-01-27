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
  tool_availability?: Record<string, boolean>;  // Which tools were available during analysis
}

export interface ToolStatusInfo {
  available: boolean;
  install_hint?: string;
  description?: string;
  bridge_connected?: boolean;
  bridge_available?: boolean;
  headless_ready?: boolean;
  docker_available?: boolean;
  image_built?: boolean;
}

export interface HealthStatus {
  status: 'ok' | 'error';
  model: string;
  provider?: string;
  available_models?: string[];
  model_names?: Record<string, string>;
  ghidra_ready: boolean;
  tools?: Record<string, ToolStatusInfo>;
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

// Auto-profiling types for quick binary characterization
export interface SecurityFeatures {
  relro: 'none' | 'partial' | 'full' | 'unknown';
  stack_canary: boolean | null;
  nx: boolean | null;
  pie: boolean | null;
  fortify: boolean | null;
  rpath: boolean | null;
  runpath: boolean | null;
}

export interface EmbeddedFile {
  offset: number;
  description: string;
}

export interface AutoProfileData {
  mode: 'autoprofile';
  profile: {
    file_type: string;
    architecture: string;
    bits: number | null;
    endian: 'little' | 'big' | 'unknown';
    is_stripped: boolean | null;
    has_debug_info: boolean | null;
    security: SecurityFeatures;
    total_strings: number;
    network_strings: string[];
    crypto_strings: string[];
    file_io_strings: string[];
    dangerous_functions: string[];
    suspicious_strings: string[];
    embedded_files: EmbeddedFile[];
    has_compressed_data: boolean;
    has_encrypted_data: boolean;
    risk_level: 'low' | 'medium' | 'high';
    risk_factors: string[];
  };
  error?: string;
}

// Ghidra decompilation types
export interface GhidraDecompiledFunction {
  name: string;
  address: string;
  signature: string;
  decompiled_c: string;
  parameters: Array<{ name: string; type: string; index: number }>;
  return_type: string;
  calling_convention: string | null;
}

export interface GhidraTypeInfo {
  name: string;
  category: string;
  size: number;
  kind: 'struct' | 'enum' | 'typedef' | 'pointer' | 'array' | 'primitive';
  members: Array<{
    name: string;
    type?: string;
    offset?: number;
    size?: number;
    value?: number;
  }>;
}

export interface GhidraXref {
  from_address?: string;
  to_address?: string;
  ref_type: string;
  from_function?: string | null;
  to_function?: string | null;
}

export interface GhidraData {
  mode: 'bridge' | 'headless';
  functions?: Array<{
    name: string;
    address: number;
    size: number;
    signature?: string;
    calling_convention?: string;
    is_thunk?: boolean;
    comment?: string;
  }>;
  function_count?: number;
  decompiled: GhidraDecompiledFunction[];
  decompiled_count: number;
  types: GhidraTypeInfo[];
  type_count: number;
  strings?: Array<{
    address: number;
    value: string;
    length: number;
    type?: string;
  }>;
  string_count?: number;
  xref_map?: Record<string, { to: GhidraXref[]; from: GhidraXref[] }>;
  binary: string;
  error?: string;
}

// GEF/GDB dynamic analysis types
export interface RegisterSnapshot {
  pc: number;
  sp: number;
  registers: Record<string, number>;
}

export interface GEFMemoryRegion {
  start: string;
  end: string;
  size: string;
  offset: string;
  permissions: string;
  name: string;
}

export interface GEFExecutionTrace {
  entry_point?: string;
  register_snapshots: RegisterSnapshot[];
  memory_maps: GEFMemoryRegion[];
  instruction_count: number;
  exit_code?: number;
  error?: string;
}

export interface GEFData {
  mode: 'gef';
  binary: string;
  returncode: number;
  trace: GEFExecutionTrace;
  error?: string;
}

// Ghidra Scripting types
export interface GhidraScriptTask {
  id: string;
  description: string;
  language: 'python' | 'java';
  script: string;
  status: 'pending' | 'generating' | 'ready' | 'running' | 'completed' | 'failed';
  result?: string;
  error?: string;
  createdAt: string;
  executedAt?: string;
}

export interface GhidraScriptGenerateResponse {
  script: string;
  language: string;
  task: string;
  error?: string;
}

export interface GhidraScriptExecuteResponse {
  output: string;
  language: string;
  success: boolean;
  error?: string;
}

export interface GhidraStatusResponse {
  available: boolean;
  bridge_available: boolean;
  bridge_connected: boolean;
  bridge_program?: string | null;
  headless_available: boolean;
  install_dir?: string | null;
  issues: string[];
  notes: string[];
}

// Tool execution status types (from /api/tools/status)
export interface ToolExecutionStatus {
  available: boolean;
  description: string;
  bridge_available?: boolean;
  bridge_connected?: boolean;
  headless_available?: boolean;
}

export interface ToolsStatusResponse {
  tools: Record<string, ToolExecutionStatus>;
  available_count: number;
  total_count: number;
}
