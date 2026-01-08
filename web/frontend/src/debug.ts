/**
 * Debug logging system for r2d2 frontend
 *
 * Provides structured logging for user activity tracking and debugging.
 * Enabled by default, can be toggled via localStorage or environment variable.
 */

// Check if debug mode is enabled (default: true)
const isDebugEnabled = (): boolean => {
  // Check localStorage override first
  const storedValue = localStorage.getItem('r2d2_debug');
  if (storedValue !== null) {
    return storedValue === 'true';
  }
  // Default to enabled
  return true;
};

// Log levels
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  category: string;
  message: string;
  data?: unknown;
}

// Color coding for different categories
const categoryColors: Record<string, string> = {
  activity: '#22c55e',    // green - user activity
  api: '#3b82f6',         // blue - API calls
  cfg: '#f59e0b',         // amber - CFG viewer
  chat: '#8b5cf6',        // purple - chat interactions
  session: '#ec4899',     // pink - session management
  error: '#ef4444',       // red - errors
  system: '#6b7280',      // gray - system events
};

// Log storage for debugging and export
const logHistory: LogEntry[] = [];
const MAX_LOG_HISTORY = 1000;

// Format timestamp
const formatTimestamp = (): string => {
  return new Date().toISOString();
};

// Core logging function
const log = (level: LogLevel, category: string, message: string, data?: unknown): void => {
  if (!isDebugEnabled()) return;

  const entry: LogEntry = {
    timestamp: formatTimestamp(),
    level,
    category,
    message,
    data,
  };

  // Store in history
  logHistory.push(entry);
  if (logHistory.length > MAX_LOG_HISTORY) {
    logHistory.shift();
  }

  // Console output with styling
  const color = categoryColors[category] || '#6b7280';
  const levelEmoji = {
    debug: '🔍',
    info: 'ℹ️',
    warn: '⚠️',
    error: '❌',
  }[level];

  const style = `color: ${color}; font-weight: bold;`;
  const prefix = `[r2d2] ${levelEmoji} [${category.toUpperCase()}]`;

  if (data !== undefined) {
    console.groupCollapsed(`%c${prefix} ${message}`, style);
    console.log('Data:', data);
    console.log('Time:', entry.timestamp);
    console.groupEnd();
  } else {
    console.log(`%c${prefix} ${message}`, style);
  }
};

// Public API
export const debug = {
  // Enable/disable debug mode
  enable: () => {
    localStorage.setItem('r2d2_debug', 'true');
    console.log('%c[r2d2] Debug mode ENABLED', 'color: #22c55e; font-weight: bold;');
  },

  disable: () => {
    localStorage.setItem('r2d2_debug', 'false');
    console.log('%c[r2d2] Debug mode DISABLED', 'color: #ef4444; font-weight: bold;');
  },

  isEnabled: isDebugEnabled,

  // Activity logging (user interactions)
  activity: {
    tabSwitch: (from: string, to: string) => {
      log('info', 'activity', `Tab switch: ${from} → ${to}`, { from, to });
    },
    functionView: (functionName: string, address: string) => {
      log('info', 'activity', `Viewing function: ${functionName}`, { functionName, address });
    },
    addressHover: (address: string, context?: string) => {
      log('debug', 'activity', `Hover: ${address}`, { address, context });
    },
    codeSelect: (selection: string, range?: { start: number; end: number }) => {
      log('debug', 'activity', `Code selected`, { selection: selection.slice(0, 100), range });
    },
    searchQuery: (query: string, resultCount?: number) => {
      log('info', 'activity', `Search: "${query}"`, { query, resultCount });
    },
    annotationAdd: (address: string, note: string) => {
      log('info', 'activity', `Annotation added at ${address}`, { address, note: note.slice(0, 50) });
    },
  },

  // API call logging
  api: {
    request: (method: string, url: string, body?: unknown) => {
      log('info', 'api', `${method} ${url}`, { method, url, body });
    },
    response: (url: string, status: number, data?: unknown) => {
      const level = status >= 400 ? 'error' : 'info';
      log(level, 'api', `Response ${status} from ${url}`, { status, data });
    },
    error: (url: string, error: unknown) => {
      log('error', 'api', `API error: ${url}`, { url, error });
    },
  },

  // CFG viewer logging
  cfg: {
    functionSelect: (functionName: string, offset: string) => {
      log('info', 'cfg', `Selected function: ${functionName}`, { functionName, offset });
    },
    blockSelect: (blockOffset: string) => {
      log('info', 'cfg', `Selected block: ${blockOffset}`, { blockOffset });
    },
    zoom: (level: number, action: 'in' | 'out' | 'wheel' | 'fit') => {
      log('debug', 'cfg', `Zoom ${action}: ${level.toFixed(2)}`, { level, action });
    },
    maximize: (isMaximized: boolean) => {
      log('info', 'cfg', `Maximize: ${isMaximized}`, { isMaximized });
    },
    autoName: (functionCount: number, status: 'start' | 'complete' | 'error', error?: string) => {
      log('info', 'cfg', `Auto-name ${status}: ${functionCount} functions`, { functionCount, status, error });
    },
    askClaude: (context: unknown) => {
      log('info', 'cfg', 'Ask Claude about CFG', context);
    },
  },

  // Chat logging
  chat: {
    send: (sessionId: string, messagePreview: string) => {
      log('info', 'chat', `Sending message to ${sessionId}`, { sessionId, preview: messagePreview.slice(0, 100) });
    },
    receive: (sessionId: string, role: string) => {
      log('info', 'chat', `Received ${role} message in ${sessionId}`, { sessionId, role });
    },
    error: (sessionId: string, error: string) => {
      log('error', 'chat', `Chat error in ${sessionId}: ${error}`, { sessionId, error });
    },
  },

  // Session management logging
  session: {
    create: (sessionId: string, binaryPath: string) => {
      log('info', 'session', `Created session: ${sessionId}`, { sessionId, binaryPath });
    },
    load: (sessionId: string) => {
      log('info', 'session', `Loaded session: ${sessionId}`, { sessionId });
    },
    delete: (sessionId: string) => {
      log('info', 'session', `Deleted session: ${sessionId}`, { sessionId });
    },
    switch: (fromId: string | null, toId: string) => {
      log('info', 'session', `Session switch: ${fromId || 'none'} → ${toId}`, { fromId, toId });
    },
  },

  // System logging
  system: {
    init: () => {
      log('info', 'system', 'r2d2 frontend initialized');
    },
    analysisStart: (binary: string, options: unknown) => {
      log('info', 'system', `Analysis started: ${binary}`, options);
    },
    analysisComplete: (binary: string, duration?: number) => {
      log('info', 'system', `Analysis complete: ${binary}`, { binary, duration });
    },
    error: (message: string, error?: unknown) => {
      log('error', 'error', message, error);
    },
  },

  // Direct logging methods
  log: (message: string, data?: unknown) => log('info', 'system', message, data),
  warn: (message: string, data?: unknown) => log('warn', 'system', message, data),
  error: (message: string, data?: unknown) => log('error', 'error', message, data),

  // Export log history
  getHistory: () => [...logHistory],

  // Export to JSON
  exportLogs: () => {
    const json = JSON.stringify(logHistory, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `r2d2-logs-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
    log('info', 'system', 'Logs exported');
  },

  // Clear log history
  clear: () => {
    logHistory.length = 0;
    console.clear();
    console.log('%c[r2d2] Log history cleared', 'color: #6b7280;');
  },
};

// Expose to window for console access
if (typeof window !== 'undefined') {
  (window as unknown as Record<string, unknown>).r2d2Debug = debug;
}

export default debug;
