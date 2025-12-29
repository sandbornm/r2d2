/**
 * Activity tracking context for context engineering.
 * 
 * Tracks user activities (tab visits, function views, selections, etc.)
 * and provides this context to the LLM for better responses.
 */
import { createContext, FC, ReactNode, useCallback, useContext, useEffect, useRef, useState } from 'react';
import type { ActivityEvent, ActivityEventType } from '../types';

interface ActivityContextState {
  events: ActivityEvent[];
  currentTab: string;
  lastViewedFunction: string | null;
  lastViewedAddress: string | null;
  sessionStartTime: number;
}

interface ActivityContextValue extends ActivityContextState {
  trackEvent: (type: ActivityEventType, data?: Record<string, unknown>) => void;
  setCurrentTab: (tab: string) => void;
  setViewedFunction: (name: string, address?: string) => void;
  setViewedAddress: (address: string) => void;
  getRecentContext: (limit?: number) => ActivityEvent[];
  getContextSummary: () => string;
  syncToBackend: (sessionId: string) => Promise<void>;
}

const ActivityContext = createContext<ActivityContextValue | null>(null);

// Maximum events to keep in memory
const MAX_EVENTS = 100;
// Time window for "recent" events (5 minutes)
const RECENT_WINDOW_MS = 5 * 60 * 1000;

export const ActivityProvider: FC<{ children: ReactNode }> = ({ children }) => {
  const [state, setState] = useState<ActivityContextState>({
    events: [],
    currentTab: 'results',
    lastViewedFunction: null,
    lastViewedAddress: null,
    sessionStartTime: Date.now(),
  });
  
  const lastTabRef = useRef<string>('results');
  const lastTabTimeRef = useRef<number>(Date.now());
  const pendingEventsRef = useRef<ActivityEvent[]>([]);

  // Track an activity event
  const trackEvent = useCallback((type: ActivityEventType, data: Record<string, unknown> = {}) => {
    const now = Date.now();
    const event: ActivityEvent = {
      event_type: type,
      event_data: data,
      created_at: new Date(now).toISOString(),
    };
    
    setState(prev => {
      const events = [...prev.events, event];
      // Keep only the last MAX_EVENTS
      if (events.length > MAX_EVENTS) {
        events.shift();
      }
      return { ...prev, events };
    });
    
    // Queue for backend sync
    pendingEventsRef.current.push(event);
  }, []);

  // Set current tab and track the switch
  const setCurrentTab = useCallback((tab: string) => {
    const now = Date.now();
    const duration = now - lastTabTimeRef.current;
    
    // Track the tab switch with duration on previous tab
    trackEvent('tab_switch', {
      from_tab: lastTabRef.current,
      to_tab: tab,
      time_on_previous_ms: duration,
    });
    
    lastTabRef.current = tab;
    lastTabTimeRef.current = now;
    
    setState(prev => ({ ...prev, currentTab: tab }));
  }, [trackEvent]);

  // Track function view
  const setViewedFunction = useCallback((name: string, address?: string) => {
    trackEvent('function_view', {
      function_name: name,
      address: address,
    });
    
    setState(prev => ({
      ...prev,
      lastViewedFunction: name,
      lastViewedAddress: address ?? prev.lastViewedAddress,
    }));
  }, [trackEvent]);

  // Track address view
  const setViewedAddress = useCallback((address: string) => {
    trackEvent('address_hover', { address });
    setState(prev => ({ ...prev, lastViewedAddress: address }));
  }, [trackEvent]);

  // Get recent events within time window
  const getRecentContext = useCallback((limit: number = 20): ActivityEvent[] => {
    const cutoff = Date.now() - RECENT_WINDOW_MS;
    return state.events
      .filter(e => new Date(e.created_at).getTime() > cutoff)
      .slice(-limit);
  }, [state.events]);

  // Generate a human-readable context summary for the LLM
  const getContextSummary = useCallback((): string => {
    const recent = getRecentContext(15);
    if (recent.length === 0) {
      return "User just started the session.";
    }

    const lines: string[] = [];
    const sessionDuration = Math.floor((Date.now() - state.sessionStartTime) / 1000);
    
    lines.push(`Session duration: ${formatDuration(sessionDuration)}`);
    lines.push(`Current view: ${state.currentTab}`);
    
    if (state.lastViewedFunction) {
      lines.push(`Last viewed function: ${state.lastViewedFunction}`);
    }
    if (state.lastViewedAddress) {
      lines.push(`Last viewed address: ${state.lastViewedAddress}`);
    }

    // Summarize activity patterns
    const tabSwitches = recent.filter(e => e.event_type === 'tab_switch');
    const functionViews = recent.filter(e => e.event_type === 'function_view');
    const codeSelects = recent.filter(e => e.event_type === 'code_select');
    const questions = recent.filter(e => e.event_type === 'ask_claude');

    if (tabSwitches.length > 0) {
      const tabs = tabSwitches.map(e => e.event_data.to_tab).filter(Boolean);
      const uniqueTabs = [...new Set(tabs)];
      if (uniqueTabs.length > 1) {
        lines.push(`Recently visited tabs: ${uniqueTabs.join(', ')}`);
      }
    }

    if (functionViews.length > 0) {
      const funcs = functionViews.map(e => e.event_data.function_name).filter(Boolean);
      const uniqueFuncs = [...new Set(funcs)].slice(-5);
      if (uniqueFuncs.length > 0) {
        lines.push(`Recently explored functions: ${uniqueFuncs.join(', ')}`);
      }
    }

    if (codeSelects.length > 0) {
      lines.push(`Selected code ${codeSelects.length} time(s) recently`);
    }

    if (questions.length > 0) {
      lines.push(`Asked ${questions.length} question(s) in this session`);
    }

    // Add recent activity timeline (last 5 events)
    const recentFive = recent.slice(-5);
    if (recentFive.length > 0) {
      lines.push('\nRecent activity:');
      for (const event of recentFive) {
        const ago = formatTimeAgo(event.created_at);
        lines.push(`  - ${ago}: ${describeEvent(event)}`);
      }
    }

    return lines.join('\n');
  }, [state, getRecentContext]);

  // Sync pending events to backend
  const syncToBackend = useCallback(async (sessionId: string) => {
    const events = pendingEventsRef.current;
    if (events.length === 0 || !sessionId) return;
    
    pendingEventsRef.current = [];
    
    try {
      await fetch(`/api/chats/${sessionId}/activities`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ events }),
      });
    } catch (error) {
      // Re-queue events on failure
      pendingEventsRef.current = [...events, ...pendingEventsRef.current];
      console.warn('Failed to sync activity events:', error);
    }
  }, []);

  // Auto-sync every 30 seconds
  useEffect(() => {
    // We need sessionId from outside - this will be called manually
    // when sending messages
  }, []);

  const value: ActivityContextValue = {
    ...state,
    trackEvent,
    setCurrentTab,
    setViewedFunction,
    setViewedAddress,
    getRecentContext,
    getContextSummary,
    syncToBackend,
  };

  return (
    <ActivityContext.Provider value={value}>
      {children}
    </ActivityContext.Provider>
  );
};

export const useActivity = (): ActivityContextValue => {
  const context = useContext(ActivityContext);
  if (!context) {
    throw new Error('useActivity must be used within an ActivityProvider');
  }
  return context;
};

// Helper functions
function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

function formatTimeAgo(isoString: string): string {
  const seconds = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
  if (seconds < 10) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

function describeEvent(event: ActivityEvent): string {
  const data = event.event_data;
  switch (event.event_type) {
    case 'tab_switch':
      return `Switched to ${data.to_tab} tab`;
    case 'function_view':
      return `Viewed function ${data.function_name || 'unknown'}`;
    case 'address_hover':
      return `Examined address ${data.address}`;
    case 'code_select':
      return `Selected ${data.line_count || '?'} lines of code`;
    case 'annotation_add':
      return `Added annotation at ${data.address}`;
    case 'search_query':
      return `Searched for "${data.query}"`;
    case 'cfg_navigate':
      return `Navigated CFG to ${data.block || data.function || 'block'}`;
    case 'disassembly_scroll':
      return `Scrolled to ${data.address || 'new position'}`;
    case 'ask_claude':
      return `Asked about ${data.topic || 'code'}`;
    default:
      return event.event_type;
  }
}

export default ActivityContext;

