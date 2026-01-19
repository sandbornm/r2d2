/**
 * Activity tracking context for backend synchronization.
 *
 * This is a lightweight context that tracks user events and syncs them to the backend.
 * The primary user activity tracking for LLM context is handled by TrajectoryContext.
 * This context focuses on:
 * - Backend synchronization of events
 * - Simple event tracking for analytics
 */
import { createContext, FC, ReactNode, useCallback, useContext, useRef, useState } from 'react';
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

const MAX_EVENTS = 100;
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

  const trackEvent = useCallback((type: ActivityEventType, data: Record<string, unknown> = {}) => {
    const event: ActivityEvent = {
      event_type: type,
      event_data: data,
      created_at: new Date().toISOString(),
    };

    setState(prev => {
      const events = [...prev.events, event];
      if (events.length > MAX_EVENTS) events.shift();
      return { ...prev, events };
    });

    pendingEventsRef.current.push(event);
  }, []);

  const setCurrentTab = useCallback((tab: string) => {
    const duration = Date.now() - lastTabTimeRef.current;

    trackEvent('tab_switch', {
      from_tab: lastTabRef.current,
      to_tab: tab,
      time_on_previous_ms: duration,
    });

    lastTabRef.current = tab;
    lastTabTimeRef.current = Date.now();
    setState(prev => ({ ...prev, currentTab: tab }));
  }, [trackEvent]);

  const setViewedFunction = useCallback((name: string, address?: string) => {
    trackEvent('function_view', { function_name: name, address });
    setState(prev => ({
      ...prev,
      lastViewedFunction: name,
      lastViewedAddress: address ?? prev.lastViewedAddress,
    }));
  }, [trackEvent]);

  const setViewedAddress = useCallback((address: string) => {
    trackEvent('address_hover', { address });
    setState(prev => ({ ...prev, lastViewedAddress: address }));
  }, [trackEvent]);

  const getRecentContext = useCallback((limit = 20): ActivityEvent[] => {
    const cutoff = Date.now() - RECENT_WINDOW_MS;
    return state.events
      .filter(e => new Date(e.created_at).getTime() > cutoff)
      .slice(-limit);
  }, [state.events]);

  const getContextSummary = useCallback((): string => {
    const recent = getRecentContext(15);
    if (recent.length === 0) return 'User just started the session.';

    const sessionDuration = Math.floor((Date.now() - state.sessionStartTime) / 1000);
    const lines = [
      `Session duration: ${formatDuration(sessionDuration)}`,
      `Current view: ${state.currentTab}`,
    ];

    if (state.lastViewedFunction) {
      lines.push(`Last viewed function: ${state.lastViewedFunction}`);
    }
    if (state.lastViewedAddress) {
      lines.push(`Last viewed address: ${state.lastViewedAddress}`);
    }

    const recentFive = recent.slice(-5);
    if (recentFive.length > 0) {
      lines.push('\nRecent activity:');
      recentFive.forEach(event => {
        lines.push(`  - ${formatTimeAgo(event.created_at)}: ${describeEvent(event)}`);
      });
    }

    return lines.join('\n');
  }, [state, getRecentContext]);

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
    } catch {
      pendingEventsRef.current = [...events, ...pendingEventsRef.current];
    }
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
    case 'dwarf_view':
      return `Opened DWARF debug info panel`;
    case 'dwarf_function_view':
      return `Viewed DWARF function ${data.function_name || 'unknown'}`;
    case 'dwarf_type_view':
      return `Viewed DWARF type ${data.type_name || 'unknown'}`;
    case 'dwarf_ask_claude':
      return `Asked Claude about DWARF ${data.topic || 'info'}`;
    default:
      return event.event_type;
  }
}

export default ActivityContext;

