/**
 * Trajectory Context - React integration for the trajectory tracking system.
 *
 * Provides hooks and context for tracking user actions throughout the app.
 */
import { createContext, FC, ReactNode, useCallback, useContext, useMemo, useRef, useState } from 'react';
import {
  addNode,
  createSnapshot,
  createTrajectory,
  serializeSnapshot,
  Trajectory,
  TrajectoryNodeData,
  TrajectoryNodeType,
  TrajectorySnapshot,
} from './TrajectoryStore';

interface TrajectoryContextValue {
  // Current trajectory
  trajectory: Trajectory | null;

  // Current snapshot for display
  snapshot: TrajectorySnapshot | null;

  // Start a new trajectory for a session
  startTrajectory: (sessionId: string) => void;

  // Record an action
  recordAction: (type: TrajectoryNodeType, data?: TrajectoryNodeData) => void;

  // Get serialized context for LLM
  getLLMContext: () => string;

  // Get current view
  currentView: string;

  // Set current view
  setCurrentView: (view: string) => void;

  // Clear trajectory
  clearTrajectory: () => void;
}

const TrajectoryContext = createContext<TrajectoryContextValue | null>(null);

export const TrajectoryProvider: FC<{ children: ReactNode }> = ({ children }) => {
  const [trajectory, setTrajectory] = useState<Trajectory | null>(null);
  const [currentView, setCurrentViewState] = useState<string>('results');
  const lastViewRef = useRef<string>('results');
  const viewStartTimeRef = useRef<number>(Date.now());

  const startTrajectory = useCallback((sessionId: string) => {
    const newTrajectory = createTrajectory(sessionId);
    // Add session start node
    const { trajectory: updated } = addNode(newTrajectory, 'session_start', {
      timestamp: Date.now(),
    });
    setTrajectory(updated);
  }, []);

  const recordAction = useCallback(
    (type: TrajectoryNodeType, data: TrajectoryNodeData = {}) => {
      setTrajectory((prev) => {
        if (!prev) return prev;
        const { trajectory: updated } = addNode(prev, type, data);
        return updated;
      });
    },
    []
  );

  const setCurrentView = useCallback(
    (view: string) => {
      const now = Date.now();
      const timeOnPrev = now - viewStartTimeRef.current;

      // Record view change in trajectory
      if (trajectory && lastViewRef.current !== view) {
        // Map view names to trajectory node types
        const viewTypeMap: Record<string, TrajectoryNodeType | null> = {
          disasm: 'view_disasm',
          cfg: 'view_cfg',
          decompiler: 'view_decompiled',
          strings: 'view_strings',
          security: 'view_security',
          profile: 'view_security',
          dwarf: 'view_dwarf',
          gef: 'view_dynamic',
          dynamic: 'view_dynamic',
        };

        const nodeType = viewTypeMap[view.toLowerCase()];
        if (nodeType) {
          recordAction(nodeType, {
            from_tab: lastViewRef.current,
            to_tab: view,
            time_on_previous_ms: timeOnPrev,
          });
        }
      }

      lastViewRef.current = view;
      viewStartTimeRef.current = now;
      setCurrentViewState(view);
    },
    [trajectory, recordAction]
  );

  const snapshot = useMemo(() => {
    if (!trajectory) return null;
    return createSnapshot(trajectory, currentView);
  }, [trajectory, currentView]);

  const getLLMContext = useCallback(() => {
    if (!snapshot) return '';
    return serializeSnapshot(snapshot);
  }, [snapshot]);

  const clearTrajectory = useCallback(() => {
    setTrajectory(null);
  }, []);

  const value: TrajectoryContextValue = {
    trajectory,
    snapshot,
    startTrajectory,
    recordAction,
    getLLMContext,
    currentView,
    setCurrentView,
    clearTrajectory,
  };

  return <TrajectoryContext.Provider value={value}>{children}</TrajectoryContext.Provider>;
};

export const useTrajectory = (): TrajectoryContextValue => {
  const context = useContext(TrajectoryContext);
  if (!context) {
    throw new Error('useTrajectory must be used within a TrajectoryProvider');
  }
  return context;
};

/**
 * Convenience hook for recording specific action types
 */
export const useTrajectoryActions = () => {
  const { recordAction } = useTrajectory();

  return useMemo(
    () => ({
      viewFunction: (name: string, address?: string) =>
        recordAction('view_function', { function_name: name, function_address: address }),

      navigateAddress: (address: string) =>
        recordAction('navigate_address', { address }),

      selectCode: (lineCount: number, snippet?: string) =>
        recordAction('select_code', { line_count: lineCount, code_snippet: snippet?.slice(0, 100) }),

      askQuestion: (question: string) =>
        recordAction('ask_question', { question, question_topic: extractTopic(question) }),

      receiveAnswer: (preview?: string) =>
        recordAction('receive_answer', { answer_preview: preview?.slice(0, 100) }),

      annotate: (address: string, note: string) =>
        recordAction('annotate', { address, note: note.slice(0, 50) }),

      renameFunction: (oldName: string, newName: string) =>
        recordAction('rename_function', { function_name: newName, old_name: oldName }),

      analysisStart: (binary: string, tools: string[]) =>
        recordAction('analysis_start', { binary_name: binary, tools_used: tools }),

      analysisComplete: (binary: string, architecture: string, tools: string[]) =>
        recordAction('analysis_complete', {
          binary_name: binary,
          architecture,
          tools_used: tools,
        }),
    }),
    [recordAction]
  );
};

/**
 * Extract a simple topic from a question for summary purposes
 */
function extractTopic(question: string): string {
  const q = question.toLowerCase();

  // Common patterns
  if (q.includes('vulnerability') || q.includes('exploit') || q.includes('security')) {
    return 'security';
  }
  if (q.includes('function') || q.includes('what does')) {
    return 'function analysis';
  }
  if (q.includes('string') || q.includes('strings')) {
    return 'strings';
  }
  if (q.includes('control flow') || q.includes('cfg')) {
    return 'control flow';
  }
  if (q.includes('decompile') || q.includes('c code')) {
    return 'decompilation';
  }

  // Default: first few words
  const words = question.split(/\s+/).slice(0, 4).join(' ');
  return words.length > 30 ? words.slice(0, 30) + '...' : words;
}

export default TrajectoryContext;
