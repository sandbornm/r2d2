import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from '../App';
import type { ChatMessageItem, ChatSessionSummary, HealthStatus } from '../types';

vi.mock('../components/ResultViewer', () => ({
  default: () => <div>Mock ResultViewer</div>,
}));

vi.mock('../components/ToolStatusBar', () => ({
  default: () => <div>Mock ToolStatusBar</div>,
}));

vi.mock('../components/SettingsDrawer', () => ({
  default: () => null,
}));

vi.mock('../components/CompilerPanel', () => ({
  default: () => <div>Mock CompilerPanel</div>,
}));

vi.mock('../components/GraphExplorer', () => ({
  default: () => <div>Mock GraphExplorer</div>,
}));

vi.mock('../components/ProgressLog', () => ({
  default: () => <div>Mock ProgressLog</div>,
}));

vi.mock('../components/ChatPanel', () => ({
  default: ({ messages }: { messages: unknown[] }) => <div>Mock ChatPanel {messages.length}</div>,
}));

const fetchMock = vi.fn();
const now = '2026-01-01T00:00:00Z';

const health: HealthStatus = {
  status: 'ok',
  model: 'gemma4:latest',
  model_names: { 'gemma4:latest': 'Gemma 4' },
  available_models: ['gemma4:latest'],
  features: { show_compiler: false },
  ghidra_ready: false,
  tools: {},
};

const session: ChatSessionSummary = {
  session_id: 'session-1',
  binary_path: '/tmp/sample.elf',
  title: 'sample.elf',
  created_at: now,
  updated_at: now,
  message_count: 2,
};

const analysisAttachment = {
  type: 'analysis_result',
  binary: '/tmp/sample.elf',
  plan: { quick: true, deep: false, run_angr: false, persist_trajectory: true },
  quick_scan: { radare2: { info: { bin: { arch: 'x86', bits: 64 } } } },
  deep_scan: {},
  notes: ['restored'],
  issues: [],
};

const chatMessages: ChatMessageItem[] = [
  {
    message_id: 'message-1',
    session_id: 'session-1',
    role: 'system',
    content: 'Analysis completed',
    attachments: [analysisAttachment],
    created_at: now,
  },
];

const jsonResponse = (data: unknown, status = 200) =>
  Promise.resolve(
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );

const requestUrls = () => fetchMock.mock.calls.map(([url]) => String(url));

const setupFetch = () => {
  fetchMock.mockImplementation((url: string) => {
    if (url === '/api/health') return jsonResponse(health);
    if (url === '/api/chats?limit=50') return jsonResponse([session]);
    if (url === '/api/chats/session-1/analysis') {
      return jsonResponse({ session, analysis: analysisAttachment });
    }
    if (url === '/api/chats/session-1?limit=250') {
      return jsonResponse({ session, messages: chatMessages });
    }
    return Promise.reject(new Error(`Unhandled fetch: ${url}`));
  });
};

describe('App session loading', () => {
  beforeEach(() => {
    localStorage.clear();
    // Analysis results are cached in sessionStorage; clear it so each test
    // starts from a cold cache and its fetch assertions are deterministic.
    sessionStorage.clear();
    fetchMock.mockReset();
    setupFetch();
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
    sessionStorage.clear();
  });

  it('loads session summaries on startup without hydrating a session', async () => {
    render(<App />);

    expect(await screen.findByText('sample.elf')).toBeInTheDocument();
    expect(screen.getByText(/drop a binary file to analyze/i)).toBeInTheDocument();

    const urls = requestUrls();
    expect(urls).toContain('/api/health');
    expect(urls).toContain('/api/chats?limit=50');
    expect(urls).not.toContain('/api/chats/session-1/analysis');
    expect(urls).not.toContain('/api/chats/session-1?limit=250');
  });

  it('restores Results with the lightweight analysis endpoint', async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByText('sample.elf'));

    expect(await screen.findByText('Mock ResultViewer')).toBeInTheDocument();
    const urls = requestUrls();
    expect(urls).toContain('/api/chats/session-1/analysis');
    expect(urls).not.toContain('/api/chats/session-1?limit=250');
  });

  it('loads full message history only when Chat is opened', async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByText('sample.elf'));
    await screen.findByText('Mock ResultViewer');
    await user.click(screen.getByRole('tab', { name: 'Chat' }));

    await waitFor(() => {
      expect(requestUrls()).toContain('/api/chats/session-1?limit=250');
    });
    expect(await screen.findByText('Mock ChatPanel 1')).toBeInTheDocument();
  });

  it('restores analysis on the Map tab without loading chat history', async () => {
    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByText('sample.elf'));
    await screen.findByText('Mock ResultViewer');
    await user.click(screen.getByRole('tab', { name: /Map/ }));

    await screen.findByText('Mock GraphExplorer');
    const urls = requestUrls();
    expect(urls).toContain('/api/chats/session-1/analysis');
    expect(urls).not.toContain('/api/chats/session-1?limit=250');
  });

  it('reuses cached analysis when returning to a session instead of refetching', async () => {
    const session2: ChatSessionSummary = {
      session_id: 'session-2',
      binary_path: '/tmp/other.elf',
      title: 'other.elf',
      created_at: now,
      updated_at: now,
      message_count: 1,
    };
    const analysisAttachment2 = { ...analysisAttachment, binary: '/tmp/other.elf', notes: ['second'] };
    fetchMock.mockImplementation((url: string) => {
      if (url === '/api/health') return jsonResponse(health);
      if (url === '/api/chats?limit=50') return jsonResponse([session, session2]);
      if (url === '/api/chats/session-1/analysis') return jsonResponse({ session, analysis: analysisAttachment });
      if (url === '/api/chats/session-2/analysis') {
        return jsonResponse({ session: session2, analysis: analysisAttachment2 });
      }
      if (url === '/api/chats/session-1?limit=250') return jsonResponse({ session, messages: chatMessages });
      if (url === '/api/chats/session-2?limit=250') return jsonResponse({ session: session2, messages: [] });
      return Promise.reject(new Error(`Unhandled fetch: ${url}`));
    });

    const user = userEvent.setup();
    render(<App />);

    await user.click(await screen.findByText('sample.elf'));
    await screen.findByText('Mock ResultViewer');
    await user.click(screen.getByText('other.elf'));
    await waitFor(() => {
      expect(requestUrls()).toContain('/api/chats/session-2/analysis');
    });
    await user.click(screen.getByText('sample.elf'));

    // Returning to session-1 should hit the client cache, not fetch /analysis again.
    const session1AnalysisFetches = requestUrls().filter(
      (url) => url === '/api/chats/session-1/analysis',
    ).length;
    expect(session1AnalysisFetches).toBe(1);
  });
});
