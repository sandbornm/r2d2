import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import SettingsDrawer, { type AnalysisSettings } from '../components/SettingsDrawer';

const mockFetch = vi.fn();
global.fetch = mockFetch;

const settings: AnalysisSettings = {
  analysisProfile: 'standard',
  quickScanOnly: false,
  enableAngr: true,
  enableGhidra: true,
  enableGef: false,
  enableFrida: false,
  autoAskLLM: false,
  selectedModel: 'gemma4:latest',
};

const renderDrawer = () => render(
  <SettingsDrawer
    open
    onClose={vi.fn()}
    isDarkMode={false}
    onToggleTheme={vi.fn()}
    settings={settings}
    onSettingsChange={vi.fn()}
  />,
);

describe('SettingsDrawer', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('starts unavailable MCP services from the detailed tool list', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          tools: {
            angr_mcp: {
              available: false,
              description: 'angr MCP',
              start_command: ['uv', 'run', 'angr-mcp-dev-server'],
              working_dir: '../angr_mcp',
            },
            ghidra: { available: true, description: 'Ghidra' },
          },
          meta: { live: true, generated_at: new Date().toISOString() },
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          launch: { angr_mcp: { status: 'started' } },
          tools: {
            angr_mcp: {
              available: true,
              description: 'angr MCP',
              start_command: ['uv', 'run', 'angr-mcp-dev-server'],
            },
            ghidra: { available: true, description: 'Ghidra' },
          },
          meta: { live: true, generated_at: new Date().toISOString() },
        }),
      });

    renderDrawer();

    fireEvent.click(await screen.findByRole('button', { name: /start angr mcp/i }));

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith('/api/tools/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ services: ['angr_mcp'] }),
      });
      expect(screen.getByText(/angr MCP: started/i)).toBeInTheDocument();
    });
  });
});
