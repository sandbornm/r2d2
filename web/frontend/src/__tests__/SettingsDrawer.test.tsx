import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi, beforeEach } from 'vitest';
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

describe('SettingsDrawer', () => {
  beforeEach(() => {
    mockFetch.mockReset();
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ tools: { ghidra: { available: true }, angr: { available: true } } }),
    });
  });

  it('renders profile and engine toggles without a live tool crawl', async () => {
    const onChange = vi.fn();
    render(
      <SettingsDrawer
        open
        onClose={vi.fn()}
        isDarkMode
        onToggleTheme={vi.fn()}
        settings={settings}
        onSettingsChange={onChange}
      />,
    );

    expect(screen.getByText('Settings')).toBeInTheDocument();
    expect(screen.getByText('angr')).toBeInTheDocument();
    expect(screen.getByText('Ghidra')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /start angr mcp/i })).not.toBeInTheDocument();

    fireEvent.mouseDown(screen.getByRole('combobox'));
    fireEvent.click(await screen.findByRole('option', { name: 'Triage' }));
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ analysisProfile: 'triage', quickScanOnly: true }));
  });
});
