import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ResultViewer from '../components/ResultViewer';
import type { AnalysisResultPayload } from '../types';

// Mock the subcomponents that have complex dependencies
vi.mock('../components/CFGViewer', () => ({
  default: ({ onAskAboutCFG }: { onAskAboutCFG?: () => void }) => (
    <div data-testid="cfg-viewer">
      CFG Viewer Mock
      {onAskAboutCFG && <button onClick={() => onAskAboutCFG()}>Ask About CFG</button>}
    </div>
  ),
}));

vi.mock('../components/DisassemblyViewer', () => ({
  default: ({ disassembly, onAskAbout }: { disassembly: string; onAskAbout?: (code: string) => void }) => (
    <div data-testid="disassembly-viewer">
      <pre>{disassembly}</pre>
      {onAskAbout && <button onClick={() => onAskAbout('test code')}>Ask About Code</button>}
    </div>
  ),
}));

vi.mock('../components/DWARFPanel', () => ({
  default: ({ data, onAskClaude }: { data: unknown; onAskClaude?: (question: string) => void }) => (
    <div data-testid="dwarf-panel">
      DWARF Panel Mock
      {data && <span>Has DWARF data</span>}
      {onAskClaude && <button onClick={() => onAskClaude('test question')}>Ask Claude</button>}
    </div>
  ),
}));

vi.mock('../components/ToolAttribution', () => ({
  default: ({ quickScan, deepScan }: { quickScan?: Record<string, unknown>; deepScan?: Record<string, unknown> }) => (
    <div data-testid="tool-attribution">
      Tools: {Object.keys(quickScan || {}).join(', ')} | {Object.keys(deepScan || {}).join(', ')}
    </div>
  ),
}));

describe('ResultViewer', () => {
  const mockResult: AnalysisResultPayload = {
    binary: '/tmp/test.bin',
    plan: {
      quick: true,
      deep: true,
      run_angr: true,
      persist_trajectory: true,
    },
    quick_scan: {
      radare2: {
        info: {
          bin: {
            arch: 'arm',
            bits: 32,
            machine: 'ARM',
            os: 'linux',
            bintype: 'elf',
          },
          core: {
            format: 'elf',
          },
        },
        strings: [
          { string: 'Hello World', vaddr: 0x1000 },
          { string: 'Test String', vaddr: 0x1010 },
        ],
        imports: [
          { name: 'printf', plt: 0x2000 },
          { name: 'malloc', plt: 0x2004 },
        ],
      },
    },
    deep_scan: {
      radare2: {
        functions: [
          { name: 'main', offset: 0x1000, size: 100 },
          { name: 'helper', offset: 0x2000, size: 50 },
        ],
        entry_disassembly: '0x00001000 push {r4, lr}\n0x00001004 mov r0, #1',
        function_cfgs: [],
      },
      angr: {
        cfg: {
          nodes: [],
          edges: [],
        },
        active: 0,
        found: 0,
      },
    },
    notes: [],
    issues: [],
  };

  it('renders empty state when no result', () => {
    render(<ResultViewer result={null} />);
    expect(screen.getByText(/no analysis yet/i)).toBeInTheDocument();
    expect(screen.getByText(/drop a binary to get started/i)).toBeInTheDocument();
  });

  it('renders binary info header', () => {
    render(<ResultViewer result={mockResult} />);
    expect(screen.getByText('test.bin')).toBeInTheDocument();
    expect(screen.getByText(/elf.*arm32.*linux/i)).toBeInTheDocument();
  });

  it('renders count chips', () => {
    render(<ResultViewer result={mockResult} />);
    expect(screen.getByText('2 fn')).toBeInTheDocument();
    expect(screen.getByText('2 imp')).toBeInTheDocument();
    expect(screen.getByText('2 str')).toBeInTheDocument();
  });

  it('renders summary tab by default', () => {
    render(<ResultViewer result={mockResult} />);
    expect(screen.getByTestId('tool-attribution')).toBeInTheDocument();
    expect(screen.getByText('Binary Info')).toBeInTheDocument();
    expect(screen.getByText('Top Functions')).toBeInTheDocument();
    expect(screen.getByText('Imports')).toBeInTheDocument();
  });

  it('switches to functions tab', async () => {
    const user = userEvent.setup();
    render(<ResultViewer result={mockResult} />);

    await user.click(screen.getByRole('tab', { name: /functions/i }));

    expect(screen.getByText('main')).toBeInTheDocument();
    expect(screen.getByText('helper')).toBeInTheDocument();
  });

  it('switches to strings tab', async () => {
    const user = userEvent.setup();
    render(<ResultViewer result={mockResult} />);

    await user.click(screen.getByRole('tab', { name: /strings/i }));

    expect(screen.getByText('Hello World')).toBeInTheDocument();
    expect(screen.getByText('Test String')).toBeInTheDocument();
  });

  it('switches to disasm tab', async () => {
    const user = userEvent.setup();
    render(<ResultViewer result={mockResult} />);

    await user.click(screen.getByRole('tab', { name: /disasm/i }));

    expect(screen.getByTestId('disassembly-viewer')).toBeInTheDocument();
  });

  it('switches to CFG tab', async () => {
    const user = userEvent.setup();
    render(<ResultViewer result={mockResult} />);

    await user.click(screen.getByRole('tab', { name: /cfg/i }));

    expect(screen.getByTestId('cfg-viewer')).toBeInTheDocument();
  });

  it('switches to DWARF tab', async () => {
    const user = userEvent.setup();
    render(<ResultViewer result={mockResult} />);

    await user.click(screen.getByRole('tab', { name: /debug/i }));

    expect(screen.getByTestId('dwarf-panel')).toBeInTheDocument();
  });

  it('calls onAskAboutCode callback when provided', async () => {
    const user = userEvent.setup();
    const handleAskAboutCode = vi.fn();
    render(<ResultViewer result={mockResult} onAskAboutCode={handleAskAboutCode} />);

    await user.click(screen.getByRole('tab', { name: /disasm/i }));
    await user.click(screen.getByText('Ask About Code'));

    expect(handleAskAboutCode).toHaveBeenCalledWith('test code');
  });

  it('handles arm64 architecture display', () => {
    const arm64Result: AnalysisResultPayload = {
      ...mockResult,
      quick_scan: {
        radare2: {
          info: {
            bin: {
              arch: 'arm',
              bits: 64,
              machine: 'ARM64',
              os: 'linux',
              bintype: 'elf',
            },
            core: {
              format: 'elf',
            },
          },
          strings: [],
          imports: [],
        },
      },
    };

    render(<ResultViewer result={arm64Result} />);
    expect(screen.getByText(/elf.*arm64.*linux/i)).toBeInTheDocument();
  });

  it('handles x86 architecture display', () => {
    const x86Result: AnalysisResultPayload = {
      ...mockResult,
      quick_scan: {
        radare2: {
          info: {
            bin: {
              arch: 'x86',
              bits: 64,
              machine: 'AMD64',
              os: 'linux',
              bintype: 'elf',
            },
            core: {
              format: 'elf',
            },
          },
          strings: [],
          imports: [],
        },
      },
    };

    render(<ResultViewer result={x86Result} />);
    expect(screen.getByText(/elf.*x86_64.*linux/i)).toBeInTheDocument();
  });
});
