import { render, screen } from '@testing-library/react';
import ToolAttribution from '../components/ToolAttribution';

describe('ToolAttribution', () => {
  it('returns null when no tools are used', () => {
    const { container } = render(
      <ToolAttribution quickScan={{}} deepScan={{}} />
    );
    expect(container.firstChild).toBeNull();
  });

  it('displays radare2 when present in quickScan', () => {
    render(
      <ToolAttribution
        quickScan={{ radare2: { info: {} } }}
        deepScan={{}}
      />
    );
    expect(screen.getByText('radare2')).toBeInTheDocument();
  });

  it('displays multiple tools when present', () => {
    render(
      <ToolAttribution
        quickScan={{ radare2: {}, libmagic: {} }}
        deepScan={{ angr: {} }}
      />
    );

    expect(screen.getByText('radare2')).toBeInTheDocument();
    expect(screen.getByText('angr')).toBeInTheDocument();
    expect(screen.getByText('libmagic')).toBeInTheDocument();
  });

  it('shows correct count of active tools', () => {
    render(
      <ToolAttribution
        quickScan={{ radare2: {} }}
        deepScan={{ angr: {}, ghidra: {} }}
      />
    );

    expect(screen.getByText(/3 active/i)).toBeInTheDocument();
  });

  it('renders in compact mode', () => {
    render(
      <ToolAttribution
        quickScan={{ radare2: {} }}
        deepScan={{}}
        compact={true}
      />
    );

    expect(screen.getByText(/powered by/i)).toBeInTheDocument();
    expect(screen.getByText('radare2')).toBeInTheDocument();
  });

  it('displays all known tools with appropriate styling', () => {
    render(
      <ToolAttribution
        quickScan={{ radare2: {}, libmagic: {}, capstone: {} }}
        deepScan={{ angr: {}, ghidra: {}, frida: {} }}
      />
    );

    // All 6 tools should be present
    expect(screen.getByText('radare2')).toBeInTheDocument();
    expect(screen.getByText('angr')).toBeInTheDocument();
    expect(screen.getByText('Capstone')).toBeInTheDocument();
    expect(screen.getByText('Ghidra')).toBeInTheDocument();
    expect(screen.getByText('Frida')).toBeInTheDocument();
    expect(screen.getByText('libmagic')).toBeInTheDocument();

    expect(screen.getByText(/6 active/i)).toBeInTheDocument();
  });

  it('handles case-insensitive tool names', () => {
    render(
      <ToolAttribution
        quickScan={{ RADARE2: {}, Libmagic: {} }}
        deepScan={{ ANGR: {} }}
      />
    );

    // Should still recognize the tools
    expect(screen.getByText(/3 active/i)).toBeInTheDocument();
  });
});
