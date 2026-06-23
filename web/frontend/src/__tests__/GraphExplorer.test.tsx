import { fireEvent, render, screen } from '@testing-library/react';
import GraphExplorer from '../components/GraphExplorer';
import type { AnalysisGraphPayload } from '../types';

const graph: AnalysisGraphPayload = {
  schema_version: 'r2d2.analysis_graph.v1',
  binary: 'router-firmware.bin',
  generated_at: '2026-01-01T00:00:00Z',
  nodes: [
    { id: 'binary:root', kind: 'binary', label: 'router-firmware.bin', source: 'r2d2', properties: {} },
    { id: 'profile:inventory', kind: 'firmware_profile', label: 'Firmware inventory', source: 'firmware', properties: {} },
    {
      id: 'artifact:rootfs',
      kind: 'embedded_artifact',
      label: 'SquashFS rootfs',
      source: 'firmware',
      address: '0x1000',
      properties: { kind: 'squashfs_filesystem', recommended: true },
    },
    { id: 'function:main', kind: 'function', label: 'main', source: 'ghidra_gdb', address: '0x401000', properties: {} },
    { id: 'import:system', kind: 'import', label: 'system', source: 'radare2', properties: {} },
    { id: 'string:admin', kind: 'string', label: 'admin password', source: 'radare2', properties: {} },
    { id: 'tool:angr_mcp', kind: 'tool', label: 'angr_mcp', source: 'r2d2', properties: { available: false } },
    { id: 'issue:telnet', kind: 'issue', label: 'Telnet reachable from LAN', source: 'r2d2', properties: {} },
  ],
  edges: [
    { id: 'e1', kind: 'has_inventory', source: 'binary:root', target: 'profile:inventory', source_tool: 'firmware', properties: {} },
    { id: 'e2', kind: 'contains_artifact', source: 'binary:root', target: 'artifact:rootfs', source_tool: 'firmware', properties: {} },
    { id: 'e3', kind: 'contains_function', source: 'binary:root', target: 'function:main', source_tool: 'ghidra_gdb', properties: {} },
    { id: 'e4', kind: 'imports', source: 'function:main', target: 'import:system', source_tool: 'radare2', properties: {} },
    { id: 'e5', kind: 'references_string', source: 'function:main', target: 'string:admin', source_tool: 'radare2', properties: {} },
    { id: 'e6', kind: 'has_issue', source: 'string:admin', target: 'issue:telnet', source_tool: 'r2d2', properties: {} },
    { id: 'e7', kind: 'candidate_for', source: 'artifact:rootfs', target: 'tool:angr_mcp', source_tool: 'firmware', properties: {} },
    { id: 'e8', kind: 'has_issue', source: 'artifact:rootfs', target: 'issue:telnet', source_tool: 'r2d2', properties: {} },
  ],
  summary: {
    node_count: 8,
    edge_count: 8,
    node_kinds: {
      binary: 1,
      firmware_profile: 1,
      embedded_artifact: 1,
      function: 1,
      import: 1,
      string: 1,
      tool: 1,
      issue: 1,
    },
  },
};

describe('GraphExplorer', () => {
  it('starts as a calm segmented map and can focus a segment', () => {
    render(<GraphExplorer analysisGraph={graph} />);

    expect(screen.getByText('Findings Map')).toBeInTheDocument();
    expect(screen.getByText(/6 areas/i)).toBeInTheDocument();
    expect(screen.getByText(/Calm density/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /calm map density/i })).toHaveAttribute('aria-pressed', 'true');

    fireEvent.click(screen.getByRole('button', { name: /linked map density/i }));
    expect(screen.getByText(/Linked density/i)).toBeInTheDocument();

    fireEvent.click(screen.getByText(/Artifacts 1 \/ 1 signal/i));
    expect(screen.getByText(/1 nodes and .* links in this segment/i)).toBeInTheDocument();
  });
});
