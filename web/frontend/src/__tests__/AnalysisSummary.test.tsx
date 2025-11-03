import { render, screen } from '@testing-library/react';
import AnalysisSummary from '../components/AnalysisSummary';
import type { AnalysisResultPayload } from '../types';

describe('AnalysisSummary', () => {
  const sampleAnalysis: AnalysisResultPayload = {
    binary: '/tmp/sample',
    plan: { quick: true, deep: true, run_angr: true, persist_trajectory: true },
    quick_scan: {
      radare2: {
        info: {
          bin: {
            arch: 'x86_64',
            bits: 64,
            baddr: 4198400,
          },
        },
      },
    },
    deep_scan: {
      radare2: {
        functions: [
          { name: 'main', offset: 4198400, size: 64 },
          { name: 'helper', offset: 4198464, size: 32 },
        ],
      },
      capstone: {
        instructions: [
          { address: 4198400, mnemonic: 'push', op_str: 'rbp' },
          { address: 4198401, mnemonic: 'mov', op_str: 'rbp, rsp' },
        ],
      },
    },
    notes: ['entry point flagged'],
    issues: ['angr disabled'],
    session_id: 'abc',
    trajectory_id: 'traj',
  };

  it('renders architecture and function count summaries', () => {
    render(<AnalysisSummary analysis={sampleAnalysis} complexity="beginner" />);

    expect(screen.getByText(/Architecture/i)).toBeInTheDocument();
    expect(screen.getByText(/Bits/i)).toBeInTheDocument();
    expect(screen.getByText(/Functions/i)).toBeInTheDocument();
    expect(screen.getByText(/2/)).toBeInTheDocument();
  });
});
