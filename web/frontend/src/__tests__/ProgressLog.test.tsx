import { render, screen } from '@testing-library/react';
import ProgressLog from '../components/ProgressLog';
import type { ProgressEventEntry } from '../types';

describe('ProgressLog', () => {
  it('renders empty state when no entries', () => {
    render(<ProgressLog entries={[]} />);
    expect(screen.getByText(/waiting for action/i)).toBeInTheDocument();
    expect(screen.getByText(/drop a binary/i)).toBeInTheDocument();
  });

  it('renders job started event', () => {
    const entries: ProgressEventEntry[] = [
      {
        id: '1',
        event: 'job_started',
        data: { binary: '/tmp/test.bin' },
        timestamp: Date.now(),
      },
    ];

    render(<ProgressLog entries={entries} />);
    expect(screen.getByText(/analysis initiated/i)).toBeInTheDocument();
  });

  it('renders job completed event', () => {
    const entries: ProgressEventEntry[] = [
      {
        id: '1',
        event: 'job_completed',
        data: {},
        timestamp: Date.now(),
      },
    ];

    render(<ProgressLog entries={entries} />);
    expect(screen.getByText(/all done/i)).toBeInTheDocument();
  });

  it('renders job failed event with error message', () => {
    const entries: ProgressEventEntry[] = [
      {
        id: '1',
        event: 'job_failed',
        data: { error: 'Binary not found' },
        timestamp: Date.now(),
      },
    ];

    render(<ProgressLog entries={entries} />);
    expect(screen.getByText(/analysis failed.*binary not found/i)).toBeInTheDocument();
  });

  it('renders stage events', () => {
    const entries: ProgressEventEntry[] = [
      {
        id: '1',
        event: 'stage_started',
        data: { stage: 'quick' },
        timestamp: Date.now(),
      },
    ];

    render(<ProgressLog entries={entries} />);
    expect(screen.getByText(/quick recon/i)).toBeInTheDocument();
  });

  it('renders adapter events', () => {
    const entries: ProgressEventEntry[] = [
      {
        id: '1',
        event: 'adapter_started',
        data: { adapter: 'radare2' },
        timestamp: Date.now(),
      },
    ];

    render(<ProgressLog entries={entries} />);
    expect(screen.getByText(/r2 is doing its thing/i)).toBeInTheDocument();
  });

  it('renders adapter completed event', () => {
    const entries: ProgressEventEntry[] = [
      {
        id: '1',
        event: 'adapter_completed',
        data: { adapter: 'radare2' },
        timestamp: Date.now(),
      },
    ];

    render(<ProgressLog entries={entries} />);
    expect(screen.getByText(/radare2 analysis complete/i)).toBeInTheDocument();
  });

  it('renders adapter skipped event', () => {
    const entries: ProgressEventEntry[] = [
      {
        id: '1',
        event: 'adapter_skipped',
        data: { adapter: 'angr', reason: 'Not installed' },
        timestamp: Date.now(),
      },
    ];

    render(<ProgressLog entries={entries} />);
    expect(screen.getByText(/skipped angr.*not installed/i)).toBeInTheDocument();
  });

  it('shows running indicator when analysis in progress', () => {
    const entries: ProgressEventEntry[] = [
      {
        id: '1',
        event: 'job_started',
        data: {},
        timestamp: Date.now(),
      },
      {
        id: '2',
        event: 'adapter_started',
        data: { adapter: 'radare2' },
        timestamp: Date.now(),
      },
    ];

    render(<ProgressLog entries={entries} />);
    expect(screen.getByText(/analysis in progress/i)).toBeInTheDocument();
  });

  it('does not show running indicator when job completed', () => {
    const entries: ProgressEventEntry[] = [
      {
        id: '1',
        event: 'job_started',
        data: {},
        timestamp: Date.now(),
      },
      {
        id: '2',
        event: 'job_completed',
        data: {},
        timestamp: Date.now(),
      },
    ];

    render(<ProgressLog entries={entries} />);
    expect(screen.queryByText(/analysis in progress/i)).not.toBeInTheDocument();
  });

  it('displays stage chips', () => {
    const entries: ProgressEventEntry[] = [
      {
        id: '1',
        event: 'stage_started',
        data: { stage: 'deep' },
        timestamp: Date.now(),
      },
    ];

    render(<ProgressLog entries={entries} />);
    expect(screen.getByText('deep')).toBeInTheDocument();
  });

  it('displays adapter chips', () => {
    const entries: ProgressEventEntry[] = [
      {
        id: '1',
        event: 'adapter_started',
        data: { adapter: 'angr', stage: 'deep' },
        timestamp: Date.now(),
      },
    ];

    render(<ProgressLog entries={entries} />);
    expect(screen.getByText('angr')).toBeInTheDocument();
    expect(screen.getByText('deep')).toBeInTheDocument();
  });
});
