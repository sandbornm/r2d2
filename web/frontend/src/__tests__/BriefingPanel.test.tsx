import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import BriefingPanel from '../components/BriefingPanel';
import type { AnalysisBriefingPayload } from '../types';

const briefing: AnalysisBriefingPayload = {
  schema_version: 'r2d2.briefing.v1',
  binary: '/tmp/httpd',
  summary: 'httpd looks like elf; ARM/32. First region: Entry / main.',
  overall_ask: 'SUMMARIZE FROM THESE FACTS',
  next_steps: ['Open main at 0x1000 and send that region ask first.'],
  regions: [
    {
      id: 'entry:main',
      title: 'Entry / main',
      why: 'Start of httpd',
      score: 89,
      tags: ['entry', 'disasm'],
      snippet: {
        source: 'radare2',
        kind: 'disasm',
        text: '0x1000  push {lr}',
        address: '0x1000',
        function: 'main',
      },
      ask: 'REGION 1/1: Entry / main',
      next_actions: ['r2: pdf @ 0x1000'],
    },
  ],
};

describe('BriefingPanel', () => {
  it('renders ranked regions and copies a region ask', async () => {
    const onAsk = vi.fn();
    const user = userEvent.setup();
    render(<BriefingPanel briefing={briefing} onAsk={onAsk} />);

    expect(screen.getByText('Steer')).toBeInTheDocument();
    expect(screen.getByTestId('briefing-goal')).toBeInTheDocument();
    expect(screen.getByText('Entry / main')).toBeInTheDocument();
    expect(screen.getByText(/push \{lr\}/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /copy ask/i }));
    expect(onAsk).not.toHaveBeenCalled();
  });

  it('compact mode shows inferred thesis and hides region dump', () => {
    render(<BriefingPanel briefing={briefing} compact />);
    expect(screen.getByText('Next')).toBeInTheDocument();
    expect(screen.getByTestId('briefing-goal-source')).toHaveTextContent(/inferred/i);
    expect(screen.queryByText(/push \{lr\}/)).not.toBeInTheDocument();
  });

  it('reranks when a user thesis is supplied', () => {
    const withFirmware: typeof briefing = {
      ...briefing,
      inferred_goal: 'carve the rootfs and brief the userspace ELF — not this wrapper',
      ranking_tags: ['lens-unpack'],
      regions: [
        ...briefing.regions,
        {
          id: 'fw:squashfs_filesystem:0x100200',
          title: 'Firmware region: SquashFS LE',
          why: 'root filesystem',
          score: 93,
          tags: ['firmware', 'squashfs_filesystem'],
          snippet: { source: 'firmware', kind: 'inventory', text: 'kind=squashfs_filesystem', address: '0x100200', function: null },
          ask: 'REGION squash',
          next_actions: ['unsquashfs'],
        },
      ],
    };
    render(<BriefingPanel briefing={withFirmware} userGoal="carve squashfs" />);
    expect(screen.getByTestId('briefing-goal-source')).toHaveTextContent(/thesis/i);
    expect(screen.getByTestId('briefing-goal')).toHaveTextContent(/carve squashfs/i);
    expect(screen.getByText(/SquashFS/)).toBeInTheDocument();
  });
});
