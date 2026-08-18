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
  it('renders ranked regions and forwards an ask', async () => {
    const onAsk = vi.fn();
    const user = userEvent.setup();
    render(<BriefingPanel briefing={briefing} onAsk={onAsk} />);

    expect(screen.getByText(/what to ask next/i)).toBeInTheDocument();
    expect(screen.getByText('Entry / main')).toBeInTheDocument();
    expect(screen.getByText(/push \{lr\}/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /ask qwen about this image/i }));
    expect(onAsk).toHaveBeenCalledWith('SUMMARIZE FROM THESE FACTS');
  });
});
