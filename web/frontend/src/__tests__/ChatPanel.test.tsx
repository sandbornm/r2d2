import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ChatPanel from '../components/ChatPanel';
import type { ChatMessageItem, ChatSessionSummary } from '../types';

describe('ChatPanel', () => {
  const session: ChatSessionSummary = {
    session_id: 'session-1',
    binary_path: '/tmp/a.out',
    title: 'Sample binary',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    message_count: 0,
  };

  const messages: ChatMessageItem[] = [
    {
      message_id: 'm1',
      session_id: 'session-1',
      role: 'system',
      content: 'Analysis completed',
      attachments: [],
      created_at: new Date().toISOString(),
    },
  ];

  it('submits user input via onSend callback', async () => {
    const user = userEvent.setup();
    const handleSend = vi.fn().mockResolvedValue(undefined);

    render(
      <ChatPanel
        session={session}
        messages={messages}
        onSend={handleSend}
      />,
    );

    await user.type(screen.getByPlaceholderText(/ask about the binary/i), 'What does main do?');
    await user.click(screen.getByLabelText(/Ask LLM for a response/i));
    await user.click(screen.getByRole('button', { name: /send/i }));

    expect(handleSend).toHaveBeenCalledWith('What does main do?', { callLLM: false });
  });
});
