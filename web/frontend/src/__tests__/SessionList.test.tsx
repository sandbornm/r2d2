import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import SessionList from '../components/SessionList';
import type { ChatSessionSummary } from '../types';

describe('SessionList', () => {
  const mockSessions: ChatSessionSummary[] = [
    {
      session_id: 'session-1',
      binary_path: '/tmp/binary1.bin',
      title: 'Binary One',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      message_count: 5,
    },
    {
      session_id: 'session-2',
      binary_path: '/tmp/path/to/binary2.bin',
      title: null,
      created_at: new Date(Date.now() - 86400000).toISOString(), // 1 day ago
      updated_at: new Date(Date.now() - 86400000).toISOString(),
      message_count: 3,
    },
  ];

  it('renders empty state when no sessions', () => {
    render(
      <SessionList
        sessions={[]}
        activeSessionId={null}
        onSelect={vi.fn()}
      />
    );
    expect(screen.getByText(/no sessions yet/i)).toBeInTheDocument();
  });

  it('renders session list with titles', () => {
    render(
      <SessionList
        sessions={mockSessions}
        activeSessionId={null}
        onSelect={vi.fn()}
      />
    );

    expect(screen.getByText('Binary One')).toBeInTheDocument();
    // Second session has no title, should show filename
    expect(screen.getByText('binary2.bin')).toBeInTheDocument();
  });

  it('highlights active session', () => {
    render(
      <SessionList
        sessions={mockSessions}
        activeSessionId="session-1"
        onSelect={vi.fn()}
      />
    );

    const activeButton = screen.getByText('Binary One').closest('div[role="button"]');
    expect(activeButton).toHaveClass('Mui-selected');
  });

  it('calls onSelect when session is clicked', async () => {
    const user = userEvent.setup();
    const handleSelect = vi.fn();

    render(
      <SessionList
        sessions={mockSessions}
        activeSessionId={null}
        onSelect={handleSelect}
      />
    );

    await user.click(screen.getByText('Binary One'));

    expect(handleSelect).toHaveBeenCalledWith(mockSessions[0]);
  });

  it('shows delete option in context menu', async () => {
    const user = userEvent.setup();
    const handleDelete = vi.fn();

    render(
      <SessionList
        sessions={mockSessions}
        activeSessionId={null}
        onSelect={vi.fn()}
        onDelete={handleDelete}
      />
    );

    // Click the menu button for first session
    const menuButtons = screen.getAllByRole('button');
    // Find the menu button (not the list item button)
    const menuButton = menuButtons.find(btn => btn.querySelector('svg'));
    expect(menuButton).toBeDefined();

    await user.click(menuButton!);

    // Click delete
    const deleteMenuItem = await screen.findByText('Delete');
    await user.click(deleteMenuItem);

    expect(handleDelete).toHaveBeenCalledWith('session-1');
  });

  it('displays relative time for sessions', () => {
    render(
      <SessionList
        sessions={mockSessions}
        activeSessionId={null}
        onSelect={vi.fn()}
      />
    );

    // First session should show something like "a few seconds ago" or "just now"
    // Second session should show "a day ago" or "1 day ago"
    const timeElements = screen.getAllByText(/ago|just now/i);
    expect(timeElements.length).toBeGreaterThanOrEqual(2);
  });

  it('uses filename when title is null', () => {
    const sessionsWithNullTitle: ChatSessionSummary[] = [
      {
        session_id: 'session-3',
        binary_path: '/some/deep/path/myfile.elf',
        title: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        message_count: 0,
      },
    ];

    render(
      <SessionList
        sessions={sessionsWithNullTitle}
        activeSessionId={null}
        onSelect={vi.fn()}
      />
    );

    expect(screen.getByText('myfile.elf')).toBeInTheDocument();
  });
});
