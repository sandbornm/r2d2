import { render, screen, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ActivityProvider, useActivity } from '../contexts/ActivityContext';

// Test component that uses the activity context
function TestComponent() {
  const activity = useActivity();

  return (
    <div>
      <div data-testid="current-tab">{activity.currentTab}</div>
      <div data-testid="event-count">{activity.events.length}</div>
      <div data-testid="last-function">{activity.lastViewedFunction || 'none'}</div>
      <div data-testid="last-address">{activity.lastViewedAddress || 'none'}</div>
      <button onClick={() => activity.setCurrentTab('chat')}>Switch to Chat</button>
      <button onClick={() => activity.setViewedFunction('main', '0x1000')}>View Function</button>
      <button onClick={() => activity.setViewedAddress('0x2000')}>View Address</button>
      <button onClick={() => activity.trackEvent('code_select', { line_count: 5 })}>Track Select</button>
      <div data-testid="context-summary">{activity.getContextSummary()}</div>
    </div>
  );
}

describe('ActivityContext', () => {
  it('provides default values', () => {
    render(
      <ActivityProvider>
        <TestComponent />
      </ActivityProvider>
    );

    expect(screen.getByTestId('current-tab')).toHaveTextContent('results');
    expect(screen.getByTestId('event-count')).toHaveTextContent('0');
    expect(screen.getByTestId('last-function')).toHaveTextContent('none');
    expect(screen.getByTestId('last-address')).toHaveTextContent('none');
  });

  it('tracks tab switches', async () => {
    const user = userEvent.setup();
    render(
      <ActivityProvider>
        <TestComponent />
      </ActivityProvider>
    );

    await user.click(screen.getByText('Switch to Chat'));

    expect(screen.getByTestId('current-tab')).toHaveTextContent('chat');
    expect(screen.getByTestId('event-count')).toHaveTextContent('1');
  });

  it('tracks function views', async () => {
    const user = userEvent.setup();
    render(
      <ActivityProvider>
        <TestComponent />
      </ActivityProvider>
    );

    await user.click(screen.getByText('View Function'));

    expect(screen.getByTestId('last-function')).toHaveTextContent('main');
    expect(screen.getByTestId('last-address')).toHaveTextContent('0x1000');
    expect(screen.getByTestId('event-count')).toHaveTextContent('1');
  });

  it('tracks address views', async () => {
    const user = userEvent.setup();
    render(
      <ActivityProvider>
        <TestComponent />
      </ActivityProvider>
    );

    await user.click(screen.getByText('View Address'));

    expect(screen.getByTestId('last-address')).toHaveTextContent('0x2000');
  });

  it('tracks custom events', async () => {
    const user = userEvent.setup();
    render(
      <ActivityProvider>
        <TestComponent />
      </ActivityProvider>
    );

    await user.click(screen.getByText('Track Select'));

    expect(screen.getByTestId('event-count')).toHaveTextContent('1');
  });

  it('generates context summary', async () => {
    const user = userEvent.setup();
    render(
      <ActivityProvider>
        <TestComponent />
      </ActivityProvider>
    );

    // Perform some actions
    await user.click(screen.getByText('View Function'));

    const summary = screen.getByTestId('context-summary').textContent;
    expect(summary).toContain('Session duration');
    expect(summary).toContain('Current view');
  });

  it('throws error when used outside provider', () => {
    // Suppress console.error for this test
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => {
      render(<TestComponent />);
    }).toThrow('useActivity must be used within an ActivityProvider');

    consoleSpy.mockRestore();
  });

  it('limits event history', async () => {
    const user = userEvent.setup();
    render(
      <ActivityProvider>
        <TestComponent />
      </ActivityProvider>
    );

    // Track more than MAX_EVENTS (100)
    for (let i = 0; i < 110; i++) {
      await act(async () => {
        await user.click(screen.getByText('Track Select'));
      });
    }

    // Should be capped at 100
    const count = parseInt(screen.getByTestId('event-count').textContent || '0', 10);
    expect(count).toBeLessThanOrEqual(100);
  });

  it('includes tab switch information in events', async () => {
    const user = userEvent.setup();

    let capturedEvents: unknown[] = [];

    function EventCapture() {
      const activity = useActivity();
      capturedEvents = activity.events;
      return (
        <button onClick={() => activity.setCurrentTab('cfg')}>Switch Tab</button>
      );
    }

    render(
      <ActivityProvider>
        <EventCapture />
      </ActivityProvider>
    );

    await user.click(screen.getByText('Switch Tab'));

    expect(capturedEvents.length).toBe(1);
    expect((capturedEvents[0] as { event_type: string }).event_type).toBe('tab_switch');
  });
});
