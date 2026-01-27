import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import ScriptExecutionBlock from '../components/ScriptExecutionBlock';

describe('ScriptExecutionBlock', () => {
  const mockValidation = {
    valid: true,
    errors: [],
    warnings: [],
    error_summary: 'Validation passed',
  };

  const mockExecution = {
    status: 'success' as const,
    duration_ms: 150,
    stdout: 'Found 3 functions\nmain\nhelper\ninit',
    stderr: '',
  };

  it('renders script with tool and language', () => {
    render(
      <ScriptExecutionBlock
        tool="ghidra"
        language="python"
        script="print(currentProgram.getName())"
        validation={mockValidation}
        execution={mockExecution}
      />
    );

    expect(screen.getByText(/ghidra/i)).toBeInTheDocument();
    expect(screen.getByText(/python/i)).toBeInTheDocument();
  });

  it('shows validation success indicator', () => {
    render(
      <ScriptExecutionBlock
        tool="ghidra"
        language="python"
        script="print('hello')"
        validation={mockValidation}
        execution={mockExecution}
      />
    );

    // When validation is valid and execution succeeds, status shows "Success"
    expect(screen.getByText('Success')).toBeInTheDocument();
  });

  it('shows validation errors', () => {
    const invalidValidation = {
      valid: false,
      errors: [{ message: 'SyntaxError: invalid syntax', location: 'line 1', severity: 'error' }],
      warnings: [],
      error_summary: 'SyntaxError: invalid syntax',
    };

    render(
      <ScriptExecutionBlock
        tool="ghidra"
        language="python"
        script="def broken("
        validation={invalidValidation}
        execution={null}
      />
    );

    expect(screen.getByText(/SyntaxError/i)).toBeInTheDocument();
  });

  it('shows execution output on success', () => {
    render(
      <ScriptExecutionBlock
        tool="ghidra"
        language="python"
        script="print('test')"
        validation={mockValidation}
        execution={mockExecution}
      />
    );

    expect(screen.getByText(/Found 3 functions/)).toBeInTheDocument();
  });

  it('shows execution time', () => {
    render(
      <ScriptExecutionBlock
        tool="ghidra"
        language="python"
        script="print('test')"
        validation={mockValidation}
        execution={mockExecution}
      />
    );

    expect(screen.getByText(/150ms/)).toBeInTheDocument();
  });

  it('shows execution error status', () => {
    const errorExecution = {
      status: 'error' as const,
      duration_ms: 50,
      stdout: '',
      stderr: 'NameError: undefined is not defined',
      exception: 'NameError',
    };

    render(
      <ScriptExecutionBlock
        tool="ghidra"
        language="python"
        script="print(undefined)"
        validation={mockValidation}
        execution={errorExecution}
      />
    );

    // Status chip shows "Error" label
    expect(screen.getByText('Error')).toBeInTheDocument();
    // Error output section shows the error details
    expect(screen.getByText('Error Output')).toBeInTheDocument();
    expect(screen.getByText(/NameError/)).toBeInTheDocument();
  });

  it('shows timeout status', () => {
    const timeoutExecution = {
      status: 'timeout' as const,
      duration_ms: 30000,
      stdout: '',
      stderr: 'Execution timed out',
    };

    render(
      <ScriptExecutionBlock
        tool="ghidra"
        language="python"
        script="while True: pass"
        validation={mockValidation}
        execution={timeoutExecution}
      />
    );

    expect(screen.getByText(/timeout/i)).toBeInTheDocument();
  });

  it('expands script when clicked', async () => {
    const user = userEvent.setup();
    const longScript = `# Long script\nfor i in range(100):\n    print(i)`;

    render(
      <ScriptExecutionBlock
        tool="ghidra"
        language="python"
        script={longScript}
        validation={mockValidation}
        execution={mockExecution}
      />
    );

    // Click to expand
    const expandButton = screen.getByRole('button', { name: /expand|show/i });
    await user.click(expandButton);

    expect(screen.getByText(/for i in range/)).toBeInTheDocument();
  });

  it('calls onRetry when retry button is clicked', async () => {
    const user = userEvent.setup();
    const onRetry = vi.fn();

    render(
      <ScriptExecutionBlock
        tool="ghidra"
        language="python"
        script="print('test')"
        validation={mockValidation}
        execution={mockExecution}
        onRetry={onRetry}
      />
    );

    const retryButton = screen.getByRole('button', { name: /retry|rerun/i });
    await user.click(retryButton);

    expect(onRetry).toHaveBeenCalled();
  });
});
