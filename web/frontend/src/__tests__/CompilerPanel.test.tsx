import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import CompilerPanel from '../components/CompilerPanel';

// Mock fetch for API calls
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('CompilerPanel', () => {
  beforeEach(() => {
    mockFetch.mockReset();

    // Mock compilers endpoint
    mockFetch.mockImplementation((url: string) => {
      if (url.includes('/api/compilers') && !url.includes('/preview') && !url.includes('/download')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            compilers: {
              arm64: [{ name: 'aarch64-linux-gnu-gcc', path: '/usr/bin/aarch64-linux-gnu-gcc', version: '11.2.0', is_clang: false }],
              arm32: [{ name: 'arm-linux-gnueabihf-gcc', path: '/usr/bin/arm-linux-gnueabihf-gcc', version: '11.2.0', is_clang: false }],
            },
            available_architectures: ['arm64', 'arm32'],
            docker_available: true,
            docker_image_exists: true,
          }),
        });
      }
      if (url.includes('/api/compilers/preview')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            command: 'aarch64-linux-gnu-gcc -O0 -ffreestanding -nostartfiles -o output input.c',
            uses_docker: false,
            compiler: 'aarch64-linux-gnu-gcc',
            available: true,
          }),
        });
      }
      if (url.includes('/api/compile') && !url.includes('/download')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            success: true,
            stdout: '',
            stderr: '',
            command: 'aarch64-linux-gnu-gcc ...',
            return_code: 0,
            architecture: 'arm64',
            compiler: 'aarch64-linux-gnu-gcc',
            output_path: '/tmp/output',
            output_name: 'output',
            assembly: '    .arch armv8-a\n    .text\n    mov x0, #0\n    ret',
          }),
        });
      }
      return Promise.resolve({ ok: false, json: () => Promise.resolve({}) });
    });
  });

  it('renders architecture selector', () => {
    render(<CompilerPanel />);
    expect(screen.getByLabelText(/architecture/i)).toBeInTheDocument();
  });

  it('renders optimization selector', () => {
    render(<CompilerPanel />);
    expect(screen.getByLabelText(/optimization/i)).toBeInTheDocument();
  });

  it('renders freestanding toggle', () => {
    render(<CompilerPanel />);
    expect(screen.getByText(/freestanding/i)).toBeInTheDocument();
  });

  it('renders compile button', () => {
    render(<CompilerPanel />);
    expect(screen.getByRole('button', { name: /compile/i })).toBeInTheDocument();
  });

  it('renders example buttons', () => {
    render(<CompilerPanel />);
    expect(screen.getByText('Hello')).toBeInTheDocument();
    expect(screen.getByText('Fib')).toBeInTheDocument();
    expect(screen.getByText('Loops')).toBeInTheDocument();
    expect(screen.getByText('Memory')).toBeInTheDocument();
  });

  it('loads Hello example when clicked', async () => {
    const user = userEvent.setup();
    render(<CompilerPanel />);

    await user.click(screen.getByText('Hello'));

    // The code editor should contain the hello example (check for characteristic content)
    await waitFor(() => {
      expect(screen.getByText(/hello from arm64/i)).toBeInTheDocument();
    });
  });

  it('compiles code and shows success', async () => {
    const user = userEvent.setup();
    const handleBinaryCompiled = vi.fn();

    render(<CompilerPanel onBinaryCompiled={handleBinaryCompiled} />);

    // Wait for initial API calls
    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalled();
    });

    // Click compile
    await user.click(screen.getByRole('button', { name: /compile/i }));

    // Wait for compile to complete
    await waitFor(() => {
      expect(screen.getByText('Success')).toBeInTheDocument();
    });

    expect(handleBinaryCompiled).toHaveBeenCalledWith('/tmp/output', 'output');
  });

  it('shows error on compile failure', async () => {
    const user = userEvent.setup();

    // Override mock for compile to return failure
    mockFetch.mockImplementation((url: string) => {
      if (url.includes('/api/compilers') && !url.includes('/preview')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            compilers: { arm64: [{ name: 'gcc', path: '/usr/bin/gcc', version: '11', is_clang: false }] },
            available_architectures: ['arm64'],
            docker_available: true,
            docker_image_exists: true,
          }),
        });
      }
      if (url.includes('/api/compilers/preview')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ command: 'gcc ...', uses_docker: false, compiler: 'gcc', available: true }),
        });
      }
      if (url.includes('/api/compile')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            success: false,
            stdout: '',
            stderr: 'error: undefined reference to `main`',
            command: 'gcc ...',
            return_code: 1,
            architecture: 'arm64',
            compiler: 'gcc',
          }),
        });
      }
      return Promise.resolve({ ok: false, json: () => Promise.resolve({}) });
    });

    render(<CompilerPanel />);

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalled();
    });

    await user.click(screen.getByRole('button', { name: /compile/i }));

    await waitFor(() => {
      expect(screen.getByText('Failed')).toBeInTheDocument();
    });

    expect(screen.getByText(/undefined reference/i)).toBeInTheDocument();
  });

  it('shows download buttons after successful compile', async () => {
    const user = userEvent.setup();

    render(<CompilerPanel />);

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalled();
    });

    await user.click(screen.getByRole('button', { name: /compile/i }));

    await waitFor(() => {
      expect(screen.getByText('Success')).toBeInTheDocument();
    });

    // Should have download buttons for ELF and assembly
    expect(screen.getByRole('button', { name: /elf/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /\.s/i })).toBeInTheDocument();
  });

  it('calls onAnalyzeAndChat when chat button clicked', async () => {
    const user = userEvent.setup();
    const handleAnalyzeAndChat = vi.fn();

    render(<CompilerPanel onAnalyzeAndChat={handleAnalyzeAndChat} />);

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalled();
    });

    await user.click(screen.getByRole('button', { name: /compile/i }));

    await waitFor(() => {
      expect(screen.getByText('Success')).toBeInTheDocument();
    });

    const chatButton = screen.getByRole('button', { name: /chat/i });
    await user.click(chatButton);

    expect(handleAnalyzeAndChat).toHaveBeenCalledWith('/tmp/output', 'output');
  });

  it('disables compile button while compiling', async () => {
    const user = userEvent.setup();

    // Make compile take longer
    mockFetch.mockImplementation((url: string) => {
      if (url.includes('/api/compilers') && !url.includes('/preview')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            compilers: { arm64: [] },
            available_architectures: ['arm64'],
            docker_available: true,
            docker_image_exists: true,
          }),
        });
      }
      if (url.includes('/api/compilers/preview')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ command: 'gcc', uses_docker: false, compiler: 'gcc', available: true }),
        });
      }
      if (url.includes('/api/compile')) {
        return new Promise((resolve) =>
          setTimeout(
            () =>
              resolve({
                ok: true,
                json: () =>
                  Promise.resolve({
                    success: true,
                    stdout: '',
                    stderr: '',
                    command: '',
                    return_code: 0,
                    architecture: 'arm64',
                    compiler: 'gcc',
                  }),
              }),
            100
          )
        );
      }
      return Promise.resolve({ ok: false, json: () => Promise.resolve({}) });
    });

    render(<CompilerPanel />);

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalled();
    });

    const compileButton = screen.getByRole('button', { name: /compile/i });
    await user.click(compileButton);

    // Button should show "Compiling..." while in progress
    expect(screen.getByRole('button', { name: /compiling/i })).toBeDisabled();
  });
});
