import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DWARFPanel from '../components/DWARFPanel';
import type { DWARFData } from '../types';
import { ActivityProvider } from '../contexts/ActivityContext';

// Wrap component with ActivityProvider for testing
const renderWithActivity = (ui: React.ReactElement) => {
  return render(<ActivityProvider>{ui}</ActivityProvider>);
};

describe('DWARFPanel', () => {
  const mockDWARFData: DWARFData = {
    has_dwarf: true,
    dwarf_version: 4,
    compilation_units: [
      {
        offset: 0,
        version: 4,
        unit_length: 100,
        name: 'main.c',
        producer: 'GCC 11.2.0',
        language: 0x000c, // C99
        comp_dir: '/home/user/project',
        source_files: ['main.c', 'utils.h'],
        functions: [
          {
            name: 'main',
            offset: 0x100,
            low_pc: 0x1000,
            high_pc: 0x1100,
            size: 256,
            is_external: true,
            is_inline: false,
            parameters: [
              { name: 'argc', offset: 0x110 },
              { name: 'argv', offset: 0x120 },
            ],
            local_variables: [],
          },
        ],
        variables: [],
        types: [],
      },
    ],
    functions: [
      {
        name: 'main',
        offset: 0x100,
        low_pc: 0x1000,
        high_pc: 0x1100,
        size: 256,
        is_external: true,
        is_inline: false,
        parameters: [
          { name: 'argc', offset: 0x110 },
          { name: 'argv', offset: 0x120 },
        ],
        local_variables: [],
      },
      {
        name: 'helper_inline',
        offset: 0x200,
        low_pc: 0x2000,
        high_pc: null,
        is_external: false,
        is_inline: true,
        parameters: [],
        local_variables: [],
      },
    ],
    variables: [
      {
        name: 'global_var',
        offset: 0x300,
        is_local: false,
        is_external: true,
      },
    ],
    types: [
      {
        name: 'int',
        offset: 0x400,
        tag: 'DW_TAG_base_type',
        byte_size: 4,
      },
      {
        name: 'MyStruct',
        offset: 0x500,
        tag: 'DW_TAG_structure_type',
        byte_size: 16,
        members: [
          { name: 'x', offset: 0 },
          { name: 'y', offset: 4 },
        ],
      },
    ],
    source_files: ['main.c', 'utils.h'],
    line_programs: [],
  };

  it('renders empty state when no data', () => {
    renderWithActivity(<DWARFPanel data={null} />);
    expect(screen.getByText(/no dwarf data available/i)).toBeInTheDocument();
  });

  it('renders info alert when binary has no DWARF', () => {
    const noDwarfData: DWARFData = {
      has_dwarf: false,
      compilation_units: [],
      functions: [],
      variables: [],
      types: [],
      source_files: [],
      line_programs: [],
    };

    renderWithActivity(<DWARFPanel data={noDwarfData} />);
    expect(screen.getByText(/does not contain dwarf debug information/i)).toBeInTheDocument();
    expect(screen.getByText(/-g/i)).toBeInTheDocument();
  });

  it('renders overview tab by default', () => {
    renderWithActivity(<DWARFPanel data={mockDWARFData} />);

    expect(screen.getByText('Debug Information Summary')).toBeInTheDocument();
    expect(screen.getByText('DWARF v4')).toBeInTheDocument();
    expect(screen.getByText('1 Compilation Units')).toBeInTheDocument();
    expect(screen.getByText('2 Functions')).toBeInTheDocument();
    expect(screen.getByText('2 Types')).toBeInTheDocument();
  });

  it('switches to functions tab', async () => {
    const user = userEvent.setup();
    renderWithActivity(<DWARFPanel data={mockDWARFData} />);

    await user.click(screen.getByRole('tab', { name: /functions \(2\)/i }));

    expect(screen.getByText('main')).toBeInTheDocument();
    expect(screen.getByText('helper_inline')).toBeInTheDocument();
    expect(screen.getByText('inline')).toBeInTheDocument(); // inline chip
  });

  it('switches to types tab', async () => {
    const user = userEvent.setup();
    renderWithActivity(<DWARFPanel data={mockDWARFData} />);

    await user.click(screen.getByRole('tab', { name: /types \(2\)/i }));

    expect(screen.getByText('int')).toBeInTheDocument();
    expect(screen.getByText('MyStruct')).toBeInTheDocument();
  });

  it('switches to variables tab', async () => {
    const user = userEvent.setup();
    renderWithActivity(<DWARFPanel data={mockDWARFData} />);

    await user.click(screen.getByRole('tab', { name: /variables \(1\)/i }));

    expect(screen.getByText('global_var')).toBeInTheDocument();
  });

  it('switches to sources tab', async () => {
    const user = userEvent.setup();
    renderWithActivity(<DWARFPanel data={mockDWARFData} />);

    await user.click(screen.getByRole('tab', { name: /sources \(2\)/i }));

    expect(screen.getByText('main.c')).toBeInTheDocument();
    expect(screen.getByText('utils.h')).toBeInTheDocument();
  });

  it('calls onAskClaude for function', async () => {
    const user = userEvent.setup();
    const handleAskClaude = vi.fn();

    renderWithActivity(<DWARFPanel data={mockDWARFData} onAskClaude={handleAskClaude} />);

    // Navigate to functions tab
    await user.click(screen.getByRole('tab', { name: /functions/i }));

    // Click the help button for the first function
    const helpButtons = screen.getAllByRole('button');
    const askButton = helpButtons.find(btn => btn.querySelector('[data-testid="HelpOutlineIcon"]'));
    if (askButton) {
      await user.click(askButton);
      expect(handleAskClaude).toHaveBeenCalled();
      expect(handleAskClaude.mock.calls[0][0]).toContain('main');
    }
  });

  it('displays external function badge', async () => {
    const user = userEvent.setup();
    renderWithActivity(<DWARFPanel data={mockDWARFData} />);

    await user.click(screen.getByRole('tab', { name: /functions/i }));

    expect(screen.getByText('extern')).toBeInTheDocument();
  });

  it('displays struct members count', async () => {
    const user = userEvent.setup();
    renderWithActivity(<DWARFPanel data={mockDWARFData} />);

    await user.click(screen.getByRole('tab', { name: /types/i }));

    expect(screen.getByText(/2 members/i)).toBeInTheDocument();
  });

  it('expands compilation unit details', async () => {
    const user = userEvent.setup();
    renderWithActivity(<DWARFPanel data={mockDWARFData} />);

    // Click on the accordion to expand it
    const accordion = screen.getByText('main.c').closest('div[class*="MuiAccordion"]');
    if (accordion) {
      await user.click(accordion);

      // Check for compiler info
      expect(await screen.findByText(/GCC 11.2.0/i)).toBeInTheDocument();
      expect(screen.getByText('C99')).toBeInTheDocument();
    }
  });
});
