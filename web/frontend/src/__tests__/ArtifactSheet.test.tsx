import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ArtifactSheet from '../components/ArtifactSheet';

describe('ArtifactSheet', () => {
  it('shows host sniff facts and hides skipped passes by default', async () => {
    const user = userEvent.setup();
    render(
      <ArtifactSheet
        fileName="wr841.bin"
        format="firmware_container"
        arch="unknown"
        os="tp_link_cloud"
        firmware={{
          top_level_format: 'ver. 2.0',
          container_type: 'tp_link_cloud',
          embedded_artifacts: [{ kind: 'squashfs', offset: '0x100200' }],
          recommended_targets: [{ name: 'httpd' }],
        }}
        sniff={{
          file: 'data',
          sha256: 'deadbeef',
          size_bytes: 2048,
          hex_head: '00000000  00 00 00 00',
          strings: [{ value: 'httpd' }],
        }}
        toolStatus={{
          sniff: { status: 'completed', duration_ms: 8 },
          firmware: { status: 'completed', duration_ms: 40 },
          radare2: { status: 'skipped' },
        }}
        toolScorecard={{}}
        functionCount={0}
        importCount={0}
        stringCount={1}
      />,
    );

    expect(screen.getByTestId('artifact-sheet')).toBeInTheDocument();
    expect(screen.getByText('deadbeef')).toBeInTheDocument();
    expect(screen.getByTestId('artifact-coverage')).toHaveTextContent(/squashfs/);
    expect(screen.getByTestId('artifact-coverage')).toHaveTextContent(/0x100200/);
    expect(screen.getByTestId('artifact-passes')).toHaveTextContent('sniff 8ms');
    expect(screen.getByTestId('artifact-passes')).not.toHaveTextContent('radare2');

    await user.click(screen.getByRole('button', { name: /1 skipped/i }));
    expect(screen.getByTestId('artifact-passes')).toHaveTextContent('radare2');
  });
});
