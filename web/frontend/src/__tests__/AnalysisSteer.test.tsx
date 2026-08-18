import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import AnalysisSteer from '../components/AnalysisSteer';

describe('AnalysisSteer', () => {
  it('shows squashfs carve and hides JFFS2 / ELF@0 on unpack', () => {
    render(
      <AnalysisSteer
        binary="/tmp/image.bin"
        lenses={['unpack']}
        goal="carve the rootfs"
        firmware={{
          embedded_artifacts: [
            { kind: 'vendor_wrapper', offset_hex: '0x0', name: 'Cloud' },
            { kind: 'elf_binary', offset: 0, offset_hex: '0x0', name: 'ELF @ 0x0' },
            { kind: 'jffs2_marker', offset_hex: '0x137eb', name: 'JFFS2 LE' },
            { kind: 'squashfs_filesystem', offset_hex: '0x100200', name: 'SquashFS LE' },
          ],
        }}
        imports={['strcpy']}
        sniffStrings={['httpd', 'Hello World', 'rootpath']}
      />,
    );
    expect(screen.getByText(/0x100200/)).toBeInTheDocument();
    expect(screen.queryByText(/JFFS2/)).not.toBeInTheDocument();
    expect(screen.queryByText(/ELF @ 0x0/)).not.toBeInTheDocument();
    expect(screen.queryByText('strcpy')).not.toBeInTheDocument();
    expect(screen.getByText('httpd')).toBeInTheDocument();
    expect(screen.queryByText('Hello World')).not.toBeInTheDocument();
  });

  it('shows sink xrefs when the thesis is sinks', () => {
    render(
      <AnalysisSteer
        binary="/tmp/httpd"
        lenses={['sinks', 'network']}
        goal="who calls popen"
        imports={['popen', 'strcpy', 'printf']}
        sniffStrings={['/cgi-bin/login']}
      />,
    );
    expect(screen.getByRole('button', { name: 'popen' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'strcpy' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'printf' })).not.toBeInTheDocument();
    expect(screen.getByText('/cgi-bin/login')).toBeInTheDocument();
  });
});
