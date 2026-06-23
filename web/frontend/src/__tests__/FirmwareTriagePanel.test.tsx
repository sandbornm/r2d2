import { render, screen } from '@testing-library/react';
import FirmwareTriagePanel from '../components/FirmwareTriagePanel';

describe('FirmwareTriagePanel', () => {
  it('renders firmware-native string signals and entropy windows', () => {
    render(
      <FirmwareTriagePanel
        firmware={{
          mode: 'firmware_inventory',
          size_bytes: 131072,
          is_elf: false,
          top_level_format: 'firmware_container',
          container_type: 'boot_firmware',
          scan: {
            bytes_scanned: 131072,
            truncated: false,
            signature_count: 1,
          },
          embedded_artifacts: [
            {
              offset: 4096,
              offset_hex: '0x1000',
              kind: 'squashfs_filesystem',
              name: 'SquashFS LE',
              recommended: true,
              analysis_role: 'filesystem',
            },
          ],
          recommended_targets: [
            {
              offset: 4096,
              offset_hex: '0x1000',
              kind: 'squashfs_filesystem',
              name: 'SquashFS LE',
              recommended: true,
              analysis_role: 'filesystem',
            },
          ],
          string_signals: {
            total_strings: 12,
            matched_count: 3,
            category_counts: {
              credential: 1,
              network: 1,
              dangerous_api: 1,
            },
            top_signals: [
              {
                category: 'credential',
                label: 'Credential or default-login material',
                value: 'admin_password=root',
                offset: 8192,
                offset_hex: '0x2000',
                confidence: 0.82,
              },
              {
                category: 'network',
                label: 'Network endpoint or protocol',
                value: 'http://updates.example/router.bin',
                offset: 8448,
                offset_hex: '0x2100',
                confidence: 0.78,
              },
            ],
          },
          entropy: {
            window_size: 65536,
            sampled_windows: 2,
            average: 6.81,
            max: 7.98,
            high_entropy_threshold: 7.2,
            high_entropy_windows: [
              {
                offset: 0,
                offset_hex: '0x0',
                entropy: 7.98,
                size: 65536,
              },
            ],
          },
          notes: [],
        }}
      />
    );

    expect(screen.getByText('Signal Strings')).toBeInTheDocument();
    expect(screen.getByText('Entropy')).toBeInTheDocument();
    expect(screen.getByText(/credential 1/i)).toBeInTheDocument();
    expect(screen.getByText(/network 1/i)).toBeInTheDocument();
    expect(screen.getByText(/dangerous api 1/i)).toBeInTheDocument();
    expect(screen.getByText(/credential: admin_password=root/i)).toBeInTheDocument();
    expect(screen.getByText(/network: http:\/\/updates\.example\/router\.bin/i)).toBeInTheDocument();
    expect(screen.getByText(/0x0 entropy 7\.98/i)).toBeInTheDocument();
  });
});
