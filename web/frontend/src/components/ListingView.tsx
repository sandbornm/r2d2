import React, { useEffect, useState } from 'react';
import { Box, Typography, CircularProgress, Chip } from '@mui/material';

interface ListingLine {
  type: 'section' | 'function' | 'instruction';
  address?: string;
  bytes?: string;
  instruction?: string;
  name?: string;
  function?: string;
}

interface ListingData {
  filename: string;
  listing: ListingLine[];
  raw?: string;
}

interface ListingViewProps {
  binaryName: string | null;
  height?: string;
}

const API_BASE = '';

export default function ListingView({ binaryName, height = '100%' }: ListingViewProps) {
  const [listing, setListing] = useState<ListingData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!binaryName) {
      setListing(null);
      return;
    }

    const fetchListing = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetch(`${API_BASE}/api/compile/listing/${binaryName}`);
        if (!response.ok) {
          const err = await response.json();
          throw new Error(err.error || 'Failed to fetch listing');
        }
        const data = await response.json();
        setListing(data);
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to load listing');
      } finally {
        setLoading(false);
      }
    };

    fetchListing();
  }, [binaryName]);

  if (!binaryName) {
    return (
      <Box
        sx={{
          height,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'text.disabled',
        }}
      >
        <Typography variant="body2">Compile to see binary listing</Typography>
      </Box>
    );
  }

  if (loading) {
    return (
      <Box
        sx={{
          height,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 1,
        }}
      >
        <CircularProgress size={20} />
        <Typography variant="body2" color="text.secondary">
          Loading listing...
        </Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <Box
        sx={{
          height,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'error.main',
          p: 2,
          textAlign: 'center',
        }}
      >
        <Typography variant="body2">{error}</Typography>
      </Box>
    );
  }

  if (!listing || listing.listing.length === 0) {
    return (
      <Box
        sx={{
          height,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'text.disabled',
        }}
      >
        <Typography variant="body2">No listing data available</Typography>
      </Box>
    );
  }

  // Count instructions for stats
  const instructionCount = listing.listing.filter((l) => l.type === 'instruction').length;
  const functionCount = listing.listing.filter((l) => l.type === 'function').length;

  return (
    <Box
      sx={{
        height,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        bgcolor: '#1a1a1a',
      }}
    >
      {/* Stats bar */}
      <Box
        sx={{
          px: 1,
          py: 0.5,
          borderBottom: '1px solid',
          borderColor: 'divider',
          display: 'flex',
          gap: 1,
          alignItems: 'center',
          flexShrink: 0,
        }}
      >
        <Chip
          label={`${functionCount} functions`}
          size="small"
          variant="outlined"
          sx={{ height: 20, fontSize: '0.65rem' }}
        />
        <Chip
          label={`${instructionCount} instructions`}
          size="small"
          variant="outlined"
          sx={{ height: 20, fontSize: '0.65rem' }}
        />
      </Box>

      {/* Listing content */}
      <Box
        sx={{
          flex: 1,
          overflow: 'auto',
          fontFamily: '"JetBrains Mono", "Fira Code", "Consolas", monospace',
          fontSize: '0.75rem',
          lineHeight: 1.6,
        }}
      >
        {listing.listing.map((line, idx) => {
          if (line.type === 'section') {
            return (
              <Box
                key={idx}
                sx={{
                  px: 1.5,
                  py: 0.75,
                  bgcolor: 'rgba(100, 100, 255, 0.1)',
                  borderTop: idx > 0 ? '1px solid' : 'none',
                  borderBottom: '1px solid',
                  borderColor: 'divider',
                  color: '#7cacf8',
                  fontWeight: 600,
                }}
              >
                {line.name}
              </Box>
            );
          }

          if (line.type === 'function') {
            return (
              <Box
                key={idx}
                sx={{
                  display: 'flex',
                  px: 1.5,
                  py: 0.5,
                  bgcolor: 'rgba(255, 200, 100, 0.08)',
                  borderTop: '1px solid',
                  borderColor: 'rgba(255, 200, 100, 0.2)',
                  mt: idx > 0 ? 0.5 : 0,
                }}
              >
                <Box sx={{ width: 90, color: '#6a9955', flexShrink: 0 }}>
                  {line.address}
                </Box>
                <Box sx={{ color: '#dcdcaa', fontWeight: 600 }}>
                  {'<'}{line.name}{'>'}:
                </Box>
              </Box>
            );
          }

          if (line.type === 'instruction') {
            // Parse instruction to highlight different parts
            const instr = line.instruction || '';
            const parts = instr.split(/\s+/);
            const mnemonic = parts[0] || '';
            const operands = parts.slice(1).join(' ');

            // Color based on instruction type
            let mnemonicColor = '#569cd6'; // default blue for most instructions
            if (/^b\.?/.test(mnemonic) || mnemonic === 'ret' || mnemonic === 'bl' || mnemonic === 'blr') {
              mnemonicColor = '#c586c0'; // purple for branches
            } else if (/^ldr|^str|^ldp|^stp|^push|^pop/.test(mnemonic)) {
              mnemonicColor = '#4ec9b0'; // teal for memory ops
            } else if (/^mov|^mvn|^add|^sub|^mul|^div|^and|^orr|^eor|^lsl|^lsr|^asr/.test(mnemonic)) {
              mnemonicColor = '#9cdcfe'; // light blue for arithmetic
            } else if (/^cmp|^tst|^cmn/.test(mnemonic)) {
              mnemonicColor = '#ce9178'; // orange for comparisons
            } else if (/^svc|^nop|^udf/.test(mnemonic)) {
              mnemonicColor = '#d16969'; // red for syscalls/special
            }

            return (
              <Box
                key={idx}
                sx={{
                  display: 'flex',
                  px: 1.5,
                  py: 0.15,
                  '&:hover': { bgcolor: 'rgba(255,255,255,0.03)' },
                }}
              >
                {/* Address */}
                <Box
                  sx={{
                    width: 90,
                    color: '#6a9955',
                    flexShrink: 0,
                    userSelect: 'none',
                  }}
                >
                  {line.address}
                </Box>

                {/* Bytes */}
                <Box
                  sx={{
                    width: 100,
                    color: '#808080',
                    flexShrink: 0,
                    letterSpacing: '0.05em',
                  }}
                >
                  {line.bytes}
                </Box>

                {/* Mnemonic */}
                <Box
                  sx={{
                    width: 60,
                    color: mnemonicColor,
                    fontWeight: 500,
                    flexShrink: 0,
                  }}
                >
                  {mnemonic}
                </Box>

                {/* Operands */}
                <Box sx={{ color: '#d4d4d4', flex: 1 }}>
                  {operands.split(',').map((op, i, arr) => {
                    const trimmed = op.trim();
                    // Highlight registers
                    const isReg = /^[xwrsp]\d+$|^sp$|^lr$|^pc$|^fp$/i.test(trimmed);
                    // Highlight immediates
                    const isImm = /^#/.test(trimmed) || /^0x/.test(trimmed);
                    // Highlight memory references
                    const isMem = /^\[/.test(trimmed);

                    let color = '#d4d4d4';
                    if (isReg) color = '#9cdcfe';
                    else if (isImm) color = '#b5cea8';
                    else if (isMem) color = '#ce9178';

                    return (
                      <span key={i}>
                        <span style={{ color }}>{trimmed}</span>
                        {i < arr.length - 1 && <span style={{ color: '#808080' }}>, </span>}
                      </span>
                    );
                  })}
                </Box>
              </Box>
            );
          }

          return null;
        })}
      </Box>
    </Box>
  );
}

