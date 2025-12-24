import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import SelectAllIcon from '@mui/icons-material/SelectAll';
import { alpha, Box, Button, IconButton, Popover, Stack, TextField, Tooltip, Typography, useTheme } from '@mui/material';
import { FC, useCallback, useMemo, useRef, useState } from 'react';

import type { AssemblyAnnotation } from '../types';

interface DisassemblyViewerProps {
  disassembly: string;
  arch?: string;
  annotations?: AssemblyAnnotation[];
  onAnnotate?: (address: string, note: string) => void;
  onAskAbout?: (selectedCode: string) => void;  // For asking Claude about selected code
}

// ARM instruction documentation (Thumb/ARM32/ARM64)
const ARM_DOCS: Record<string, string> = {
  // Data processing
  'mov': 'Move: Copy value to register. MOV Rd, Op2',
  'movs': 'Move with flags update: Copy value and update condition flags',
  'movw': 'Move wide: Load 16-bit immediate into lower halfword',
  'movt': 'Move top: Load 16-bit immediate into upper halfword',
  'mvn': 'Move NOT: Copy bitwise complement to register',
  'add': 'Add: Rd = Rn + Op2',
  'adds': 'Add with flags: Rd = Rn + Op2, update NZCV flags',
  'adc': 'Add with carry: Rd = Rn + Op2 + Carry',
  'sub': 'Subtract: Rd = Rn - Op2',
  'subs': 'Subtract with flags: Rd = Rn - Op2, update NZCV flags',
  'sbc': 'Subtract with carry: Rd = Rn - Op2 - NOT(Carry)',
  'rsb': 'Reverse subtract: Rd = Op2 - Rn',
  'mul': 'Multiply: Rd = Rm × Rs (32-bit result)',
  'mla': 'Multiply-accumulate: Rd = (Rm × Rs) + Rn',
  'umull': 'Unsigned multiply long: 64-bit = Rm × Rs',
  'smull': 'Signed multiply long: 64-bit = Rm × Rs',
  'sdiv': 'Signed divide: Rd = Rn / Rm',
  'udiv': 'Unsigned divide: Rd = Rn / Rm',
  'and': 'Bitwise AND: Rd = Rn & Op2',
  'ands': 'Bitwise AND with flags update',
  'orr': 'Bitwise OR: Rd = Rn | Op2',
  'eor': 'Bitwise XOR: Rd = Rn ^ Op2',
  'bic': 'Bit clear: Rd = Rn & ~Op2',
  'lsl': 'Logical shift left: Rd = Rm << n',
  'lsr': 'Logical shift right: Rd = Rm >> n (zero fill)',
  'asr': 'Arithmetic shift right: Rd = Rm >> n (sign extend)',
  'ror': 'Rotate right: circular shift',
  'cmp': 'Compare: Update flags based on Rn - Op2',
  'cmn': 'Compare negative: Update flags based on Rn + Op2',
  'tst': 'Test bits: Update flags based on Rn & Op2',
  'teq': 'Test equivalence: Update flags based on Rn ^ Op2',
  'neg': 'Negate: Rd = 0 - Rm',
  'adr': 'Address: Load PC-relative address into register',
  // Load/Store
  'ldr': 'Load register: Load 32-bit word from memory',
  'ldrb': 'Load register byte: Load 8-bit value, zero-extend',
  'ldrh': 'Load register halfword: Load 16-bit value, zero-extend',
  'ldrsb': 'Load register signed byte: Load 8-bit value, sign-extend',
  'ldrsh': 'Load register signed halfword: Load 16-bit value, sign-extend',
  'ldrd': 'Load register double: Load 64-bit value to register pair',
  'ldm': 'Load multiple: Pop multiple registers from memory',
  'ldmia': 'Load multiple increment after: Pop registers, increment base',
  'ldmdb': 'Load multiple decrement before: Pop registers, decrement base',
  'str': 'Store register: Store 32-bit word to memory',
  'strb': 'Store register byte: Store 8-bit value',
  'strh': 'Store register halfword: Store 16-bit value',
  'strd': 'Store register double: Store 64-bit value from register pair',
  'stm': 'Store multiple: Push multiple registers to memory',
  'stmia': 'Store multiple increment after: Push registers, increment base',
  'stmdb': 'Store multiple decrement before (PUSH): Push registers, decrement base',
  'push': 'Push registers onto stack: SP -= 4×n, store registers',
  'pop': 'Pop registers from stack: Load registers, SP += 4×n',
  // Branch
  'b': 'Branch: Unconditional jump to label',
  'bl': 'Branch with link: Call subroutine, save return address in LR',
  'blx': 'Branch with link and exchange: Call with possible mode switch (ARM↔Thumb)',
  'bx': 'Branch and exchange: Jump with possible mode switch',
  'beq': 'Branch if equal: Jump if Z flag set',
  'bne': 'Branch if not equal: Jump if Z flag clear',
  'bgt': 'Branch if greater than (signed): Jump if Z=0 and N=V',
  'bge': 'Branch if greater or equal (signed): Jump if N=V',
  'blt': 'Branch if less than (signed): Jump if N≠V',
  'ble': 'Branch if less or equal (signed): Jump if Z=1 or N≠V',
  'bhi': 'Branch if higher (unsigned): Jump if C=1 and Z=0',
  'bhs': 'Branch if higher or same (unsigned): Jump if C=1',
  'blo': 'Branch if lower (unsigned): Jump if C=0',
  'bls': 'Branch if lower or same (unsigned): Jump if C=0 or Z=1',
  'bcs': 'Branch if carry set: Jump if C flag set',
  'bcc': 'Branch if carry clear: Jump if C flag clear',
  'bmi': 'Branch if minus: Jump if N flag set',
  'bpl': 'Branch if plus: Jump if N flag clear',
  'bvs': 'Branch if overflow set: Jump if V flag set',
  'bvc': 'Branch if overflow clear: Jump if V flag clear',
  'cbz': 'Compare and branch if zero: if Rn == 0, branch',
  'cbnz': 'Compare and branch if not zero: if Rn != 0, branch',
  'it': 'If-Then: Make following 1-4 instructions conditional',
  'ite': 'If-Then-Else: Conditional block with else clause',
  // System
  'svc': 'Supervisor call: Trigger system call exception (syscall)',
  'swi': 'Software interrupt: Trigger system call (legacy name for SVC)',
  'bkpt': 'Breakpoint: Trigger debug exception',
  'nop': 'No operation: Do nothing (often MOV r0, r0)',
  'wfi': 'Wait for interrupt: Enter low-power state',
  'wfe': 'Wait for event: Enter low-power state until event',
  'sev': 'Send event: Signal other cores',
  'dmb': 'Data memory barrier: Ensure memory access ordering',
  'dsb': 'Data synchronization barrier: Complete all memory accesses',
  'isb': 'Instruction synchronization barrier: Flush pipeline',
  'mrs': 'Move to register from special: Read system register',
  'msr': 'Move to special from register: Write system register',
  // SIMD/VFP
  'vmov': 'Vector move: Move data between ARM and VFP/NEON registers',
  'vldr': 'Vector load: Load floating-point register from memory',
  'vstr': 'Vector store: Store floating-point register to memory',
  'vadd': 'Vector add: Floating-point addition',
  'vsub': 'Vector subtract: Floating-point subtraction',
  'vmul': 'Vector multiply: Floating-point multiplication',
  'vdiv': 'Vector divide: Floating-point division',
  'vcmp': 'Vector compare: Compare floating-point values',
  // Thumb-2 specific
  'ldr.w': 'Load register wide: 32-bit Thumb-2 LDR encoding',
  'str.w': 'Store register wide: 32-bit Thumb-2 STR encoding',
  'add.w': 'Add wide: 32-bit Thumb-2 ADD encoding',
};

// x86/x64 instruction documentation
const X86_DOCS: Record<string, string> = {
  // Data movement
  'mov': 'Move: Copy source to destination',
  'movzx': 'Move with zero-extend: Copy and zero-extend to larger size',
  'movsx': 'Move with sign-extend: Copy and sign-extend to larger size',
  'movsxd': 'Move with sign-extend doubleword: Sign-extend 32-bit to 64-bit',
  'movabs': 'Move absolute: Load 64-bit immediate (x64)',
  'lea': 'Load effective address: Calculate address without dereferencing',
  'push': 'Push onto stack: Decrement SP, store value',
  'pop': 'Pop from stack: Load value, increment SP',
  'xchg': 'Exchange: Swap two operands atomically',
  'cmov': 'Conditional move: Move if condition is met',
  'cmove': 'Conditional move if equal: Move if ZF=1',
  'cmovne': 'Conditional move if not equal: Move if ZF=0',
  'cmovg': 'Conditional move if greater (signed)',
  'cmovl': 'Conditional move if less (signed)',
  // Arithmetic
  'add': 'Add: dest = dest + src',
  'sub': 'Subtract: dest = dest - src',
  'imul': 'Signed multiply: Signed integer multiplication',
  'mul': 'Unsigned multiply: Unsigned integer multiplication',
  'idiv': 'Signed divide: Signed integer division',
  'div': 'Unsigned divide: Unsigned integer division',
  'inc': 'Increment: dest = dest + 1',
  'dec': 'Decrement: dest = dest - 1',
  'neg': 'Negate: dest = -dest (two\'s complement)',
  'adc': 'Add with carry: dest = dest + src + CF',
  'sbb': 'Subtract with borrow: dest = dest - src - CF',
  // Logic
  'and': 'Bitwise AND: dest = dest & src',
  'or': 'Bitwise OR: dest = dest | src',
  'xor': 'Bitwise XOR: dest = dest ^ src',
  'not': 'Bitwise NOT: dest = ~dest',
  'shl': 'Shift left: dest = dest << count',
  'shr': 'Shift right logical: dest = dest >> count (zero fill)',
  'sar': 'Shift right arithmetic: dest = dest >> count (sign fill)',
  'rol': 'Rotate left: Circular shift left',
  'ror': 'Rotate right: Circular shift right',
  // Compare/Test
  'cmp': 'Compare: Set flags based on dest - src',
  'test': 'Test bits: Set flags based on dest & src',
  // Control flow
  'jmp': 'Jump: Unconditional jump to address',
  'call': 'Call: Push return address, jump to function',
  'ret': 'Return: Pop return address, jump to it',
  'je': 'Jump if equal: Jump if ZF=1',
  'jne': 'Jump if not equal: Jump if ZF=0',
  'jz': 'Jump if zero: Jump if ZF=1 (same as JE)',
  'jnz': 'Jump if not zero: Jump if ZF=0 (same as JNE)',
  'jg': 'Jump if greater (signed): ZF=0 and SF=OF',
  'jge': 'Jump if greater or equal (signed): SF=OF',
  'jl': 'Jump if less (signed): SF≠OF',
  'jle': 'Jump if less or equal (signed): ZF=1 or SF≠OF',
  'ja': 'Jump if above (unsigned): CF=0 and ZF=0',
  'jae': 'Jump if above or equal (unsigned): CF=0',
  'jb': 'Jump if below (unsigned): CF=1',
  'jbe': 'Jump if below or equal (unsigned): CF=1 or ZF=1',
  'js': 'Jump if sign (negative): SF=1',
  'jns': 'Jump if not sign (positive): SF=0',
  'jo': 'Jump if overflow: OF=1',
  'jno': 'Jump if not overflow: OF=0',
  // Stack frame
  'enter': 'Make stack frame: Push BP, BP=SP, allocate locals',
  'leave': 'Destroy stack frame: SP=BP, pop BP',
  // String ops
  'rep': 'Repeat prefix: Repeat following instruction CX times',
  'movsb': 'Move string byte: Copy byte from [SI] to [DI]',
  'stosb': 'Store string byte: Store AL at [DI]',
  'lodsb': 'Load string byte: Load [SI] into AL',
  'cmpsb': 'Compare string bytes: Compare [SI] with [DI]',
  'scasb': 'Scan string byte: Compare AL with [DI]',
  // System
  'syscall': 'System call: Invoke OS kernel (x64)',
  'int': 'Interrupt: Trigger software interrupt',
  'nop': 'No operation: Do nothing',
  'hlt': 'Halt: Stop execution until interrupt',
  'cpuid': 'CPU identification: Query processor info',
  'rdtsc': 'Read timestamp counter: Get cycle count',
  // SSE/AVX
  'movss': 'Move scalar single: Move 32-bit float',
  'movsd': 'Move scalar double: Move 64-bit float',
  'movaps': 'Move aligned packed single: Move 128-bit aligned',
  'movups': 'Move unaligned packed single: Move 128-bit unaligned',
  'addss': 'Add scalar single: Float addition',
  'subss': 'Subtract scalar single: Float subtraction',
  'mulss': 'Multiply scalar single: Float multiplication',
  'divss': 'Divide scalar single: Float division',
  'xorps': 'XOR packed single: Bitwise XOR on 128-bit',
  'pxor': 'Packed XOR: Bitwise XOR on packed integers',
  'endbr64': 'End branch 64: CET indirect branch tracking marker',
  'endbr32': 'End branch 32: CET indirect branch tracking marker',
};

// Get instruction docs based on architecture
const getInstructionDocs = (mnemonic: string, arch: string): string | null => {
  const normalizedMnemonic = mnemonic.toLowerCase().replace(/\.w$/, '');
  
  // Check for conditional suffixes on ARM
  if (arch.includes('arm') || arch.includes('thumb')) {
    // Strip condition codes for lookup
    const armBase = normalizedMnemonic.replace(/(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al|hs|lo)$/, '');
    if (ARM_DOCS[normalizedMnemonic]) return ARM_DOCS[normalizedMnemonic];
    if (ARM_DOCS[armBase]) return ARM_DOCS[armBase];
  }
  
  if (arch.includes('x86') || arch.includes('amd64') || arch.includes('i386')) {
    if (X86_DOCS[normalizedMnemonic]) return X86_DOCS[normalizedMnemonic];
  }
  
  // Fallback: check both
  return ARM_DOCS[normalizedMnemonic] || X86_DOCS[normalizedMnemonic] || null;
};

interface ParsedInstruction {
  address?: string;
  bytes?: string;
  mnemonic?: string;
  operands?: string;
  comment?: string;
  raw: string;
  isLabel?: boolean;
  isComment?: boolean;
  isEmpty?: boolean;
}

// Parse a single line of radare2 disassembly
const parseDisasmLine = (line: string): ParsedInstruction => {
  const trimmed = line.trimEnd();
  
  // Empty line
  if (!trimmed) {
    return { raw: line, isEmpty: true };
  }
  
  // Pure comment line (starts with ; after optional whitespace)
  if (/^\s*;/.test(trimmed)) {
    return { raw: line, isComment: true, comment: trimmed };
  }
  
  // Label line (ends with : and has no instruction)
  if (/^\s*\w+:$/.test(trimmed) || /^[│├└─\s]*;--\s*\w+:?/.test(trimmed)) {
    return { raw: line, isLabel: true };
  }
  
  // Try to parse standard radare2 format: 
  // │ │ 0x000003fc 4ff0000b mov.w fp, 0 ; [13] -r-x section...
  // or simpler: 0x000003fc 4ff0000b mov.w fp, 0
  
  const patterns = [
    // Full r2 format with tree chars
    /^([│├└─\s]*)\s*(0x[0-9a-f]+)\s+([0-9a-f]+)\s+(\w+(?:\.\w+)?)\s*([^;]*)?(?:;\s*(.*))?$/i,
    // Simple format
    /^\s*(0x[0-9a-f]+):\s*([0-9a-f]+)\s+(\w+(?:\.\w+)?)\s*([^;]*)?(?:;\s*(.*))?$/i,
    // Another common format
    /^\s*(0x[0-9a-f]+)\s+(\w+(?:\.\w+)?)\s*([^;]*)?(?:;\s*(.*))?$/i,
  ];
  
  for (const pattern of patterns) {
    const match = trimmed.match(pattern);
    if (match) {
      if (pattern === patterns[0]) {
        return {
          raw: line,
          address: match[2],
          bytes: match[3],
          mnemonic: match[4],
          operands: match[5]?.trim(),
          comment: match[6],
        };
      } else if (pattern === patterns[1]) {
        return {
          raw: line,
          address: match[1],
          bytes: match[2],
          mnemonic: match[3],
          operands: match[4]?.trim(),
          comment: match[5],
        };
      } else {
        return {
          raw: line,
          address: match[1],
          mnemonic: match[2],
          operands: match[3]?.trim(),
          comment: match[4],
        };
      }
    }
  }
  
  // Fallback: treat as raw line
  return { raw: line };
};

// Build ARM documentation URL - uses official ARM Developer docs
// Reference: https://developer.arm.com/documentation/dui0489/h/arm-and-thumb-instructions/instruction-summary
const getARMDocUrl = (mnemonic: string): string => {
  const cleanMnemonic = mnemonic.toLowerCase().replace(/\.w$/, '').replace(/(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al|hs|lo)$/, '');
  // ARM Developer documentation - Thumb/ARM instruction reference
  // The URL pattern depends on the instruction category
  return `https://developer.arm.com/documentation/dui0489/h/arm-and-thumb-instructions/${cleanMnemonic.toUpperCase()}`;
};

// Alternative ARM doc URL for search fallback
const getARMSearchUrl = (mnemonic: string): string => {
  const cleanMnemonic = mnemonic.toLowerCase().replace(/\.w$/, '');
  return `https://developer.arm.com/search#q=${encodeURIComponent(cleanMnemonic + ' instruction')}&sort=relevancy`;
};

// Build x86 documentation URL
const getX86DocUrl = (mnemonic: string): string => {
  const cleanMnemonic = mnemonic.toLowerCase();
  // Use Felix Cloutier's x86 reference (community standard)
  return `https://www.felixcloutier.com/x86/${cleanMnemonic}`;
};

interface InstructionLineProps {
  parsed: ParsedInstruction;
  arch: string;
  annotation?: string;
}

const InstructionLine: FC<InstructionLineProps> = ({ parsed, arch, annotation }) => {
  const theme = useTheme();
  const [hovered, setHovered] = useState(false);
  
  const isDark = theme.palette.mode === 'dark';
  
  // Colors for syntax highlighting
  const colors = {
    address: isDark ? '#6a9fb5' : '#0550ae',
    bytes: isDark ? '#555' : '#999',
    mnemonic: isDark ? '#b294bb' : '#a626a4',
    register: isDark ? '#cc6666' : '#c18401',
    immediate: isDark ? '#8abeb7' : '#0184bc',
    memory: isDark ? '#f0c674' : '#50a14f',
    comment: isDark ? '#5a5a5a' : '#a0a0a0',
    label: isDark ? '#81a2be' : '#4078f2',
    tree: isDark ? '#333' : '#ddd',
  };
  
  // Get instruction documentation
  const docs = parsed.mnemonic ? getInstructionDocs(parsed.mnemonic, arch) : null;
  
  // Highlight operands (registers, immediates, memory refs)
  const highlightOperands = useCallback((operands: string) => {
    if (!operands) return null;
    
    const parts: JSX.Element[] = [];
    let key = 0;
    
    // Split by common delimiters while preserving them
    const tokens = operands.split(/(\s+|,|\[|\]|\{|\})/);
    
    for (const token of tokens) {
      if (!token) continue;
      
      // Register patterns
      if (/^(r\d+|sp|lr|pc|fp|ip|sl|sb|[re]?[abcd]x|[re]?[sd]i|[re]?bp|[re]?sp|r\d{1,2}[dwb]?|[xy]mm\d+|zmm\d+)$/i.test(token)) {
        parts.push(<span key={key++} style={{ color: colors.register }}>{token}</span>);
      }
      // Immediate values (hex or decimal)
      else if (/^#?-?0x[0-9a-f]+$/i.test(token) || /^#?-?\d+$/.test(token)) {
        parts.push(<span key={key++} style={{ color: colors.immediate }}>{token}</span>);
      }
      // Memory brackets
      else if (token === '[' || token === ']') {
        parts.push(<span key={key++} style={{ color: colors.memory }}>{token}</span>);
      }
      // Everything else
      else {
        parts.push(<span key={key++}>{token}</span>);
      }
    }
    
    return parts;
  }, [colors]);
  
  // Handle special line types
  if (parsed.isEmpty) {
    return <Box sx={{ height: '1.4em' }} />;
  }
  
  if (parsed.isComment) {
    return (
      <Box sx={{ color: colors.comment, fontStyle: 'italic' }}>
        {parsed.raw}
      </Box>
    );
  }
  
  if (parsed.isLabel) {
    return (
      <Box sx={{ color: colors.label, fontWeight: 600 }}>
        {parsed.raw}
      </Box>
    );
  }
  
  // If we couldn't parse it, check for tree characters and try to extract
  if (!parsed.mnemonic) {
    // Still try to colorize any recognizable parts
    const treeMatch = parsed.raw.match(/^([│├└─\s]*)(.*)/);
    if (treeMatch && treeMatch[1]) {
      return (
        <Box>
          <span style={{ color: colors.tree }}>{treeMatch[1]}</span>
          <span>{treeMatch[2]}</span>
        </Box>
      );
    }
    return <Box>{parsed.raw}</Box>;
  }
  
  // Render parsed instruction with syntax highlighting
  const instructionContent = (
    <Box
      component="span"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      sx={{
        display: 'inline-flex',
        alignItems: 'baseline',
        gap: '1ch',
        cursor: docs ? 'help' : 'default',
        backgroundColor: hovered && docs ? (isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.03)') : 'transparent',
        borderRadius: 0.5,
        px: hovered && docs ? 0.5 : 0,
        mx: hovered && docs ? -0.5 : 0,
        transition: 'background-color 0.15s',
      }}
    >
      {/* Address */}
      {parsed.address && (
        <span style={{ color: colors.address, minWidth: '10ch' }}>{parsed.address}</span>
      )}
      
      {/* Bytes */}
      {parsed.bytes && (
        <span style={{ color: colors.bytes, minWidth: '8ch', fontSize: '0.9em' }}>{parsed.bytes}</span>
      )}
      
      {/* Mnemonic */}
      <span style={{ color: colors.mnemonic, fontWeight: 500, minWidth: '6ch' }}>
        {parsed.mnemonic}
      </span>
      
      {/* Operands */}
      {parsed.operands && (
        <span style={{ minWidth: '20ch' }}>
          {highlightOperands(parsed.operands)}
        </span>
      )}
      
      {/* Comment */}
      {parsed.comment && (
        <span style={{ color: colors.comment, marginLeft: '2ch' }}>
          ; {parsed.comment}
        </span>
      )}
    </Box>
  );
  
  // Build documentation URL based on architecture
  const isARM = arch.includes('arm') || arch.includes('thumb');
  const isX86 = arch.includes('x86') || arch.includes('amd64') || arch.includes('i386');
  const docUrl = parsed.mnemonic 
    ? (isARM ? getARMDocUrl(parsed.mnemonic) : isX86 ? getX86DocUrl(parsed.mnemonic) : null)
    : null;

  // Wrap with tooltip if we have docs
  if (docs) {
    return (
      <Tooltip
        title={
          <Box sx={{ maxWidth: 400 }}>
            <Stack direction="row" alignItems="center" justifyContent="space-between" spacing={1}>
              <Typography variant="subtitle2" fontWeight={600} sx={{ fontFamily: 'monospace' }}>
                {parsed.mnemonic?.toUpperCase()}
              </Typography>
              {docUrl && (
                <Tooltip title="Look up in official docs">
                  <IconButton
                    size="small"
                    onClick={(e) => {
                      e.stopPropagation();
                      window.open(docUrl, '_blank', 'noopener');
                    }}
                    sx={{ p: 0.25, color: 'primary.light' }}
                  >
                    <OpenInNewIcon sx={{ fontSize: 14 }} />
                  </IconButton>
                </Tooltip>
              )}
            </Stack>
            <Typography variant="body2" sx={{ mt: 0.5 }}>
              {docs}
            </Typography>
            {isARM && (
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block', fontStyle: 'italic' }}>
                Click icon to view ARM reference
              </Typography>
            )}
          </Box>
        }
        placement="right"
        arrow
        enterDelay={200}
        leaveDelay={100}
      >
        <Box 
          component="div" 
          sx={{ 
            display: 'flex', 
            alignItems: 'center',
            gap: 1,
          }}
        >
          {instructionContent}
          {annotation && (
            <Typography 
              variant="caption" 
              sx={{ 
                color: 'warning.main', 
                fontStyle: 'italic',
                fontSize: '0.7rem',
                ml: 1,
              }}
            >
              📝 {annotation}
            </Typography>
          )}
        </Box>
      </Tooltip>
    );
  }
  
  return (
    <Box 
      sx={{ 
        display: 'flex', 
        alignItems: 'center',
        gap: 1,
      }}
    >
      {instructionContent}
      {annotation && (
        <Typography 
          variant="caption" 
          sx={{ 
            color: 'warning.main', 
            fontStyle: 'italic',
            fontSize: '0.7rem',
            ml: 1,
          }}
        >
          📝 {annotation}
        </Typography>
      )}
    </Box>
  );
};

const DisassemblyViewer: FC<DisassemblyViewerProps> = ({ 
  disassembly, 
  arch = 'unknown',
  annotations = [],
  onAnnotate,
  onAskAbout,
}) => {
  const theme = useTheme();
  const [copied, setCopied] = useState(false);
  const [selectionStart, setSelectionStart] = useState<number | null>(null);
  const [selectionEnd, setSelectionEnd] = useState<number | null>(null);
  const [isSelecting, setIsSelecting] = useState(false);
  const [selectionPopoverAnchor, setSelectionPopoverAnchor] = useState<HTMLElement | null>(null);
  const [rangeAnnotationText, setRangeAnnotationText] = useState('');
  const containerRef = useRef<HTMLDivElement>(null);
  
  const lines = useMemo(() => {
    return disassembly.split('\n').map(parseDisasmLine);
  }, [disassembly]);

  // Build annotation lookup map
  const annotationMap = useMemo(() => {
    const map: Record<string, string> = {};
    for (const ann of annotations) {
      map[ann.address] = ann.note;
    }
    return map;
  }, [annotations]);

  // Get selected lines
  const selectedLines = useMemo(() => {
    if (selectionStart === null || selectionEnd === null) return [];
    const start = Math.min(selectionStart, selectionEnd);
    const end = Math.max(selectionStart, selectionEnd);
    return lines.slice(start, end + 1);
  }, [lines, selectionStart, selectionEnd]);

  const selectedText = useMemo(() => {
    return selectedLines.map(l => l.raw).join('\n');
  }, [selectedLines]);

  // Selection handlers
  const handleLineMouseDown = useCallback((index: number, e: React.MouseEvent) => {
    if (e.button !== 0) return; // Only left click
    setIsSelecting(true);
    setSelectionStart(index);
    setSelectionEnd(index);
    setSelectionPopoverAnchor(null);
  }, []);

  const handleLineMouseEnter = useCallback((index: number) => {
    if (isSelecting) {
      setSelectionEnd(index);
    }
  }, [isSelecting]);

  const handleMouseUp = useCallback(() => {
    if (isSelecting && selectionStart !== null && selectionEnd !== null) {
      setIsSelecting(false);
      // Show popover if we have a selection of more than one line
      if (Math.abs(selectionEnd - selectionStart) >= 0 && containerRef.current) {
        setSelectionPopoverAnchor(containerRef.current);
      }
    }
  }, [isSelecting, selectionStart, selectionEnd]);

  const handleClearSelection = useCallback(() => {
    setSelectionStart(null);
    setSelectionEnd(null);
    setSelectionPopoverAnchor(null);
    setRangeAnnotationText('');
  }, []);

  const handleCopySelection = useCallback(() => {
    navigator.clipboard.writeText(selectedText);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [selectedText]);

  const handleAskAboutSelection = useCallback(() => {
    if (onAskAbout && selectedText) {
      onAskAbout(selectedText);
    }
    handleClearSelection();
  }, [onAskAbout, selectedText, handleClearSelection]);

  const handleAnnotateRange = useCallback(() => {
    if (onAnnotate && selectedLines.length > 0 && rangeAnnotationText.trim()) {
      // Get the first address in the range
      const firstWithAddr = selectedLines.find(l => l.address);
      if (firstWithAddr?.address) {
        onAnnotate(firstWithAddr.address, rangeAnnotationText.trim());
      }
    }
    handleClearSelection();
  }, [onAnnotate, selectedLines, rangeAnnotationText, handleClearSelection]);

  const isLineSelected = useCallback((index: number) => {
    if (selectionStart === null || selectionEnd === null) return false;
    const start = Math.min(selectionStart, selectionEnd);
    const end = Math.max(selectionStart, selectionEnd);
    return index >= start && index <= end;
  }, [selectionStart, selectionEnd]);
  
  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(disassembly);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [disassembly]);
  
  const isDark = theme.palette.mode === 'dark';
  const isARM = arch.includes('arm') || arch.includes('thumb');
  
  // State for user question input
  const [askQuestionText, setAskQuestionText] = useState('');
  const [showAskInput, setShowAskInput] = useState(false);

  const handleShowAskInput = useCallback(() => {
    setShowAskInput(true);
    setAskQuestionText('');
  }, []);

  const handleAskWithQuestion = useCallback(() => {
    if (onAskAbout && selectedText) {
      // If user provided a question, include it; otherwise use boilerplate
      const userQuestion = askQuestionText.trim();
      if (userQuestion) {
        // User provided their own question
        onAskAbout(`${userQuestion}\n\n\`\`\`asm\n${selectedText}\n\`\`\``);
      } else {
        // No user question - use boilerplate analysis
        onAskAbout(selectedText);
      }
    }
    handleClearSelection();
    setShowAskInput(false);
    setAskQuestionText('');
  }, [onAskAbout, selectedText, askQuestionText, handleClearSelection]);

  // Selection popover for range actions
  const selectionPopover = (
    <Popover
      open={Boolean(selectionPopoverAnchor) && selectedLines.length > 0}
      anchorEl={selectionPopoverAnchor}
      onClose={() => {
        handleClearSelection();
        setShowAskInput(false);
        setAskQuestionText('');
      }}
      anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
      transformOrigin={{ vertical: 'bottom', horizontal: 'center' }}
    >
      <Box sx={{ p: 1.5, width: 360 }}>
        <Typography variant="caption" color="text.secondary" fontWeight={600} sx={{ mb: 1, display: 'block' }}>
          {selectedLines.length} line{selectedLines.length !== 1 ? 's' : ''} selected
        </Typography>
        
        {/* Main action buttons */}
        <Stack direction="row" spacing={1} sx={{ mb: 1 }}>
          <Tooltip title="Copy selection">
            <Button size="small" variant="outlined" onClick={handleCopySelection} startIcon={<ContentCopyIcon sx={{ fontSize: 14 }} />}>
              Copy
            </Button>
          </Tooltip>
          {onAskAbout && !showAskInput && (
            <Tooltip title="Ask Claude about this code">
              <Button size="small" variant="contained" onClick={handleShowAskInput}>
                Ask Claude
              </Button>
            </Tooltip>
          )}
        </Stack>

        {/* Ask Claude input area */}
        {onAskAbout && showAskInput && (
          <Box sx={{ mt: 1, pt: 1, borderTop: 1, borderColor: 'divider' }}>
            <Typography variant="caption" color="primary.main" fontWeight={600} sx={{ mb: 0.5, display: 'block' }}>
              Ask Claude about this code:
            </Typography>
            <TextField
              size="small"
              multiline
              rows={2}
              fullWidth
              autoFocus
              placeholder="What would you like to know? (leave empty for general analysis)"
              value={askQuestionText}
              onChange={(e) => setAskQuestionText(e.target.value)}
              sx={{ mb: 1 }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && e.ctrlKey) {
                  e.preventDefault();
                  handleAskWithQuestion();
                }
              }}
            />
            <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: 'block' }}>
              Press Ctrl+Enter to send, or leave empty for default analysis
            </Typography>
            <Stack direction="row" spacing={1} justifyContent="flex-end">
              <Button size="small" onClick={() => setShowAskInput(false)}>Cancel</Button>
              <Button size="small" variant="contained" onClick={handleAskWithQuestion}>
                {askQuestionText.trim() ? 'Ask' : 'Analyze'}
              </Button>
            </Stack>
          </Box>
        )}

        {/* Annotation input */}
        {onAnnotate && !showAskInput && (
          <Box sx={{ mt: 1, pt: 1, borderTop: 1, borderColor: 'divider' }}>
            <TextField
              size="small"
              multiline
              rows={2}
              fullWidth
              placeholder="Add annotation for this range..."
              value={rangeAnnotationText}
              onChange={(e) => setRangeAnnotationText(e.target.value)}
              sx={{ mb: 1 }}
            />
            <Stack direction="row" spacing={1} justifyContent="flex-end">
              <Button size="small" onClick={handleClearSelection}>Cancel</Button>
              <Button 
                size="small" 
                variant="contained" 
                onClick={handleAnnotateRange}
                disabled={!rangeAnnotationText.trim()}
              >
                Annotate
              </Button>
            </Stack>
          </Box>
        )}
      </Box>
    </Popover>
  );

  return (
    <Box>
      {selectionPopover}
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
        <Stack direction="row" spacing={1} alignItems="center">
          <Typography variant="caption" color="text.secondary" fontWeight={600}>
            Entry point disassembly
          </Typography>
          {isARM && (
            <Typography variant="caption" sx={{ 
              px: 0.75, 
              py: 0.25, 
              bgcolor: 'primary.main', 
              color: 'primary.contrastText',
              borderRadius: 0.5,
              fontSize: '0.65rem',
            }}>
              ARM
            </Typography>
          )}
          {selectionStart !== null && selectionEnd !== null && (
            <Typography variant="caption" sx={{ 
              px: 0.75, 
              py: 0.25, 
              bgcolor: alpha(theme.palette.warning.main, 0.2),
              color: 'warning.main',
              borderRadius: 0.5,
              fontSize: '0.65rem',
            }}>
              {Math.abs(selectionEnd - selectionStart) + 1} selected
            </Typography>
          )}
        </Stack>
        <Stack direction="row" spacing={0.5}>
          {selectionStart !== null && (
            <Tooltip title="Clear selection">
              <IconButton size="small" onClick={handleClearSelection}>
                <SelectAllIcon sx={{ fontSize: 14 }} />
              </IconButton>
            </Tooltip>
          )}
          <Tooltip title={copied ? 'Copied!' : 'Copy all'}>
            <IconButton size="small" onClick={handleCopy}>
              <ContentCopyIcon sx={{ fontSize: 14 }} />
            </IconButton>
          </Tooltip>
          {isARM && (
            <Tooltip title="ARM Reference Manual">
              <IconButton 
                size="small" 
                onClick={() => window.open('https://developer.arm.com/documentation/ddi0487/latest/', '_blank', 'noopener')}
              >
                <OpenInNewIcon sx={{ fontSize: 14 }} />
              </IconButton>
            </Tooltip>
          )}
        </Stack>
      </Stack>
      
      <Box
        ref={containerRef}
        onMouseUp={handleMouseUp}
        onMouseLeave={() => isSelecting && setIsSelecting(false)}
        sx={{
          fontFamily: '"JetBrains Mono", "Fira Code", "SF Mono", Consolas, monospace',
          fontSize: '0.72rem',
          lineHeight: 1.6,
          bgcolor: isDark ? '#0d1117' : '#f6f8fa',
          border: `1px solid ${isDark ? '#21262d' : '#d0d7de'}`,
          p: 1.5,
          borderRadius: 1,
          maxHeight: 450,
          overflow: 'auto',
          userSelect: 'none',
          cursor: isSelecting ? 'crosshair' : 'default',
          '&::-webkit-scrollbar': {
            width: 8,
            height: 8,
          },
          '&::-webkit-scrollbar-track': {
            bgcolor: isDark ? '#161b22' : '#f0f0f0',
          },
          '&::-webkit-scrollbar-thumb': {
            bgcolor: isDark ? '#30363d' : '#c1c1c1',
            borderRadius: 4,
          },
        }}
      >
        {lines.map((parsed, i) => (
          <Box
            key={i}
            onMouseDown={(e) => handleLineMouseDown(i, e)}
            onMouseEnter={() => handleLineMouseEnter(i)}
            sx={{
              bgcolor: isLineSelected(i) 
                ? alpha(theme.palette.warning.main, isDark ? 0.18 : 0.12)
                : 'transparent',
              mx: -1.5,
              px: 1.5,
              py: 0.125,
              borderLeft: isLineSelected(i) 
                ? `3px solid ${theme.palette.warning.main}`
                : '3px solid transparent',
              // Clean, crisp transitions
              transition: 'background-color 0.15s ease-out, border-color 0.15s ease-out',
              '&:hover': {
                bgcolor: isLineSelected(i) 
                  ? alpha(theme.palette.warning.main, isDark ? 0.25 : 0.18)
                  : alpha(theme.palette.primary.main, isDark ? 0.08 : 0.04),
                borderLeftColor: isLineSelected(i) 
                  ? theme.palette.warning.main
                  : alpha(theme.palette.primary.main, 0.5),
              },
            }}
          >
            <InstructionLine 
              parsed={parsed} 
              arch={arch}
              annotation={parsed.address ? annotationMap[parsed.address] : undefined}
            />
          </Box>
        ))}
      </Box>
      
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mt: 0.5 }}>
        <Typography variant="caption" color="text.secondary" sx={{ fontStyle: 'italic' }}>
          Drag to select • Hover for docs • Click 📝 to annotate
        </Typography>
        {annotations.length > 0 && (
          <Typography variant="caption" color="warning.main">
            {annotations.length} annotation{annotations.length !== 1 ? 's' : ''}
          </Typography>
        )}
      </Stack>
    </Box>
  );
};

export default DisassemblyViewer;

