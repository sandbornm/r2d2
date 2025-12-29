import React, { useCallback, useMemo } from 'react';
import CodeMirror from '@uiw/react-codemirror';
import { cpp } from '@codemirror/lang-cpp';
import { vscodeDark } from '@uiw/codemirror-theme-vscode';
import { Box } from '@mui/material';

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  language?: 'c' | 'asm';
  height?: string;
  readOnly?: boolean;
}

export default function CodeEditor({
  value,
  onChange,
  language = 'c',
  height = '350px',
  readOnly = false,
}: CodeEditorProps) {
  const handleChange = useCallback((val: string) => {
    onChange(val);
  }, [onChange]);

  // Extensions based on language
  const extensions = language === 'c' ? [cpp()] : [];

  return (
    <Box
      sx={{
        borderRadius: 1,
        overflow: 'hidden',
        border: '1px solid',
        borderColor: 'divider',
        '& .cm-editor': {
          fontSize: '0.875rem',
        },
        '& .cm-scroller': {
          fontFamily: '"JetBrains Mono", "Fira Code", "Consolas", monospace',
        },
        '& .cm-focused': {
          outline: 'none',
        },
      }}
    >
      <CodeMirror
        value={value}
        height={height}
        theme={vscodeDark}
        extensions={extensions}
        onChange={handleChange}
        readOnly={readOnly}
        basicSetup={{
          lineNumbers: true,
          highlightActiveLineGutter: true,
          highlightSpecialChars: true,
          history: true,
          foldGutter: true,
          drawSelection: true,
          dropCursor: true,
          allowMultipleSelections: true,
          indentOnInput: true,
          syntaxHighlighting: true,
          bracketMatching: true,
          closeBrackets: true,
          autocompletion: true,
          rectangularSelection: true,
          crosshairCursor: true,
          highlightActiveLine: true,
          highlightSelectionMatches: true,
          closeBracketsKeymap: true,
          defaultKeymap: true,
          searchKeymap: true,
          historyKeymap: true,
          foldKeymap: true,
          completionKeymap: true,
          lintKeymap: true,
        }}
      />
    </Box>
  );
}

// ARM/AArch64 Assembly tokens for syntax highlighting
const ARM_REGISTERS = new Set([
  // ARM64 general purpose
  'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
  'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30',
  'w0', 'w1', 'w2', 'w3', 'w4', 'w5', 'w6', 'w7', 'w8', 'w9', 'w10', 'w11', 'w12', 'w13', 'w14', 'w15',
  'w16', 'w17', 'w18', 'w19', 'w20', 'w21', 'w22', 'w23', 'w24', 'w25', 'w26', 'w27', 'w28', 'w29', 'w30',
  'sp', 'lr', 'pc', 'xzr', 'wzr', 'fp',
  // ARM32
  'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
  // SIMD/FP
  'v0', 'v1', 'v2', 'v3', 'v4', 'v5', 'v6', 'v7', 'v8', 'v9', 'v10', 'v11', 'v12', 'v13', 'v14', 'v15',
  'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
]);

const ARM_INSTRUCTIONS = new Set([
  // Data movement
  'mov', 'movk', 'movz', 'movn', 'mvn', 'ldr', 'str', 'ldp', 'stp', 'ldrb', 'strb', 'ldrh', 'strh',
  'ldrsb', 'ldrsh', 'ldrsw', 'ldur', 'stur', 'ldnp', 'stnp', 'adrp', 'adr',
  // Arithmetic
  'add', 'adds', 'sub', 'subs', 'mul', 'madd', 'msub', 'smull', 'umull', 'sdiv', 'udiv',
  'neg', 'negs', 'adc', 'adcs', 'sbc', 'sbcs', 'ngc', 'ngcs',
  // Logical
  'and', 'ands', 'orr', 'orn', 'eor', 'eon', 'bic', 'bics', 'tst',
  // Shift/rotate
  'lsl', 'lsr', 'asr', 'ror', 'rrx',
  // Compare
  'cmp', 'cmn', 'ccmp', 'ccmn',
  // Branch
  'b', 'bl', 'br', 'blr', 'ret', 'cbz', 'cbnz', 'tbz', 'tbnz',
  'b.eq', 'b.ne', 'b.cs', 'b.cc', 'b.mi', 'b.pl', 'b.vs', 'b.vc',
  'b.hi', 'b.ls', 'b.ge', 'b.lt', 'b.gt', 'b.le', 'b.al', 'b.nv',
  'beq', 'bne', 'bgt', 'blt', 'bge', 'ble', 'bhi', 'blo', 'bhs', 'bls',
  // System
  'svc', 'hvc', 'smc', 'brk', 'hlt', 'nop', 'wfe', 'wfi', 'sev', 'sevl', 'yield',
  'mrs', 'msr', 'isb', 'dsb', 'dmb',
  // Conditional select
  'csel', 'csinc', 'csinv', 'csneg', 'cset', 'csetm', 'cinc', 'cinv', 'cneg',
  // Bit manipulation
  'cls', 'clz', 'rbit', 'rev', 'rev16', 'rev32', 'extr', 'bfm', 'sbfm', 'ubfm',
  'bfi', 'bfxil', 'sbfiz', 'sbfx', 'ubfiz', 'ubfx',
  // Push/pop (ARM32 style)
  'push', 'pop',
]);

const ARM_DIRECTIVES = new Set([
  '.text', '.data', '.bss', '.section', '.global', '.globl', '.local', '.weak',
  '.byte', '.hword', '.word', '.quad', '.ascii', '.asciz', '.string', '.space', '.skip', '.zero',
  '.align', '.balign', '.p2align', '.type', '.size', '.file', '.loc', '.cfi_startproc', '.cfi_endproc',
  '.cfi_def_cfa', '.cfi_def_cfa_offset', '.cfi_def_cfa_register', '.cfi_offset', '.cfi_rel_offset',
  '.equ', '.set', '.comm', '.lcomm', '.ident', '.arch', '.cpu', '.fpu', '.syntax', '.thumb', '.arm',
]);

// Interactive assembly line component
interface AsmLineProps {
  lineNumber: number;
  content: string;
  isLabel: boolean;
  isDirective: boolean;
  isInstruction: boolean;
}

function AsmLine({ lineNumber, content, isLabel, isDirective, isInstruction }: AsmLineProps) {
  const trimmed = content.trim();
  
  // Parse the line into tokens for coloring
  const tokens = useMemo(() => {
    const result: { text: string; type: string }[] = [];
    let remaining = content;
    let match;

    while (remaining.length > 0) {
      // Leading whitespace
      if ((match = remaining.match(/^(\s+)/))) {
        result.push({ text: match[1], type: 'space' });
        remaining = remaining.slice(match[1].length);
        continue;
      }

      // Comments
      if ((match = remaining.match(/^([;@].*|\/\/.*|#APP.*|#NO_APP.*)$/))) {
        result.push({ text: match[1], type: 'comment' });
        remaining = '';
        continue;
      }

      // Labels
      if ((match = remaining.match(/^([._a-zA-Z][._a-zA-Z0-9]*:)/))) {
        result.push({ text: match[1], type: 'label' });
        remaining = remaining.slice(match[1].length);
        continue;
      }

      // Directives
      if ((match = remaining.match(/^(\.[a-zA-Z_][a-zA-Z0-9_]*)/))) {
        result.push({ text: match[1], type: 'directive' });
        remaining = remaining.slice(match[1].length);
        continue;
      }

      // Numbers (hex, decimal, binary)
      if ((match = remaining.match(/^(#?0x[0-9a-fA-F]+|#?-?[0-9]+|#?0b[01]+)/))) {
        result.push({ text: match[1], type: 'number' });
        remaining = remaining.slice(match[1].length);
        continue;
      }

      // Strings
      if ((match = remaining.match(/^("[^"]*")/))) {
        result.push({ text: match[1], type: 'string' });
        remaining = remaining.slice(match[1].length);
        continue;
      }

      // Memory operands [...]
      if ((match = remaining.match(/^(\[[^\]]*\])/))) {
        // Parse the memory operand for sub-highlighting
        const memContent = match[1];
        result.push({ text: memContent, type: 'memory' });
        remaining = remaining.slice(match[1].length);
        continue;
      }

      // Registers and instructions
      if ((match = remaining.match(/^([a-zA-Z_][a-zA-Z0-9_.]*!?)/))) {
        const word = match[1].toLowerCase().replace(/!$/, '');
        if (ARM_REGISTERS.has(word)) {
          result.push({ text: match[1], type: 'register' });
        } else if (ARM_INSTRUCTIONS.has(word) || ARM_INSTRUCTIONS.has(word.replace(/\.[a-z]+$/, ''))) {
          result.push({ text: match[1], type: 'instruction' });
        } else {
          result.push({ text: match[1], type: 'symbol' });
        }
        remaining = remaining.slice(match[1].length);
        continue;
      }

      // Punctuation
      if ((match = remaining.match(/^([,\[\]{}()+\-*!:]+)/))) {
        result.push({ text: match[1], type: 'punctuation' });
        remaining = remaining.slice(match[1].length);
        continue;
      }

      // Anything else
      result.push({ text: remaining[0], type: 'other' });
      remaining = remaining.slice(1);
    }

    return result;
  }, [content]);

  const getColor = (type: string) => {
    switch (type) {
      case 'instruction': return '#569cd6';    // Blue - instructions stand out
      case 'register': return '#9cdcfe';       // Light blue - registers
      case 'label': return '#c586c0';          // Purple - labels
      case 'directive': return '#4ec9b0';      // Teal - directives
      case 'number': return '#b5cea8';         // Green - numbers
      case 'string': return '#ce9178';         // Orange - strings
      case 'comment': return '#6a9955';        // Green - comments
      case 'symbol': return '#dcdcaa';         // Yellow - symbols
      case 'memory': return '#d7ba7d';         // Gold - memory operands
      case 'punctuation': return '#d4d4d4';    // Light gray
      default: return '#d4d4d4';
    }
  };

  return (
    <Box
      sx={{
        display: 'flex',
        '&:hover': { bgcolor: 'rgba(255,255,255,0.05)' },
        fontFamily: '"JetBrains Mono", "Fira Code", "Consolas", monospace',
        fontSize: '0.8rem',
        lineHeight: 1.6,
      }}
    >
      {/* Line number */}
      <Box
        sx={{
          width: 50,
          minWidth: 50,
          textAlign: 'right',
          pr: 1.5,
          color: 'text.disabled',
          userSelect: 'none',
          borderRight: '1px solid',
          borderColor: 'divider',
          mr: 1.5,
        }}
      >
        {lineNumber}
      </Box>
      {/* Code content */}
      <Box sx={{ flex: 1, whiteSpace: 'pre' }}>
        {tokens.map((token, i) => (
          <span
            key={i}
            style={{
              color: getColor(token.type),
              fontWeight: token.type === 'instruction' || token.type === 'label' ? 600 : 400,
              fontStyle: token.type === 'comment' ? 'italic' : 'normal',
            }}
          >
            {token.text}
          </span>
        ))}
      </Box>
    </Box>
  );
}

// Rich assembly viewer with Godbolt-like features
export function AsmViewer({ 
  value, 
  height = '300px' 
}: { 
  value: string; 
  height?: string;
}) {
  const lines = useMemo(() => value.split('\n'), [value]);

  return (
    <Box
      sx={{
        height,
        overflow: 'auto',
        bgcolor: '#1e1e1e',
        borderRadius: 1,
        fontFamily: '"JetBrains Mono", "Fira Code", "Consolas", monospace',
        fontSize: '0.8rem',
        py: 1,
      }}
    >
      {lines.map((line, idx) => {
        const trimmed = line.trim();
        const isLabel = /^[._a-zA-Z][._a-zA-Z0-9]*:/.test(trimmed);
        const isDirective = trimmed.startsWith('.');
        const isInstruction = !isLabel && !isDirective && trimmed.length > 0 && !trimmed.startsWith('/') && !trimmed.startsWith('#');
        
        return (
          <AsmLine
            key={idx}
            lineNumber={idx + 1}
            content={line}
            isLabel={isLabel}
            isDirective={isDirective}
            isInstruction={isInstruction}
          />
        );
      })}
    </Box>
  );
}
