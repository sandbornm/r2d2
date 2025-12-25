import React, { useCallback } from 'react';
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

// Read-only ASM viewer
export function AsmViewer({ 
  value, 
  height = '300px' 
}: { 
  value: string; 
  height?: string;
}) {
  return (
    <CodeEditor
      value={value}
      onChange={() => {}}
      language="asm"
      height={height}
      readOnly
    />
  );
}
