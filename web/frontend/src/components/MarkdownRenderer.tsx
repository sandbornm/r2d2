import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import { alpha, Box, IconButton, Tooltip, Typography, useTheme } from '@mui/material';
import { FC, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

interface MarkdownRendererProps {
  content: string;
}

const CodeBlock: FC<{ children: string; className?: string }> = ({ children, className }) => {
  const theme = useTheme();
  const isDark = theme.palette.mode === 'dark';
  const [copied, setCopied] = useState(false);
  
  // Extract language from className (e.g., "language-python" -> "python")
  const language = className?.replace('language-', '') || '';
  const isArm = language === 'asm' || language === 'arm' || language === 'armasm';
  
  const handleCopy = () => {
    navigator.clipboard.writeText(children);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  
  return (
    <Box sx={{ position: 'relative', my: 1.5 }}>
      {/* Language badge */}
      {language && (
        <Typography
          variant="caption"
          sx={{
            position: 'absolute',
            top: 4,
            left: 8,
            px: 0.75,
            py: 0.25,
            borderRadius: 0.5,
            bgcolor: alpha(theme.palette.primary.main, 0.2),
            color: 'primary.main',
            fontSize: '0.6rem',
            fontWeight: 600,
            textTransform: 'uppercase',
          }}
        >
          {isArm ? 'ARM' : language}
        </Typography>
      )}
      
      {/* Copy button */}
      <Tooltip title={copied ? 'Copied!' : 'Copy'}>
        <IconButton
          size="small"
          onClick={handleCopy}
          sx={{
            position: 'absolute',
            top: 4,
            right: 4,
            opacity: 0.6,
            '&:hover': { opacity: 1 },
          }}
        >
          <ContentCopyIcon sx={{ fontSize: 14 }} />
        </IconButton>
      </Tooltip>
      
      <Box
        component="pre"
        sx={{
          bgcolor: isDark ? '#0d1117' : '#f6f8fa',
          border: `1px solid ${isDark ? '#21262d' : '#d0d7de'}`,
          borderRadius: 1,
          p: 1.5,
          pt: language ? 3 : 1.5,
          overflow: 'auto',
          fontFamily: '"JetBrains Mono", "Fira Code", Consolas, monospace',
          fontSize: '0.8rem',
          lineHeight: 1.5,
          '&::-webkit-scrollbar': {
            height: 6,
          },
          '&::-webkit-scrollbar-thumb': {
            bgcolor: isDark ? '#30363d' : '#c1c1c1',
            borderRadius: 3,
          },
        }}
      >
        <code>{children}</code>
      </Box>
    </Box>
  );
};

const InlineCode: FC<{ children: React.ReactNode }> = ({ children }) => {
  const theme = useTheme();
  
  return (
    <Box
      component="code"
      sx={{
        bgcolor: alpha(theme.palette.primary.main, 0.1),
        px: 0.75,
        py: 0.25,
        borderRadius: 0.5,
        fontFamily: '"JetBrains Mono", Consolas, monospace',
        fontSize: '0.85em',
      }}
    >
      {children}
    </Box>
  );
};

const MarkdownRenderer: FC<MarkdownRendererProps> = ({ content }) => {
  const theme = useTheme();
  const isDark = theme.palette.mode === 'dark';
  
  return (
    <Box
      sx={{
        '& p': {
          my: 0.75,
          lineHeight: 1.7,
          '&:first-of-type': { mt: 0 },
          '&:last-of-type': { mb: 0 },
        },
        '& h1, & h2, & h3, & h4, & h5, & h6': {
          mt: 1.5,
          mb: 0.75,
          fontWeight: 600,
          lineHeight: 1.3,
        },
        '& h1': { fontSize: '1.25rem' },
        '& h2': { fontSize: '1.1rem' },
        '& h3': { fontSize: '1rem' },
        '& h4, & h5, & h6': { fontSize: '0.9rem' },
        '& ul, & ol': {
          my: 0.75,
          pl: 2.5,
        },
        '& li': {
          my: 0.25,
          lineHeight: 1.6,
        },
        '& blockquote': {
          my: 1,
          pl: 1.5,
          borderLeft: `3px solid ${alpha(theme.palette.primary.main, 0.5)}`,
          color: 'text.secondary',
          fontStyle: 'italic',
        },
        '& hr': {
          my: 1.5,
          border: 'none',
          borderTop: `1px solid ${theme.palette.divider}`,
        },
        '& table': {
          width: '100%',
          borderCollapse: 'collapse',
          my: 1,
          fontSize: '0.85rem',
        },
        '& th, & td': {
          border: `1px solid ${theme.palette.divider}`,
          px: 1,
          py: 0.5,
          textAlign: 'left',
        },
        '& th': {
          bgcolor: alpha(theme.palette.primary.main, 0.08),
          fontWeight: 600,
        },
        '& a': {
          color: 'primary.main',
          textDecoration: 'none',
          '&:hover': {
            textDecoration: 'underline',
          },
        },
        '& strong': {
          fontWeight: 600,
        },
        '& em': {
          fontStyle: 'italic',
        },
      }}
    >
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          code({ node, className, children, ...props }) {
            const isInline = !className && typeof children === 'string' && !children.includes('\n');
            
            if (isInline) {
              return <InlineCode>{children}</InlineCode>;
            }
            
            return (
              <CodeBlock className={className}>
                {String(children).replace(/\n$/, '')}
              </CodeBlock>
            );
          },
          pre({ children }) {
            // Just pass through - code block handles styling
            return <>{children}</>;
          },
        }}
      >
        {content}
      </ReactMarkdown>
    </Box>
  );
};

export default MarkdownRenderer;

