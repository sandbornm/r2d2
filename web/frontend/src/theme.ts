import { alpha, createTheme } from '@mui/material/styles';

type PaletteMode = 'light' | 'dark';

// Improved color palette with better contrast ratios
const colors = {
  // Neutral grays - softer for better readability
  gray50: '#fafbfc',
  gray100: '#f3f4f6',
  gray200: '#e5e7eb',
  gray300: '#d1d5db',
  gray400: '#9ca3af',
  gray500: '#6b7280',
  gray600: '#4b5563',
  gray700: '#374151',
  gray800: '#1f2937',
  gray900: '#111827',
  gray950: '#030712',

  // Accent - refined blue for better visibility
  blue400: '#60a5fa',
  blue500: '#3b82f6',
  blue600: '#2563eb',
  blue700: '#1d4ed8',

  // Semantic colors - clearer distinction
  green500: '#22c55e',
  green600: '#16a34a',
  amber500: '#f59e0b',
  amber600: '#d97706',
  red500: '#ef4444',
  red600: '#dc2626',
  slate400: '#94a3b8',
  slate500: '#64748b',

  // Tool-specific colors for attribution
  toolRadare2: '#e97451',    // Warm orange
  toolAngr: '#8b5cf6',       // Purple
  toolGhidra: '#10b981',     // Emerald
  toolCapstone: '#f472b6',   // Pink
  toolFrida: '#fbbf24',      // Amber
  toolGef: '#06b6d4',        // Cyan
};

export const createAppTheme = (mode: PaletteMode) => {
  const isDark = mode === 'dark';

  return createTheme({
    palette: {
      mode,
      primary: {
        main: isDark ? colors.blue400 : colors.blue600,
        light: colors.blue400,
        dark: colors.blue700,
        contrastText: '#ffffff',
      },
      secondary: {
        main: colors.amber500,
        contrastText: isDark ? '#000000' : '#ffffff',
      },
      error: {
        main: isDark ? colors.red500 : colors.red600,
      },
      warning: {
        main: colors.amber500,
      },
      success: {
        main: isDark ? colors.green500 : colors.green600,
      },
      info: {
        main: colors.slate500,
      },
      background: {
        default: isDark ? colors.gray950 : colors.gray50,
        paper: isDark ? colors.gray900 : '#ffffff',
      },
      text: {
        // Improved contrast for readability
        primary: isDark ? colors.gray100 : colors.gray900,
        secondary: isDark ? colors.gray400 : colors.gray600,
      },
      divider: isDark ? colors.gray800 : colors.gray200,
    },
    typography: {
      // Improved font stack with better fallbacks
      fontFamily: '"Inter", "SF Pro Display", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      // Larger base font for better readability
      fontSize: 14,
      h1: {
        fontFamily: '"Inter", "SF Pro Display", -apple-system, sans-serif',
        fontWeight: 600,
        fontSize: '1.875rem',
        lineHeight: 1.3,
        letterSpacing: '-0.02em',
      },
      h2: {
        fontFamily: '"Inter", "SF Pro Display", -apple-system, sans-serif',
        fontWeight: 600,
        fontSize: '1.5rem',
        lineHeight: 1.35,
        letterSpacing: '-0.01em',
      },
      h3: {
        fontFamily: '"Inter", "SF Pro Display", -apple-system, sans-serif',
        fontWeight: 600,
        fontSize: '1.25rem',
        lineHeight: 1.4,
      },
      h4: {
        fontFamily: '"Inter", "SF Pro Display", -apple-system, sans-serif',
        fontWeight: 600,
        fontSize: '1.125rem',
        lineHeight: 1.4,
      },
      h5: {
        fontFamily: '"Inter", "SF Pro Display", -apple-system, sans-serif',
        fontWeight: 600,
        fontSize: '1rem',
        lineHeight: 1.5,
      },
      h6: {
        fontFamily: '"Inter", "SF Pro Display", -apple-system, sans-serif',
        fontWeight: 600,
        fontSize: '0.875rem',
        lineHeight: 1.5,
      },
      body1: {
        fontSize: '0.9375rem', // 15px - slightly larger for readability
        lineHeight: 1.65,
        letterSpacing: '0.01em',
      },
      body2: {
        fontSize: '0.875rem', // 14px
        lineHeight: 1.6,
        letterSpacing: '0.01em',
      },
      caption: {
        fontSize: '0.8125rem', // 13px
        lineHeight: 1.5,
        letterSpacing: '0.02em',
      },
      button: {
        textTransform: 'none',
        fontWeight: 500,
        fontSize: '0.875rem',
        letterSpacing: '0.01em',
      },
      // Code/monospace typography
      overline: {
        fontFamily: '"JetBrains Mono", "Fira Code", "SF Mono", Consolas, monospace',
        fontSize: '0.8125rem',
        fontWeight: 500,
        letterSpacing: '0.03em',
        lineHeight: 1.6,
      },
    },
    shape: {
      borderRadius: 6,
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          // Better scrollbar styling
          '*': {
            scrollbarWidth: 'thin',
            scrollbarColor: isDark ? `${colors.gray700} transparent` : `${colors.gray300} transparent`,
          },
          '*::-webkit-scrollbar': {
            width: '8px',
            height: '8px',
          },
          '*::-webkit-scrollbar-track': {
            background: 'transparent',
          },
          '*::-webkit-scrollbar-thumb': {
            backgroundColor: isDark ? colors.gray700 : colors.gray300,
            borderRadius: '4px',
            '&:hover': {
              backgroundColor: isDark ? colors.gray600 : colors.gray400,
            },
          },
          // Monospace code blocks
          'code, pre, .mono': {
            fontFamily: '"JetBrains Mono", "Fira Code", "SF Mono", Consolas, monospace',
            fontSize: '0.8125rem',
            lineHeight: 1.6,
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            borderRadius: 6,
            padding: '8px 16px',
            boxShadow: 'none',
            fontWeight: 500,
            transition: 'all 0.15s ease',
            '&:hover': {
              boxShadow: 'none',
              transform: 'translateY(-1px)',
            },
            '&:active': {
              transform: 'translateY(0)',
            },
          },
          contained: {
            '&:hover': {
              boxShadow: 'none',
            },
          },
          sizeSmall: {
            padding: '6px 12px',
            fontSize: '0.8125rem',
          },
          sizeLarge: {
            padding: '12px 24px',
            fontSize: '0.9375rem',
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: 'none',
          },
          outlined: {
            borderColor: isDark ? colors.gray800 : colors.gray200,
          },
        },
      },
      MuiTextField: {
        styleOverrides: {
          root: {
            '& .MuiOutlinedInput-root': {
              fontSize: '0.9375rem',
              '& fieldset': {
                borderColor: isDark ? colors.gray700 : colors.gray300,
                transition: 'border-color 0.15s ease',
              },
              '&:hover fieldset': {
                borderColor: isDark ? colors.gray600 : colors.gray400,
              },
              '&.Mui-focused fieldset': {
                borderColor: isDark ? colors.blue400 : colors.blue600,
                borderWidth: 2,
              },
            },
            '& .MuiInputBase-input': {
              padding: '10px 14px',
            },
          },
        },
      },
      MuiTab: {
        styleOverrides: {
          root: {
            textTransform: 'none',
            fontWeight: 500,
            fontSize: '0.875rem',
            minHeight: 44,
            padding: '10px 16px',
            transition: 'color 0.15s ease',
            '&:hover': {
              color: isDark ? colors.gray100 : colors.gray900,
            },
          },
        },
      },
      MuiTabs: {
        styleOverrides: {
          root: {
            minHeight: 44,
          },
          indicator: {
            height: 2,
            borderRadius: '2px 2px 0 0',
          },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: 6,
            fontWeight: 500,
            fontSize: '0.75rem',
            height: 24,
            transition: 'all 0.15s ease',
          },
          sizeSmall: {
            height: 20,
            fontSize: '0.6875rem',
          },
        },
      },
      MuiListItemButton: {
        styleOverrides: {
          root: {
            borderRadius: 6,
            transition: 'background-color 0.15s ease',
            '&.Mui-selected': {
              backgroundColor: alpha(isDark ? colors.blue400 : colors.blue600, 0.12),
              '&:hover': {
                backgroundColor: alpha(isDark ? colors.blue400 : colors.blue600, 0.18),
              },
            },
          },
        },
      },
      MuiSelect: {
        styleOverrides: {
          root: {
            transition: 'all 0.15s ease',
          },
        },
      },
      MuiPopover: {
        styleOverrides: {
          paper: {
            borderRadius: 8,
            boxShadow: isDark
              ? '0 4px 24px rgba(0, 0, 0, 0.5)'
              : '0 4px 24px rgba(0, 0, 0, 0.1)',
          },
        },
      },
      MuiTooltip: {
        styleOverrides: {
          tooltip: {
            backgroundColor: isDark ? colors.gray800 : colors.gray900,
            color: colors.gray100,
            fontSize: '0.8125rem',
            fontWeight: 400,
            padding: '8px 12px',
            borderRadius: 6,
            boxShadow: isDark
              ? '0 4px 12px rgba(0, 0, 0, 0.4)'
              : '0 4px 12px rgba(0, 0, 0, 0.15)',
            maxWidth: 300,
            lineHeight: 1.5,
          },
          arrow: {
            color: isDark ? colors.gray800 : colors.gray900,
          },
        },
        defaultProps: {
          arrow: true,
          enterDelay: 300,
          leaveDelay: 100,
        },
      },
      MuiDrawer: {
        styleOverrides: {
          paper: {
            transition: 'transform 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important',
          },
        },
      },
      MuiAlert: {
        styleOverrides: {
          root: {
            borderRadius: 6,
            fontSize: '0.875rem',
            alignItems: 'center',
          },
          standardInfo: {
            backgroundColor: alpha(colors.blue500, isDark ? 0.15 : 0.1),
            color: isDark ? colors.blue400 : colors.blue700,
          },
          standardSuccess: {
            backgroundColor: alpha(colors.green500, isDark ? 0.15 : 0.1),
            color: isDark ? colors.green500 : colors.green600,
          },
          standardWarning: {
            backgroundColor: alpha(colors.amber500, isDark ? 0.15 : 0.1),
            color: isDark ? colors.amber500 : colors.amber600,
          },
          standardError: {
            backgroundColor: alpha(colors.red500, isDark ? 0.15 : 0.1),
            color: isDark ? colors.red500 : colors.red600,
          },
        },
      },
      MuiIconButton: {
        styleOverrides: {
          root: {
            transition: 'all 0.15s ease',
            '&:hover': {
              transform: 'scale(1.05)',
            },
          },
          sizeSmall: {
            padding: 6,
          },
        },
      },
      MuiSwitch: {
        styleOverrides: {
          root: {
            padding: 8,
          },
          switchBase: {
            '&.Mui-checked': {
              '& + .MuiSwitch-track': {
                opacity: 1,
              },
            },
          },
          track: {
            borderRadius: 10,
            backgroundColor: isDark ? colors.gray700 : colors.gray300,
          },
        },
      },
    },
  });
};

// Tool colors for attribution badges
export const toolColors = {
  radare2: colors.toolRadare2,
  angr: colors.toolAngr,
  ghidra: colors.toolGhidra,
  capstone: colors.toolCapstone,
  frida: colors.toolFrida,
  gef: colors.toolGef,
  libmagic: colors.slate500,
  autoprofile: colors.slate400,
  dwarf: colors.amber500,
};

export const theme = createAppTheme('dark');
