import { createTheme, alpha, PaletteMode } from '@mui/material/styles';

// Vibrant color palette
const colors = {
  // Vibrant accents
  cyan: '#00d4ff',
  lime: '#39ff14',
  magenta: '#ff00ff',
  orange: '#ff6b35',
  yellow: '#ffd60a',
  red: '#ff3366',
  purple: '#a855f7',
  blue: '#3b82f6',
  green: '#22c55e',
  
  // Dark backgrounds
  darkBg: '#0a0a0a',
  darkSurface: '#141414',
  darkElevated: '#1c1c1c',
  
  // Light backgrounds
  lightBg: '#fafafa',
  lightSurface: '#ffffff',
  lightElevated: '#f5f5f5',
};

// Create theme based on mode
export const createAppTheme = (mode: PaletteMode) => {
  const isDark = mode === 'dark';

  return createTheme({
    palette: {
      mode,
      primary: {
        main: colors.cyan,
        light: '#66e5ff',
        dark: '#00a8cc',
      },
      secondary: {
        main: colors.lime,
        light: '#80ff6b',
        dark: '#2ecc10',
      },
      error: {
        main: colors.red,
        light: '#ff6b8a',
        dark: '#cc2952',
      },
      warning: {
        main: colors.orange,
        light: '#ff9a75',
        dark: '#cc5529',
      },
      info: {
        main: colors.purple,
        light: '#c084fc',
        dark: '#8b5cf6',
      },
      success: {
        main: colors.green,
        light: '#4ade80',
        dark: '#16a34a',
      },
      background: {
        default: isDark ? colors.darkBg : colors.lightBg,
        paper: isDark ? colors.darkSurface : colors.lightSurface,
      },
      text: {
        primary: isDark ? '#f4f4f5' : '#18181b',
        secondary: isDark ? '#a1a1aa' : '#71717a',
      },
      divider: isDark ? alpha('#ffffff', 0.1) : alpha('#000000', 0.1),
    },
    typography: {
      fontFamily: '"JetBrains Mono", "SF Mono", "Fira Code", "Consolas", monospace',
      h1: {
        fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
        fontWeight: 700,
      },
      h2: {
        fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
        fontWeight: 700,
      },
      h3: {
        fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
        fontWeight: 600,
      },
      h4: {
        fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
        fontWeight: 600,
      },
      h5: {
        fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
        fontWeight: 600,
      },
      h6: {
        fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, sans-serif',
        fontWeight: 600,
      },
      body1: {
        fontSize: '0.9375rem',
        lineHeight: 1.6,
      },
      body2: {
        fontSize: '0.875rem',
        lineHeight: 1.5,
      },
      button: {
        textTransform: 'none',
        fontWeight: 600,
      },
    },
    shape: {
      borderRadius: 8,
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            scrollbarWidth: 'thin',
            scrollbarColor: isDark ? '#3f3f46 transparent' : '#d4d4d8 transparent',
            '&::-webkit-scrollbar': {
              width: 8,
              height: 8,
            },
            '&::-webkit-scrollbar-track': {
              background: 'transparent',
            },
            '&::-webkit-scrollbar-thumb': {
              background: isDark ? '#3f3f46' : '#d4d4d8',
              borderRadius: 4,
            },
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            borderRadius: 8,
            padding: '10px 20px',
            fontWeight: 600,
          },
          contained: {
            boxShadow: 'none',
            '&:hover': {
              boxShadow: `0 0 20px ${alpha(colors.cyan, 0.4)}`,
            },
          },
          containedSecondary: {
            '&:hover': {
              boxShadow: `0 0 20px ${alpha(colors.lime, 0.4)}`,
            },
          },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: {
            backgroundImage: 'none',
          },
          outlined: {
            borderColor: isDark ? alpha('#ffffff', 0.12) : alpha('#000000', 0.12),
          },
        },
      },
      MuiTextField: {
        styleOverrides: {
          root: {
            '& .MuiOutlinedInput-root': {
              backgroundColor: isDark ? alpha('#000000', 0.4) : alpha('#000000', 0.02),
              '& fieldset': {
                borderColor: isDark ? alpha('#ffffff', 0.15) : alpha('#000000', 0.15),
              },
              '&:hover fieldset': {
                borderColor: colors.cyan,
              },
              '&.Mui-focused fieldset': {
                borderColor: colors.cyan,
                borderWidth: 2,
              },
            },
          },
        },
      },
      MuiTab: {
        styleOverrides: {
          root: {
            textTransform: 'none',
            fontWeight: 600,
            minHeight: 48,
            '&.Mui-selected': {
              color: colors.cyan,
            },
          },
        },
      },
      MuiTabs: {
        styleOverrides: {
          indicator: {
            height: 3,
            borderRadius: 3,
            backgroundColor: colors.cyan,
          },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: 6,
            fontWeight: 600,
          },
        },
      },
      MuiListItemButton: {
        styleOverrides: {
          root: {
            borderRadius: 8,
            '&.Mui-selected': {
              backgroundColor: alpha(colors.cyan, 0.15),
              borderLeft: `3px solid ${colors.cyan}`,
              '&:hover': {
                backgroundColor: alpha(colors.cyan, 0.2),
              },
            },
          },
        },
      },
      MuiAlert: {
        styleOverrides: {
          standardInfo: {
            backgroundColor: alpha(colors.cyan, 0.15),
            color: isDark ? colors.cyan : '#0891b2',
            '& .MuiAlert-icon': {
              color: colors.cyan,
            },
          },
          standardSuccess: {
            backgroundColor: alpha(colors.lime, 0.15),
            color: isDark ? colors.lime : '#15803d',
            '& .MuiAlert-icon': {
              color: colors.lime,
            },
          },
          standardError: {
            backgroundColor: alpha(colors.red, 0.15),
            color: isDark ? colors.red : '#dc2626',
            '& .MuiAlert-icon': {
              color: colors.red,
            },
          },
        },
      },
    },
  });
};

// Default dark theme for backwards compatibility
export const theme = createAppTheme('dark');
