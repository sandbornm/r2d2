import { alpha, createTheme, PaletteMode } from '@mui/material/styles';

// Clean, minimal color palette - inspired by technical documentation
const colors = {
  // Neutral grays - the foundation
  gray50: '#fafafa',
  gray100: '#f4f4f5',
  gray200: '#e4e4e7',
  gray300: '#d4d4d8',
  gray400: '#a1a1aa',
  gray500: '#71717a',
  gray600: '#52525b',
  gray700: '#3f3f46',
  gray800: '#27272a',
  gray900: '#18181b',
  gray950: '#09090b',
  
  // Accent - subtle blue for actions (not neon)
  blue500: '#3b82f6',
  blue600: '#2563eb',
  blue700: '#1d4ed8',
  
  // Semantic - muted tones
  green600: '#16a34a',
  amber600: '#d97706',
  red600: '#dc2626',
  slate500: '#64748b',
};

export const createAppTheme = (mode: PaletteMode) => {
  const isDark = mode === 'dark';

  return createTheme({
    palette: {
      mode,
      primary: {
        main: colors.blue600,
        light: colors.blue500,
        dark: colors.blue700,
      },
      secondary: {
        main: colors.amber600,
      },
      error: {
        main: colors.red600,
      },
      warning: {
        main: colors.amber600,
      },
      success: {
        main: colors.green600,
      },
      info: {
        main: colors.slate500,
      },
      background: {
        default: isDark ? colors.gray950 : colors.gray50,
        paper: isDark ? colors.gray900 : '#ffffff',
      },
      text: {
        primary: isDark ? colors.gray100 : colors.gray900,
        secondary: isDark ? colors.gray400 : colors.gray500,
      },
      divider: isDark ? colors.gray800 : colors.gray200,
    },
    typography: {
      fontFamily: '"IBM Plex Mono", "SF Mono", monospace',
      fontSize: 13,
      h1: {
        fontFamily: '"IBM Plex Sans", -apple-system, sans-serif',
        fontWeight: 600,
        fontSize: '1.75rem',
      },
      h2: {
        fontFamily: '"IBM Plex Sans", -apple-system, sans-serif',
        fontWeight: 600,
        fontSize: '1.5rem',
      },
      h3: {
        fontFamily: '"IBM Plex Sans", -apple-system, sans-serif',
        fontWeight: 600,
        fontSize: '1.25rem',
      },
      h4: {
        fontFamily: '"IBM Plex Sans", -apple-system, sans-serif',
        fontWeight: 600,
        fontSize: '1.125rem',
      },
      h5: {
        fontFamily: '"IBM Plex Sans", -apple-system, sans-serif',
        fontWeight: 600,
        fontSize: '1rem',
      },
      h6: {
        fontFamily: '"IBM Plex Sans", -apple-system, sans-serif',
        fontWeight: 600,
        fontSize: '0.875rem',
      },
      body1: {
        fontSize: '0.875rem',
        lineHeight: 1.6,
      },
      body2: {
        fontSize: '0.8125rem',
        lineHeight: 1.5,
      },
      caption: {
        fontSize: '0.75rem',
      },
      button: {
        textTransform: 'none',
        fontWeight: 500,
        fontSize: '0.8125rem',
      },
    },
    shape: {
      borderRadius: 4,
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            scrollbarWidth: 'thin',
            scrollbarColor: isDark ? `${colors.gray700} transparent` : `${colors.gray300} transparent`,
          },
        },
      },
      MuiButton: {
        styleOverrides: {
          root: {
            borderRadius: 4,
            padding: '6px 14px',
            boxShadow: 'none',
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
            padding: '4px 10px',
            fontSize: '0.75rem',
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
              fontSize: '0.875rem',
              '& fieldset': {
                borderColor: isDark ? colors.gray700 : colors.gray300,
              },
            },
          },
        },
      },
      MuiTab: {
        styleOverrides: {
          root: {
            textTransform: 'none',
            fontWeight: 500,
            fontSize: '0.8125rem',
            minHeight: 40,
            padding: '8px 14px',
          },
        },
      },
      MuiTabs: {
        styleOverrides: {
          root: {
            minHeight: 40,
          },
          indicator: {
            height: 2,
          },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: {
            borderRadius: 4,
            fontWeight: 500,
            fontSize: '0.6875rem',
            height: 22,
          },
          sizeSmall: {
            height: 18,
            fontSize: '0.625rem',
          },
        },
      },
      MuiListItemButton: {
        styleOverrides: {
          root: {
            borderRadius: 4,
            transition: 'background-color 0.15s ease',
            '&.Mui-selected': {
              backgroundColor: alpha(colors.blue600, isDark ? 0.15 : 0.08),
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
            boxShadow: isDark 
              ? '0 4px 20px rgba(0, 0, 0, 0.4)' 
              : '0 4px 20px rgba(0, 0, 0, 0.12)',
          },
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
            borderRadius: 4,
            fontSize: '0.8125rem',
          },
        },
      },
      MuiIconButton: {
        styleOverrides: {
          sizeSmall: {
            padding: 4,
          },
        },
      },
    },
  });
};

export const theme = createAppTheme('dark');
