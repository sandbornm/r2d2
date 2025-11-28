import { CssBaseline, PaletteMode, ThemeProvider } from '@mui/material';
import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './styles.css';
import { createAppTheme } from './theme';

// Theme context
interface ThemeContextType {
  mode: PaletteMode;
  toggleTheme: () => void;
}

export const ThemeContext = createContext<ThemeContextType>({
  mode: 'dark',
  toggleTheme: () => {},
});

export const useThemeMode = () => useContext(ThemeContext);

const Root = () => {
  // Check localStorage and system preference
  const getInitialMode = (): PaletteMode => {
    const stored = localStorage.getItem('r2d2-theme');
    if (stored === 'light' || stored === 'dark') return stored;
    // Default to dark
    return 'dark';
  };

  const [mode, setMode] = useState<PaletteMode>(getInitialMode);

  useEffect(() => {
    localStorage.setItem('r2d2-theme', mode);
    // Update CSS color scheme
    document.documentElement.style.colorScheme = mode;
  }, [mode]);

  const toggleTheme = () => {
    setMode((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  const theme = useMemo(() => createAppTheme(mode), [mode]);

  useEffect(() => {
    document.body.style.backgroundColor = theme.palette.background.default;
    document.body.style.color = theme.palette.text.primary;
  }, [theme]);

  return (
    <ThemeContext.Provider value={{ mode, toggleTheme }}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <App />
      </ThemeProvider>
    </ThemeContext.Provider>
  );
};

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
);
