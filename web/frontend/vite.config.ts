import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: '127.0.0.1',
    // Tailscale Serve / MagicDNS hits Vite with the public hostname.
    allowedHosts: [
      'r2d2.tailcba5f3.ts.net',
      'kali-raspberry-pi5.tailcba5f3.ts.net',
      '.ts.net',
    ],
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5050',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          const normalizedId = id.replace(/\\/g, '/');
          if (
            normalizedId.includes('/node_modules/react/') ||
            normalizedId.includes('/node_modules/react-dom/') ||
            normalizedId.includes('/node_modules/scheduler/')
          ) {
            return 'react-vendor';
          }
          if (
            normalizedId.includes('/node_modules/@mui/') ||
            normalizedId.includes('/node_modules/@emotion/') ||
            normalizedId.includes('/node_modules/react-is/')
          ) {
            return 'mui-vendor';
          }
          if (normalizedId.includes('/node_modules/@codemirror/') || normalizedId.includes('/node_modules/@lezer/')) {
            return 'codemirror-vendor';
          }
          if (normalizedId.includes('/node_modules/react-markdown/') || normalizedId.includes('/node_modules/remark-gfm/')) {
            return 'markdown-vendor';
          }
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    coverage: {
      reporter: ['text', 'lcov'],
    },
  },
});
