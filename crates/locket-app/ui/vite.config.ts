import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// Tauri convention: fixed port, never auto-fallback. The dev CSP in
// `src-tauri/tauri.conf.json` whitelists exactly ws://localhost:1420 +
// http://localhost:1420; if Vite picked a different port the dev shell
// would silently fail HMR.
export default defineConfig({
  plugins: [vue()],
  clearScreen: false,
  server: {
    host: '127.0.0.1',
    port: 1420,
    strictPort: true,
  },
  build: {
    target: 'es2022',
    sourcemap: false,
    emptyOutDir: true,
  },
});
