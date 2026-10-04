import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/dashboard/',
  test: { environment: 'jsdom', include: ['src/**/*.test.{ts,tsx}'],
    setupFiles: ['src/test-setup.ts'] },
  // Production always serves built files in FastAPI. This loopback-only proxy is for editing.
  server: { proxy: {
    '/dashboard/api': 'http://127.0.0.1:8000',
    '/dashboard/auth': 'http://127.0.0.1:8000',
    '/dashboard/session': 'http://127.0.0.1:8000'
  } }
});
