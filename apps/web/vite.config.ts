/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Dev proxy mirrors the production nginx layout: SPA and API same-origin.
    proxy: {
      '/api': 'http://localhost:8080',
      '/.well-known': 'http://localhost:8080',
      '/openapi.json': 'http://localhost:8080',
      '/docs': 'http://localhost:8080',
    },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
