import { defineConfig } from '@playwright/test';

// E2E: runs against the full docker stack (nginx on :8006, see Makefile).
export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  retries: 1,
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:8006',
    trace: 'retain-on-failure',
  },
  webServer: process.env.E2E_NO_AUTOSTART
    ? undefined
    : undefined, // stack is started by `make dev` / compose, not by playwright
});
