import { defineConfig, devices } from '@playwright/test';

/**
 * Runs against a live stack (default https://localhost from `docker compose up`).
 * Override with E2E_BASE_URL.
 */
export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['github']] : 'list',
  timeout: 60_000,
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'https://localhost',
    // Local stack uses Caddy's internal CA.
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
