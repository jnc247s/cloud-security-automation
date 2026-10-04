import { defineConfig, devices } from '@playwright/test';
import path from 'node:path';

if (!process.env.PYTHON_EXECUTABLE || process.env.DASHBOARD_BROWSER_TEST !== '1')
  throw new Error('Run browser acceptance through scripts/validate.py --dashboard');
export default defineConfig({
  testDir: './e2e', fullyParallel: false, workers: 1, retries: 0,
  reporter: 'list', use: { baseURL: 'http://127.0.0.1:9011', trace: 'off', screenshot: 'off', video: 'off' },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } }
  ],
  webServer: { command: `"${process.env.PYTHON_EXECUTABLE}" -m tests.dashboard_browser_server`,
    cwd: path.resolve(import.meta.dirname, '..'), url: 'http://127.0.0.1:9011/dashboard/',
    reuseExistingServer: false, timeout: 60000, stdout: 'ignore', stderr: 'pipe' }
});
