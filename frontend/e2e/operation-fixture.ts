import { test as base } from '@playwright/test';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { isUUID } from '../src/api';
import { runWithHistoryCleanup } from './history-page';

export const operationOrigin = 'http://127.0.0.1:9021';
interface OperationFixture {
  instance_id: string; scan_id: string; assessment_id: string;
  seed_proposal_id: string; seed_execution_id: string;
}
function metadata(v: unknown): v is OperationFixture {
  return typeof v === 'object' && v !== null && ['instance_id', 'scan_id', 'assessment_id', 'seed_proposal_id', 'seed_execution_id']
    .every(key => key in v && typeof (v as Record<string, unknown>)[key] === 'string'
      && isUUID((v as Record<string, string>)[key]));
}
export const test = base.extend<{ operationFixture: OperationFixture }>({
  operationFixture: [async ({ request }, use, testInfo) => {
    const python = process.env.PYTHON_EXECUTABLE, database = process.env.TEST_DATABASE_URL;
    if (!python || !database || process.env.DASHBOARD_BROWSER_TEST !== '1')
      throw new Error('Use the disposable browser validation harness');
    const instance = randomUUID();
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
      !/^(APP_|AUTH_|AWS_|BOTO|DATABASE_URL$|OIDC_|DASHBOARD_|REMEDIATION_|ASSESSMENT_|DEV_IDENTITY_|VITE_)/.test(key)));
    Object.assign(env, { DASHBOARD_BROWSER_TEST: '1', DASHBOARD_OPS_FIXTURE_ID: instance,
      TEST_DATABASE_URL: database, PYTHONUNBUFFERED: '1' });
    const child = spawn(python, ['-m', 'tests.dashboard_operation_browser_server'], {
      cwd: path.resolve(import.meta.dirname, '../..'), env, shell: false, windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    let lastStage = 'STARTING', ready = false, buffered = '';
    const closed = new Promise<number | null>(resolve => {
      child.once('close', code => resolve(code)); child.once('error', () => resolve(-1));
    });
    const started = new Promise<void>((resolve, reject) => {
      child.stdout.on('data', (chunk: Buffer) => {
        buffered += chunk.toString('utf8');
        if (buffered.length > 8192) buffered = buffered.slice(-8192);
        const lines = buffered.split('\n'); buffered = lines.pop() ?? '';
        for (const line of lines) {
          const value = line.trim();
          if (/^OPERATION_FIXTURE_STAGE=(DATABASE_READY|MIGRATED|SEEDED)$/.test(value)) lastStage = value.split('=')[1];
          if (value === 'OPERATION_FIXTURE_READY') { ready = true; resolve(); }
        }
      });
      void closed.then(() => { if (!ready) reject(new Error(`Owned operation fixture stopped at ${lastStage}`)); });
    });
    // Never print child stderr: errors can contain sensitive connection/provider material.
    child.stderr.on('data', () => {});
    child.stdin.on('error', () => {});
    let startTimer: ReturnType<typeof setTimeout> | undefined;
    await runWithHistoryCleanup(async () => {
      await Promise.race([started, new Promise<never>((_resolve, reject) => {
        startTimer = setTimeout(() => reject(new Error(`Owned operation fixture startup deadline at ${lastStage}`)), 45000);
      })]);
      clearTimeout(startTimer);
      const response = await request.get(operationOrigin + '/__test/fixture');
      let value: unknown;
      try { value = await response.json(); } catch { throw new Error('Unsupported operation fixture metadata'); }
      if (response.status() !== 200 || !metadata(value) || value.instance_id !== instance)
        throw new Error('Operation fixture ownership metadata mismatch; do not reuse another listener');
      await use(value);
    }, async () => {
      clearTimeout(startTimer);
      let stopTimer: ReturnType<typeof setTimeout> | undefined;
      try {
        if (child.exitCode === null && !child.killed && child.pid) child.stdin.end('stop\n');
        const result = await Promise.race([closed, new Promise<never>((_resolve, reject) => {
          stopTimer = setTimeout(() => reject(new Error('Owned operation fixture stop deadline')), 15000);
        })]);
        if (result !== 0) throw new Error('Owned operation fixture exited unsuccessfully');
      } catch {
        // Only the exact child returned by spawn, never a port listener or an existing process.
        if (child.exitCode === null && !child.killed && child.pid) child.kill('SIGTERM');
        if (testInfo.status === testInfo.expectedStatus) throw new Error('Owned operation fixture cleanup failed');
        try { console.error('Secondary owned operation fixture cleanup failed; original test failure retained.'); } catch { /* Keep the primary failure. */ }
      } finally { clearTimeout(stopTimer); }
    });
  }, { timeout: 60000 }]
});
export { expect } from '@playwright/test';
