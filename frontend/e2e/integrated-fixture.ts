import { test as base } from '@playwright/test';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { isUUID } from '../src/api';
import { runWithHistoryCleanup } from './history-page';
import { CapacityCohort } from './integrated-capacity';

export const integratedOrigin = 'http://127.0.0.1:9031';
export const scenarioExpected = {
  'verification-equal': { outcome: 'INCONCLUSIVE', reason: 'OBSERVATION_NOT_LATER', technical: 'PASS', scan: 'COMPLETED' },
  'verification-provenance': { outcome: 'INCONCLUSIVE', reason: 'PROVENANCE_UNAVAILABLE', technical: 'No decisive retained evidence', scan: 'COMPLETED' },
  'feature-hints': { outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', technical: 'PASS', scan: 'COMPLETED' },
  'history-versions': { outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', technical: 'PASS', scan: 'COMPLETED' },
  'reply-reference': { outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', technical: 'PASS', scan: 'COMPLETED' },
  'history-reference': { outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', technical: 'PASS', scan: 'COMPLETED' },
  'revoked-before-intent': { outcome: 'NO_VERIFICATION', reason: 'APPROVAL_REVOKED', technical: 'Original FAIL', scan: 'NO_SCAN' },
  'revoked-after-ack': { outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', technical: 'PASS', scan: 'COMPLETED' },
  'admission-stale': { outcome: 'NO_EXECUTION', reason: 'STALE_TARGET', technical: 'Original FAIL', scan: 'COMPLETED' },
  'governance-change': { outcome: 'NO_EXECUTION', reason: 'STALE_GOVERNANCE', technical: 'Original FAIL', scan: 'NO_SCAN' },
  'governance-round-trip': { outcome: 'NO_EXECUTION', reason: 'STALE_GOVERNANCE', technical: 'Original FAIL', scan: 'NO_SCAN' },
  'governance-exception': { outcome: 'NO_EXECUTION', reason: 'ACTIVE_EXCEPTION', technical: 'Original FAIL', scan: 'NO_SCAN' },
  'stale-newer-fail': { outcome: 'NO_EXECUTION', reason: 'STALE_TARGET', technical: 'Original FAIL', scan: 'COMPLETED' },
  'stale-newer-pass': { outcome: 'NO_EXECUTION', reason: 'STALE_TARGET', technical: 'Original FAIL', scan: 'COMPLETED' },
  'stale-newer-insufficient': { outcome: 'NO_EXECUTION', reason: 'STALE_TARGET', technical: 'Original FAIL', scan: 'PARTIAL' },
  'stale-equal-fail': { outcome: 'NO_EXECUTION', reason: 'STALE_TARGET', technical: 'Original FAIL', scan: 'COMPLETED' },
  'stale-equal-pass': { outcome: 'NO_EXECUTION', reason: 'STALE_TARGET', technical: 'Original FAIL', scan: 'COMPLETED' },
  'stale-equal-insufficient': { outcome: 'NO_EXECUTION', reason: 'STALE_TARGET', technical: 'Original FAIL', scan: 'PARTIAL' },
  'subject-replacement': { outcome: 'NO_EXECUTION', reason: 'SUBJECT_CHANGED', technical: 'Original FAIL', scan: 'NO_SCAN' },
  'issuer-rejection': { outcome: 'NO_EXECUTION', reason: 'ISSUER_REJECTED', technical: 'Original FAIL', scan: 'NO_SCAN' },
  'cross-issuer': { outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', technical: 'PASS', scan: 'COMPLETED' },
  verified: { outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', technical: 'PASS', scan: 'COMPLETED' },
  'recovery-guards': { outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', technical: 'PASS', scan: 'COMPLETED' },
  'in-flight': { outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', technical: 'PASS', scan: 'COMPLETED' },
  'capacity-session': { outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', technical: 'PASS', scan: 'COMPLETED' },
  'capacity-global': { outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', technical: 'PASS', scan: 'COMPLETED' },
  'uncertain-submit': { outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', technical: 'PASS', scan: 'COMPLETED' },
  'capability-loss': { outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', technical: 'PASS', scan: 'COMPLETED' },
  'expiry-session': { outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', technical: 'PASS', scan: 'COMPLETED' },
  'expiry-global': { outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', technical: 'PASS', scan: 'COMPLETED' },
  'proposal-expiry': { outcome: 'NO_EXECUTION', reason: 'EXPIRED', technical: 'Original FAIL', scan: 'NO_SCAN' },
  'idle-expiry': { outcome: 'NO_EXECUTION', reason: 'SESSION_IDLE_EXPIRED', technical: 'Original FAIL', scan: 'NO_SCAN' },
  'token-expiry': { outcome: 'NO_EXECUTION', reason: 'ACCESS_TOKEN_EXPIRED', technical: 'Original FAIL', scan: 'NO_SCAN' },
  'execution-expiry': { outcome: 'NO_VERIFICATION', reason: 'EXECUTION_EXPIRED', technical: 'Original FAIL', scan: 'NO_SCAN' },
  'not-verified': { outcome: 'NOT_VERIFIED', reason: 'POSTCONDITION_FAIL', technical: 'FAIL', scan: 'COMPLETED' },
  'attempt-limit': { outcome: 'NOT_VERIFIED', reason: 'POSTCONDITION_FAIL', technical: 'FAIL', scan: 'COMPLETED' },
  quarantine: { outcome: 'NO_VERIFICATION', reason: 'QUARANTINED', technical: 'Original FAIL', scan: 'NO_SCAN' },
  'late-ack': { outcome: 'NO_VERIFICATION', reason: 'QUARANTINED', technical: 'Original FAIL', scan: 'NO_SCAN' },
  'kms-changed': { outcome: 'INCONCLUSIVE', reason: 'KMS_CONTEXT_CHANGED', technical: 'PASS', scan: 'COMPLETED' },
  partial: { outcome: 'INCONCLUSIVE', reason: 'SCAN_INCOMPLETE', technical: 'No decisive retained evidence', scan: 'PARTIAL' }
} as const;
export type ScenarioName = keyof typeof scenarioExpected;
interface Source {
  instance_id: string; finding_id: string; occurrence_id: string;
  scan_id: string; assessment_id: string; scan_submissions: number; scenario: ScenarioName; proposal_response_losses: number;
  proposal_reply_gate: 'WAITING' | 'DISABLED';
}
type Command = 'RUN_WORKER' | 'RELEASE_READER' | 'RESTART_AUTHORITY' | 'COLLECT_STALE' | 'CHANGE_GOVERNANCE';
const targetField = (command: Command) => ({ RUN_WORKER: 'execution_id', RELEASE_READER: 'verification_id', RESTART_AUTHORITY: 'proposal_id', COLLECT_STALE: 'proposal_id', CHANGE_GOVERNANCE: 'proposal_id' } as const)[command];
export interface IntegratedFixture extends Source {
  control: (command: Command, target: string, key: string) => Promise<void>;
  capacity?: CapacityCohort;
}
function metadata(value: unknown): value is Source {
  if (typeof value !== 'object' || value === null || Object.keys(value).length !== 9) return false;
  const fields = value as Record<string, unknown>;
  return ['instance_id', 'finding_id', 'occurrence_id', 'scan_id', 'assessment_id']
    .every(key => typeof fields[key] === 'string' && isUUID(fields[key])) && fields.scan_submissions === 0
    && fields.proposal_response_losses === 0
    && fields.proposal_reply_gate === (fields.scenario === 'in-flight' ? 'WAITING' : 'DISABLED')
    && typeof fields.scenario === 'string' && Object.hasOwn(scenarioExpected, fields.scenario);
}

function startup(stage: 'START' | 'CHILD_STARTED' | 'CHILD_READY' | 'METADATA_READY' | 'CAPACITY_BEGIN' | 'CAPACITY_READY' | 'BODY_READY') {
  // Fixed lifecycle markers only; no URLs, tokens, child output or private control frames.
  try { console.log('D3_FIXTURE_' + stage); } catch { /* Preserve the original test outcome. */ }
}

export const test = base.extend<{ integratedFixture: IntegratedFixture; integratedScenario: ScenarioName }>({
  integratedScenario: ['verified', { option: true }],
  integratedFixture: [async ({ request, playwright, integratedScenario }, use, testInfo) => {
    startup('START');
    let capacity: CapacityCohort | undefined;
    const python = process.env.PYTHON_EXECUTABLE;
    if (!python || process.env.DASHBOARD_BROWSER_TEST !== '1')
      throw new Error('Use the owned integrated browser validation harness');
    const external = process.env.DASHBOARD_INTEGRATED_EXTERNAL === '1';
    if (process.env.DASHBOARD_INTEGRATED_EXTERNAL && !external) throw new Error('Invalid integrated adapter mode');
    if (external && process.env.DASHBOARD_INTEGRATED_SCENARIO !== integratedScenario)
      throw new Error('Integrated parent-selected scenario mismatch');
    const expected = scenarioExpected[integratedScenario];
    const quarantined = integratedScenario === 'quarantine' || integratedScenario === 'late-ack';
    const instance = external ? process.env.DASHBOARD_INTEGRATED_INSTANCE : randomUUID();
    if (!instance || !isUUID(instance)) throw new Error('Invalid integrated parent owner');
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
      !/^(APP_|AUTH_|AWS_|BOTO|DATABASE_|TEST_DATABASE_|OIDC_|DASHBOARD_|REMEDIATION_|ASSESSMENT_|DEV_IDENTITY_|VITE_)/.test(key)));
    Object.assign(env, { DASHBOARD_BROWSER_TEST: '1', DASHBOARD_INTEGRATED_INSTANCE: instance,
      DASHBOARD_INTEGRATED_SCENARIO: integratedScenario, PYTHONUNBUFFERED: '1' });
    if (external) Object.assign(env, { DASHBOARD_INTEGRATED_EXTERNAL: '1',
      DATABASE_URL: process.env.DATABASE_URL, DASHBOARD_INTEGRATED_SOURCE: process.env.DASHBOARD_INTEGRATED_SOURCE });
    const child = spawn(python, ['-m', external ? 'tests.dashboard_integrated_proxy' : 'tests.dashboard_integrated_guardian'], {
      cwd: path.resolve(import.meta.dirname, '../..'), env, shell: false, windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    startup('CHILD_STARTED');
    let ready = false, proof = false, cleaned = false, buffered = '', invalid = false, stage = 'STARTING';
    const pending = new Map<string, { command: Command; target: string; resolve: () => void; reject: (error: Error) => void }>();
    let readyResolve: () => void, readyReject: (error: Error) => void;
    const started = new Promise<void>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
    const fail = () => {
      invalid = true;
      const error = new Error(`Owned integrated fixture response failed at ${stage}; no retry is authorized`);
      if (!ready) readyReject(error);
      for (const value of pending.values()) value.reject(error);
      pending.clear();
    };
    const closed = new Promise<number | null>(resolve => {
      child.once('close', code => { if (!cleaned) fail(); resolve(code); });
      child.once('error', () => { fail(); resolve(-1); });
    });
    child.stdout.on('data', (chunk: Buffer) => {
      buffered += chunk.toString('utf8');
      if (buffered.length > 8192) { fail(); return; }
      const lines = buffered.split('\n'); buffered = lines.pop() ?? '';
      for (const line of lines) {
        const text = line.trim();
        if (text.startsWith('INTEGRATED_PARENT_CONTROL=') || text.startsWith('INTEGRATED_PARENT_REPLY=')) {
          if (!external || text.length > 2048) { fail(); continue; }
          // Private Docker-stdout relay, consumed by the owning parent before ordinary logging.
          process.stdout.write(text + '\n'); continue;
        }
        if (/^INTEGRATED_FIXTURE_STAGE=[A-Z_]{1,32}$/.test(text)) stage = text.split('=')[1];
        if (text === 'INTEGRATED_FIXTURE_READY') { ready = true; readyResolve(); }
        if (text === 'INTEGRATED_PERSISTENCE_PROOF=' + expected.outcome) proof = true;
        if (text === 'INTEGRATED_FIXTURE_CLEANED') cleaned = true;
        if (!text.startsWith('INTEGRATED_REPLY=')) continue;
        try {
          const reply: unknown = JSON.parse(text.slice('INTEGRATED_REPLY='.length));
          if (typeof reply !== 'object' || reply === null) throw new Error();
          const value = reply as Record<string, unknown>;
          const item = typeof value.request_id === 'string' && pending.get(value.request_id);
          if (!item || Object.keys(value).length !== 7 || value.schema_version !== '1.0.0'
            || value.instance_id !== instance || value.command !== item.command || value.effects_canceled !== false
            || value[targetField(item.command)] !== item.target
            || value.state !== (item.command === 'RUN_WORKER'
              ? quarantined ? 'WORKER_QUARANTINED' : integratedScenario === 'execution-expiry' || integratedScenario === 'revoked-before-intent' ? 'WORKER_NO_WRITE' : 'WORKER_ACKNOWLEDGED'
              : item.command === 'RESTART_AUTHORITY' ? 'AUTHORITY_RESTARTED'
              : item.command === 'COLLECT_STALE' ? 'STALE_OBSERVATION_PERSISTED'
              : item.command === 'CHANGE_GOVERNANCE' ? 'GOVERNANCE_CHANGED' : 'READER_RELEASED')) throw new Error();
          pending.delete(value.request_id as string); item.resolve();
        } catch { fail(); }
      }
    });
    // No raw child stderr: it could contain provider, HTTP or database material.
    child.stderr.on('data', () => {}); child.stdin.on('error', fail);
    let timer: ReturnType<typeof setTimeout> | undefined;
    await runWithHistoryCleanup(async () => {
      await Promise.race([started, new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error('Owned integrated fixture startup deadline')), 660000);
      })]);
      clearTimeout(timer);
      startup('CHILD_READY');
      const response = await request.get(integratedOrigin + '/__test/fixture');
      const value: unknown = await response.json();
      if (response.status() !== 200 || !metadata(value) || value.instance_id !== instance
        || value.scenario !== integratedScenario || invalid)
        throw new Error('Integrated fixture metadata ownership mismatch; never adopt another listener');
      startup('METADATA_READY');
      const control = async (command: Command, target: string, key: string) => {
        if (invalid || !isUUID(target) || !isUUID(key) || pending.has(key) || child.exitCode !== null)
          throw new Error('Invalid or unavailable private integrated control');
        const message = { schema_version: '1.0.0', instance_id: instance, request_id: key, command,
          [targetField(command)]: target };
        let deadline: ReturnType<typeof setTimeout> | undefined;
        try {
          await new Promise<void>((resolve, reject) => {
            pending.set(key, { command, target, resolve, reject });
            deadline = setTimeout(() => { fail(); }, 60000);
            child.stdin.write(JSON.stringify(message) + '\n');
          });
        } finally { clearTimeout(deadline); }
      };
      if (integratedScenario === 'capacity-global' || integratedScenario === 'expiry-global') {
        startup('CAPACITY_BEGIN');
        capacity = new CapacityCohort(playwright.request);
        if (integratedScenario === 'expiry-global') await capacity.populateExpiry(); else await capacity.populate();
        startup('CAPACITY_READY');
      }
      startup('BODY_READY');
      await use({ ...value, control, capacity });
    }, async () => {
      await runWithHistoryCleanup(async () => { if (capacity) await capacity.close(); }, async () => {
      clearTimeout(timer);
      let deadline: ReturnType<typeof setTimeout> | undefined;
      try {
        if (child.exitCode === null && !child.killed && child.pid) child.stdin.end(JSON.stringify({
          schema_version: '1.0.0', instance_id: instance, request_id: randomUUID(), command: 'STOP'
        }) + '\n');
        const code = await Promise.race([closed, new Promise<never>((_resolve, reject) => {
          deadline = setTimeout(() => reject(new Error('Owned integrated fixture stop deadline')), 45000);
        })]);
        if (code !== 0 || !cleaned || !proof || invalid) throw new Error('Integrated proof or owned cleanup incomplete');
      } catch {
        if (child.exitCode === null && !child.killed && child.pid) child.kill('SIGTERM');
        if (testInfo.status === testInfo.expectedStatus) throw new Error('Owned integrated fixture cleanup failed');
        try { console.error('Secondary integrated cleanup failed; original test failure retained.'); } catch { /* Preserve primary. */ }
      } finally { clearTimeout(deadline); }
      });
    });
  }, { timeout: 720000 }]
});
export { expect } from '@playwright/test';
