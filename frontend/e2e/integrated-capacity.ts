import { expect, type APIRequest, type APIRequestContext } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { isSession } from '../src/api';
import { isPreparedOperation, remediationEnabled, samePrepared, type PreparedOperation, type RemediationSession } from '../src/remediation-operations';
import { runWithHistoryCleanup } from './history-page';

const origin = 'http://127.0.0.1:9031', issuer = 'http://127.0.0.1:9032';
const root = '/dashboard/api/remediation-operations';
const document = () => ({ schema_version: '1.0.0', operation: 'PROPOSE',
  input: { finding_id: randomUUID(), occurrence_id: randomUUID(), reason: 'Capacity coordination only; no accepted domain authority.' } });
const sorted = (values: PreparedOperation[]) => [...values].sort((a, b) => a.operation_id.localeCompare(b.operation_id));

// Genuine signed sessions and BFF preparations only. No SQL, service override, seeded grant,
// test-only product endpoint, reduced quota, browser credential export or automatic submission.
export class CapacityOwner {
  private session?: RemediationSession;
  private frozen: PreparedOperation[] = [];
  private expected = 16;
  revoked = false;
  constructor(readonly context: APIRequestContext) {}
  private headers() {
    if (!this.session || this.revoked) throw new Error('Unavailable capacity owner');
    return { Origin: origin, 'Sec-Fetch-Site': 'same-origin', 'X-CSRF-Token': this.session.csrf_token,
      'X-Dashboard-Context': this.session.session_context };
  }
  async attach() {
    const response = await this.context.get(origin + '/dashboard/session');
    expect(response.status()).toBe(200);
    const value: unknown = await response.json();
    if (!isSession(value) || !value.authenticated || !remediationEnabled(value)
      || value.subject !== 'proposer' || value.issuer !== issuer || value.roles.join(',') !== 'ANALYST')
      throw new Error('Capacity owner must be the genuine signed analyst');
    this.session = value;
  }
  async signIn() {
    let stage = 'BOOTSTRAP';
    try {
      const bootstrap = await this.context.get(origin + '/dashboard/session');
      const anonymous: unknown = await bootstrap.json();
      if (bootstrap.status() !== 200 || !isSession(anonymous) || anonymous.authenticated)
        throw new Error();
      stage = 'LOGIN';
      const login = await this.context.post(origin + '/dashboard/auth/login', { headers: {
        Origin: origin, 'Sec-Fetch-Site': 'same-origin', 'X-CSRF-Token': anonymous.csrf_token
      } });
      if (login.status() !== 200) throw new Error();
      const navigation = await login.json();
      const url = new URL(navigation.authorization_url);
      if (url.origin !== issuer || url.pathname !== '/authorize' || url.username || url.password || url.hash)
        throw new Error();
      stage = 'AUTHORIZE';
      if ((await this.context.get(url.href)).status() !== 200) throw new Error();
      stage = 'APPROVE';
      if ((await this.context.get(issuer + '/approve?identity=proposer')).status() !== 200) throw new Error();
      stage = 'ATTACH'; await this.attach();
    } catch { throw new Error('Controlled capacity sign-in failed at ' + stage + '; no authority was seeded'); }
  }
  async fill() {
    await this.populate(16, true);
    await this.rejectExtra(); await this.assertRetained();
  }
  async fillExpiry(reserved?: PreparedOperation, partial = false) {
    if (reserved) {
      expect(isPreparedOperation(reserved) && reserved.state === 'PREPARED' && reserved.attempts === 0).toBe(true);
      expect(reserved.actor).toEqual({ issuer, subject: 'proposer' });
      this.frozen.push(reserved);
    }
    await this.populate(partial ? 15 : 16, false);
    await this.assertRetained();
  }
  private async populate(limit: 15 | 16, submitMissing: boolean) {
    this.expected = limit;
    while (this.frozen.length < limit) {
      const response = await this.context.post(origin + root, { data: document(), headers: this.headers() });
      expect(response.status()).toBe(201);
      const value: unknown = await response.json();
      if (!isPreparedOperation(value) || value.state !== 'PREPARED' || value.attempts !== 0)
        throw new Error('Invalid capacity preparation');
      this.frozen.push(value);
    }
    // A real missing-target service rejection leaves uncertainty, not permission to evict it.
    if (!submitMissing) return;
    const first = this.frozen[0];
    const submitted = await this.context.post(origin + root + '/' + first.operation_id + '/submit',
      { data: {}, headers: this.headers() });
    expect(submitted.status()).toBe(200);
    const value: unknown = await submitted.json();
    if (!isPreparedOperation(value) || value.operation_id !== first.operation_id
      || value.state !== 'UNCONFIRMED' || value.attempts !== 1 || value.result !== null)
      throw new Error('Capacity uncertainty was not preserved');
    this.frozen[0] = value;
  }
  async retainAfterExpiry(reserved?: PreparedOperation) {
    if (reserved) {
      const original = this.frozen.find(value => value.operation_id === reserved.operation_id);
      if (!original || !samePrepared(original, reserved) || reserved.state !== 'UNCONFIRMED'
        || reserved.attempts !== 1 || reserved.result !== null) throw new Error('Unbound expired forwarded work');
    }
    this.frozen = this.frozen.map((value): PreparedOperation => value.operation_id === reserved?.operation_id
      ? reserved : value.state === 'PREPARED' ? { ...value, state: 'EXPIRED' } : value);
    await this.assertRetained();
    return this.frozen.filter(value => value.state === 'EXPIRED').length;
  }
  async rejectExtra() {
    const denied = await this.context.post(origin + root, { data: document(), headers: this.headers() });
    expect(denied.status()).toBe(503);
    expect(await denied.json()).toEqual({ detail: 'Dashboard operation capacity reached; review existing history' });
  }
  async assertRetained() {
    const response = await this.context.get(origin + root, { headers: this.headers() });
    expect(response.status()).toBe(200);
    const value = await response.json();
    expect(value.schema_version).toBe('1.0.0');
    expect(value.items).toHaveLength(this.expected);
    if (!value.items.every(isPreparedOperation)) throw new Error('Unsupported retained capacity operations');
    expect(sorted(value.items)).toEqual(sorted(this.frozen));
  }
  ids() { return this.frozen.map(value => value.operation_id); }
  async rejectForeign(key: string) {
    const response = await this.context.get(origin + root + '/' + key, { headers: this.headers() });
    expect(response.status()).toBe(404);
  }
  async logout() {
    const response = await this.context.post(origin + '/dashboard/auth/logout', { headers: this.headers() });
    expect(response.status()).toBe(204);
    this.revoked = true;
  }
  async assertOldRejected(context: APIRequestContext) {
    if (!this.session || !this.revoked) throw new Error('No revoked capacity owner');
    const response = await context.get(origin + root,
      { headers: { 'X-Dashboard-Context': this.session.session_context } });
    expect(response.status()).toBe(401);
  }
}

export class CapacityCohort {
  private owners: CapacityOwner[] = [];
  constructor(private factory: APIRequest) {}
  async populate() {
    await this.populateOwners(false);
  }
  async populateExpiry() {
    await this.populateOwners(true);
  }
  private async populateOwners(reservedSlot: boolean) {
    for (let batch = 0; batch < 4; batch += 1) {
      await Promise.all(Array.from({ length: 4 }, async () => {
        const context = await this.factory.newContext();
        const owner = new CapacityOwner(context); this.owners.push(owner);
        await owner.signIn();
        if (reservedSlot) await owner.fillExpiry(undefined, batch === 3 && this.owners.indexOf(owner) === 15);
        else await owner.fill();
      }));
    }
    expect(this.owners).toHaveLength(16);
    const identifiers = this.owners.flatMap(owner => owner.ids());
    expect(identifiers).toHaveLength(reservedSlot ? 255 : 256);
    expect(new Set(identifiers).size).toBe(reservedSlot ? 255 : 256);
    await this.owners[1].rejectForeign(this.owners[0].ids()[0]);
    await this.assertRetained();
    console.log(reservedSlot ? 'D3_CAPACITY_SETUP_255_RESERVED' : 'D3_CAPACITY_SETUP_256');
  }
  async retainAfterExpiry() {
    const counts = await Promise.all(this.owners.map(owner => owner.retainAfterExpiry()));
    expect(counts.reduce((sum, count) => sum + count, 0)).toBe(255);
    await this.assertRetained();
  }
  async assertRetained() {
    const active = this.owners.filter(owner => !owner.revoked);
    expect(active).toHaveLength(this.owners.some(owner => owner.revoked) ? 15 : 16);
    for (let start = 0; start < active.length; start += 4)
      await Promise.all(active.slice(start, start + 4).map(owner => owner.assertRetained()));
  }
  async releaseOne() {
    const owner = this.owners.at(-1);
    if (!owner || owner.revoked) throw new Error('No unreleased capacity owner');
    const old = await this.factory.newContext({ storageState: await owner.context.storageState() });
    await runWithHistoryCleanup(async () => {
      await owner.logout(); await owner.assertOldRejected(old); await this.assertRetained();
    }, async () => { await old.dispose(); });
  }
  async close() {
    const outcomes = await Promise.allSettled(this.owners.map(async owner => {
      await runWithHistoryCleanup(async () => { if (!owner.revoked) await owner.logout(); },
        async () => { await owner.context.dispose(); });
    }));
    if (outcomes.some(value => value.status === 'rejected')) throw new Error('Owned capacity session cleanup failed');
  }
}
