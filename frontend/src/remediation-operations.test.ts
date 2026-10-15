import { afterEach, describe, expect, it, vi } from 'vitest';
import { isSession } from './api';
import { actionId } from './remediation-api';
import { operationId, operationRequest, operationSession, preparedOperation, resultId, targetId } from './operation-fixtures.test-support';
import { canPrepare, differentActor, isPreparation, isPreparedOperation, normalizedPreparation, OperationError,
  normalizedReason, prepareOperation, recoverOperations, remediationEnabled, sameIntentTarget, samePrepared, submitOperation,
  validReason, type OperationKind } from './remediation-operations';

const kinds: OperationKind[] = ['PROPOSE', 'DECIDE', 'REVOKE', 'REQUEST_EXECUTION', 'REQUEST_VERIFICATION'];
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
function corrupt(value: unknown, path: string, change: unknown): unknown {
  const result = structuredClone(value) as Record<string, unknown>, keys = path.split('.');
  let cursor = result;
  for (const key of keys.slice(0, -1)) cursor = cursor[key] as Record<string, unknown>;
  cursor[keys.at(-1)!] = change;
  return result;
}
afterEach(() => vi.unstubAllGlobals());

describe('optional bootstrap hints never authorize legacy or malformed sessions', () => {
  it('keeps legacy READ-only sessions valid and requires both hints plus bound CSRF for writes', () => {
    const session = operationSession();
    expect(isSession(session)).toBe(true); expect(remediationEnabled(session)).toBe(true);
    for (const change of [{ issuer: undefined }, { features: undefined }, { features: { remediation: false } }, { csrf_token: 'old-test-token' }]) {
      expect(remediationEnabled({ ...session, ...change })).toBe(false);
    }
    const { issuer: _issuer, features: _features, ...legacy } = session;
    expect(_issuer).toBeTruthy(); expect(_features).toBeTruthy();
    expect(isSession(legacy)).toBe(true); expect(remediationEnabled(legacy)).toBe(false);
  });
  it.each(['', 1, null, {}, []])('rejects malformed provided issuer %j', issuer => {
    expect(isSession({ ...operationSession(), issuer })).toBe(false);
  });
  it.each([null, [], true, {}, { remediation: 'true' }, { remediation: true, arbitrary: true }])('rejects malformed provided feature metadata %j', features => {
    expect(isSession({ ...operationSession(), features })).toBe(false);
  });
  it.each(['VIEWER', 'ANALYST', 'APPROVER', 'ADMIN'])('uses recognized %s roles only as UI affordances', role => {
    const session = { ...operationSession(), roles: [role] };
    for (const kind of kinds) expect(canPrepare(session, kind)).toBe(role === 'ADMIN'
      || role === 'APPROVER' && ['PROPOSE', 'DECIDE', 'REVOKE'].includes(kind)
      || role === 'ANALYST' && kind === 'PROPOSE');
    expect(differentActor(session, session)).toBe(false);
    expect(differentActor(session, { ...session, issuer: 'https://other.example.test' })).toBe(true);
    expect(differentActor(session, { ...session, subject: 'other' })).toBe(true);
  });
});

describe('closed coordination projections', () => {
  it.each(kinds)('normalizes and binds only the fixed %s input', kind => {
    const request = operationRequest(kind), prepared = preparedOperation(kind);
    expect(isPreparation(request)).toBe(true); expect(isPreparedOperation(prepared)).toBe(true);
    expect(normalizedPreparation({ ...request, input: { ...request.input, reason: '  exact reason  ' } } as typeof request).input.reason).toBe('exact reason');
    expect(sameIntentTarget(prepared, request)).toBe(true);
    expect(samePrepared(prepared, prepared)).toBe(true);
    for (const extra of ['url', 'method', 'idempotency_key', 'credentials', 'roles', 'desired_state']) {
      expect(isPreparation({ ...request, [extra]: 'not allowed' })).toBe(false);
      expect(isPreparation({ ...request, input: { ...request.input, [extra]: 'not allowed' } })).toBe(false);
    }
  });
  it('keeps fixed action/version server-selected and accepts bounded Unicode without lone surrogates', () => {
    const request = operationRequest();
    expect(isPreparation({ ...request, input: { ...request.input, action_id: actionId } })).toBe(false);
    expect(validReason('🔒'.repeat(2000))).toBe(true);
    for (const reason of ['', '  ', 1, null, 'x'.repeat(2001), '\ud800', '\udfff']) expect(validReason(reason)).toBe(false);
  });
  it('matches Python reason stripping instead of JavaScript-only whitespace behavior', () => {
    expect(normalizedReason('\u0085\u001c exact reason \u001f')).toBe('exact reason');
    expect(normalizedReason('\ufeff')).toBe('\ufeff');
    expect(validReason('\u0085\u001c')).toBe(false);
    expect(validReason('\ufeff')).toBe(true);
  });
  it.each([
    ['schema_version', '2.0.0'], ['operation', 'ARBITRARY'], ['operation_id', '../submit'],
    ['operation_id', targetId], ['target_id', targetId], ['risk_summary', 'Safe and reversible'],
    ['actor.issuer', ''], ['actor.subject', 0], ['actor.roles', ['ADMIN']], ['actor.extra', true],
    ['input.reason', ' unnormalized '], ['input.action_id', 'arbitrary'], ['input.action_version', '2.0.0'],
    ['input.finding_id', 'latest'], ['input.occurrence_id', true], ['input.url', 'https://unsafe.example.test'],
    ['prepared_at', NaN], ['expires_at', Infinity], ['expires_at', -1], ['prepared_at', Number.MAX_VALUE], ['attempts', 0.5],
    ['attempts', '0'], ['state', 'VERIFIED'], ['state', ['PREPARED']], ['state', 'UNCONFIRMED'],
    ['result', { result_id: resultId, scan_id: null }], ['extra', true]
  ])('rejects malformed or misleading %s', (path, value) => {
    expect(isPreparedOperation(corrupt(preparedOperation(), path, value))).toBe(false);
  });
  it('separates accepted requests from uncertain, expired and in-flight coordination', () => {
    const prepared = preparedOperation();
    for (const state of ['IN_FLIGHT', 'UNCONFIRMED']) expect(isPreparedOperation({ ...prepared, state, attempts: 1 })).toBe(true);
    expect(isPreparedOperation({ ...prepared, state: 'EXPIRED' })).toBe(true);
    expect(isPreparedOperation({ ...prepared, state: 'CONFIRMED', attempts: 1, result: { result_id: resultId, scan_id: null } })).toBe(true);
    expect(isPreparedOperation({ ...prepared, expires_at: prepared.prepared_at + 301 })).toBe(false);
    expect(isPreparedOperation({ ...prepared, expires_at: prepared.prepared_at - 1 })).toBe(false);
    const verification = preparedOperation('REQUEST_VERIFICATION');
    expect(isPreparedOperation({ ...verification, state: 'CONFIRMED', attempts: 1, result: { result_id: resultId, scan_id: targetId } })).toBe(true);
    expect(isPreparedOperation({ ...verification, state: 'CONFIRMED', attempts: 1, result: { result_id: resultId, scan_id: null } })).toBe(false);
    expect(samePrepared(prepared, { ...prepared, operation_id: resultId })).toBe(false);
  });
});

describe('fixed manual transport without browser-selected keys or automatic retries', () => {
  it.each(kinds)('prepares %s using only its closed same-origin endpoint and bound session', async kind => {
    const prepared = preparedOperation(kind), fetch = vi.fn().mockResolvedValue(json(prepared, 201));
    vi.stubGlobal('fetch', fetch);
    expect(await prepareOperation(operationSession(), operationRequest(kind))).toEqual(prepared);
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, options] = fetch.mock.calls[0];
    expect(url).toBe('/dashboard/api/remediation-operations');
    expect(options).toMatchObject({ method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'C'.repeat(43), 'X-Dashboard-Context': 'A'.repeat(43) } });
    expect(Object.keys(options.headers).sort()).toEqual(['Content-Type', 'X-CSRF-Token', 'X-Dashboard-Context']);
    expect(JSON.parse(options.body)).toEqual(normalizedPreparation(operationRequest(kind)));
  });
  it.each(kinds)('explicitly submits/retries %s using the same server UUID with an empty body', async kind => {
    const original = { ...preparedOperation(kind), state: 'UNCONFIRMED' as const, attempts: 1 };
    const result = { ...original, attempts: 2 };
    const fetch = vi.fn().mockResolvedValue(json(result)); vi.stubGlobal('fetch', fetch);
    expect(await submitOperation(operationSession(), original)).toEqual(result);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0][0]).toBe(`/dashboard/api/remediation-operations/${operationId}/submit`);
    expect(fetch.mock.calls[0][1]).toMatchObject({ method: 'POST', body: '{}', credentials: 'same-origin', redirect: 'error' });
    expect(fetch.mock.calls[0][1].headers['Idempotency-Key']).toBeUndefined();
  });
  it('does not dispatch coercive requests, missing opt-in, other actors or disallowed capabilities', async () => {
    const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
    await expect(prepareOperation({ ...operationSession(), roles: ['VIEWER'] }, operationRequest())).rejects.toBeInstanceOf(OperationError);
    await expect(prepareOperation(operationSession(), { ...operationRequest(), url: 'https://unsafe.example.test' } as unknown as ReturnType<typeof operationRequest>)).rejects.toBeInstanceOf(OperationError);
    await expect(submitOperation({ ...operationSession(), subject: 'other' }, preparedOperation())).rejects.toBeInstanceOf(OperationError);
    await expect(submitOperation(operationSession(), { ...preparedOperation(), state: 'IN_FLIGHT', attempts: 1 })).rejects.toBeInstanceOf(OperationError);
    expect(fetch).not.toHaveBeenCalled();
  });
  it.each([403, 409, 422, 503])('keeps submission uncertainty after HTTP %s without retry, raw errors or a replacement key', async status => {
    const fetch = vi.fn().mockResolvedValue(json({ private: 'never reflect error content' }, status)); vi.stubGlobal('fetch', fetch);
    await expect(submitOperation(operationSession(), preparedOperation())).rejects.toMatchObject({ status,
      message: expect.stringContaining('unconfirmed') });
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it('ignores malformed success and mismatched immutable coordination instead of confirming', async () => {
    const prepared = preparedOperation();
    const fetch = vi.fn().mockResolvedValue(json({ ...prepared, operation_id: '99999999-9999-4999-8999-999999999999', state: 'UNCONFIRMED', attempts: 1 }));
    vi.stubGlobal('fetch', fetch);
    await expect(submitOperation(operationSession(), prepared)).rejects.toMatchObject({ stage: 'SUBMIT' });
    fetch.mockResolvedValueOnce(json({ ...prepared, actor: { ...prepared.actor, subject: 'other' } }));
    await expect(prepareOperation(operationSession(), operationRequest())).rejects.toMatchObject({ stage: 'PREPARE' });
  });
  it('sanitizes lost or aborted responses without an automatic retry and preserves 401 for global clearing', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('private transport detail')); vi.stubGlobal('fetch', fetch);
    await expect(submitOperation(operationSession(), preparedOperation())).rejects.toMatchObject({ message: expect.not.stringContaining('private transport') });
    expect(fetch).toHaveBeenCalledTimes(1);
    fetch.mockResolvedValueOnce(json({}, 401));
    await expect(submitOperation(operationSession(), preparedOperation())).rejects.toMatchObject({ status: 401 });
  });
  it('recovers a bounded unique same-actor list using GET only', async () => {
    const value = preparedOperation(), fetch = vi.fn().mockResolvedValue(json({ schema_version: '1.0.0', items: [value] }));
    vi.stubGlobal('fetch', fetch);
    expect(await recoverOperations(operationSession())).toEqual([value]);
    expect(fetch.mock.calls[0][1].method).toBeUndefined();
    for (const items of [[value, value], [{ ...value, actor: { ...value.actor, issuer: 'other' } }], Array(17).fill(value)]) {
      fetch.mockResolvedValueOnce(json({ schema_version: '1.0.0', items }));
      await expect(recoverOperations(operationSession())).rejects.toMatchObject({ stage: 'RECOVER' });
    }
  });
});
