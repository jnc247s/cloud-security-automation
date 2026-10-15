// Browser coordination only. The BFF and real bearer APIs independently authorize every call.
import { APIError, isUUID, type Session } from './api';
import { object } from './investigation-api';
import { actionId, actionRisk, sameImmutable, type Actor } from './remediation-api';

type AuthenticatedSession = Extract<Session, { authenticated: true }>;
export type RemediationSession = AuthenticatedSession & { issuer: string; features: { remediation: true } };
export type OperationKind = 'PROPOSE' | 'DECIDE' | 'REVOKE' | 'REQUEST_EXECUTION' | 'REQUEST_VERIFICATION';
export type OperationState = 'PREPARED' | 'IN_FLIGHT' | 'UNCONFIRMED' | 'CONFIRMED' | 'EXPIRED';
type Reason = { reason: string };
type ProposalInput = Reason & { finding_id: string; occurrence_id: string };
type DecisionInput = Reason & { proposal_sha256: string; decision: 'APPROVE' | 'REJECT' };
type ApprovedInput = Reason & { proposal_sha256: string; approval_decision_id: string };
export type Preparation = { schema_version: '1.0.0' } & (
  { operation: 'PROPOSE'; input: ProposalInput }
  | { operation: 'DECIDE'; target_id: string; input: DecisionInput }
  | { operation: 'REVOKE' | 'REQUEST_EXECUTION'; target_id: string; input: ApprovedInput }
  | { operation: 'REQUEST_VERIFICATION'; target_id: string; input: Reason }
);
export type PreparedOperation = {
  schema_version: '1.0.0'; operation_id: string;
  actor: { issuer: string; subject: string }; risk_summary: typeof actionRisk;
  prepared_at: number; expires_at: number; state: OperationState; attempts: number;
  result: { result_id: string; scan_id: string | null } | null;
} & (
  { operation: 'PROPOSE'; target_id: null; input: ProposalInput & { action_id: typeof actionId; action_version: '1.0.0' } }
  | { operation: 'DECIDE'; target_id: string; input: DecisionInput }
  | { operation: 'REVOKE' | 'REQUEST_EXECUTION'; target_id: string; input: ApprovedInput }
  | { operation: 'REQUEST_VERIFICATION'; target_id: string; input: Reason }
);
type Identity = Pick<RemediationSession, 'issuer' | 'subject' | 'session_context'>;
type Guard = (v: unknown) => boolean;
const text: Guard = v => typeof v === 'string' && v.trim().length > 0;
const uuid: Guard = v => typeof v === 'string' && isUUID(v);
const sha: Guard = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const finite: Guard = v => typeof v === 'number' && Number.isFinite(v) && v >= 0;
const epoch: Guard = v => finite(v) && Number(v) <= 8640000000000;
const integer: Guard = v => finite(v) && Number.isSafeInteger(v);
const literal = (v: unknown): Guard => x => x === v;
const opaque = (v: string) => /^[A-Za-z0-9_-]{43}$/.test(v);
const operationUUID = (v: unknown): v is string => typeof v === 'string'
  && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
function shape(v: unknown, fields: Record<string, Guard>): v is Record<string, unknown> {
  return object(v) && Object.keys(v).length === Object.keys(fields).length
    && Object.entries(fields).every(([key, valid]) => Object.hasOwn(v, key) && valid(v[key]));
}
// Match the accepted Python str.strip reason normalization, including NEL/record separators,
// and excluding the BOM that JavaScript trim alone would remove.
const extraReasonWhitespace = new Set([0x85, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000]);
const reasonWhitespace = (point: number) => point >= 9 && point <= 13 || point >= 28 && point <= 32
  || point >= 0x2000 && point <= 0x200a || extraReasonWhitespace.has(point);
export function normalizedReason(value: string): string {
  let start = 0, end = value.length;
  while (start < end && reasonWhitespace(value.charCodeAt(start))) start += 1;
  while (end > start && reasonWhitespace(value.charCodeAt(end - 1))) end -= 1;
  return value.slice(start, end);
}
export function validReason(v: unknown): v is string {
  return typeof v === 'string' && normalizedReason(v).length > 0 && [...v].length <= 2000
    && [...v].every(c => { const point = c.codePointAt(0)!; return point < 0xd800 || point > 0xdfff; });
}
function input(v: unknown, kind: unknown, prepared = false): boolean {
  const fields: Record<string, Guard> = { reason: validReason };
  if (kind === 'PROPOSE') {
    Object.assign(fields, { finding_id: uuid, occurrence_id: uuid });
    if (prepared) Object.assign(fields, { action_id: literal(actionId), action_version: literal('1.0.0') });
  } else if (kind === 'DECIDE') {
    Object.assign(fields, { proposal_sha256: sha, decision: (v: unknown) => v === 'APPROVE' || v === 'REJECT' });
  } else if (kind === 'REVOKE' || kind === 'REQUEST_EXECUTION') {
    Object.assign(fields, { proposal_sha256: sha, approval_decision_id: uuid });
  } else if (kind !== 'REQUEST_VERIFICATION') return false;
  return shape(v, fields) && (!prepared || v.reason === normalizedReason(v.reason as string));
}
export function remediationEnabled(session: AuthenticatedSession): session is RemediationSession {
  return typeof session.issuer === 'string' && session.issuer.trim().length > 0
    && session.features?.remediation === true && session.subject.trim().length > 0
    && opaque(session.csrf_token) && opaque(session.session_context);
}
export function canPrepare(session: RemediationSession, kind: OperationKind): boolean {
  return session.roles.includes('ADMIN') || (['PROPOSE', 'DECIDE', 'REVOKE'].includes(kind)
    && session.roles.includes('APPROVER')) || (kind === 'PROPOSE' && session.roles.includes('ANALYST'));
}
export const differentActor = (session: RemediationSession, actor: Pick<Actor, 'issuer' | 'subject'>) =>
  session.issuer !== actor.issuer || session.subject !== actor.subject;
export function isPreparation(v: unknown): v is Preparation {
  if (!object(v) || v.schema_version !== '1.0.0' || !input(v.input, v.operation)) return false;
  return v.operation === 'PROPOSE'
    ? shape(v, { schema_version: literal('1.0.0'), operation: literal('PROPOSE'), input: x => input(x, v.operation) })
    : shape(v, { schema_version: literal('1.0.0'), operation: text, target_id: uuid, input: x => input(x, v.operation) });
}
export function normalizedPreparation(v: Preparation): Preparation {
  if (!isPreparation(v)) throw new OperationError('PREPARE', 0);
  if (v.operation === 'PROPOSE') return { schema_version: '1.0.0', operation: v.operation,
    input: { finding_id: v.input.finding_id.toLowerCase(), occurrence_id: v.input.occurrence_id.toLowerCase(), reason: normalizedReason(v.input.reason) } };
  if (v.operation === 'DECIDE') return { ...v, target_id: v.target_id.toLowerCase(), input: { ...v.input, reason: normalizedReason(v.input.reason) } };
  if (v.operation === 'REQUEST_VERIFICATION') return { ...v, target_id: v.target_id.toLowerCase(), input: { reason: normalizedReason(v.input.reason) } };
  return { ...v, target_id: v.target_id.toLowerCase(), input: { ...v.input,
    approval_decision_id: v.input.approval_decision_id.toLowerCase(), reason: normalizedReason(v.input.reason) } };
}
export function isPreparedOperation(v: unknown): v is PreparedOperation {
  if (!shape(v, { schema_version: literal('1.0.0'), operation_id: operationUUID, operation: text,
    target_id: x => x === null || uuid(x), input: x => object(v) && input(x, v.operation, true),
    actor: x => shape(x, { issuer: text, subject: text }), risk_summary: literal(actionRisk),
    prepared_at: epoch, expires_at: epoch, state: x => typeof x === 'string'
      && ['PREPARED', 'IN_FLIGHT', 'UNCONFIRMED', 'CONFIRMED', 'EXPIRED'].includes(x),
    attempts: integer, result: x => x === null || shape(x, { result_id: uuid, scan_id: y => y === null || uuid(y) }) })) return false;
  if ((v.operation === 'PROPOSE' ? v.target_id !== null : !uuid(v.target_id))
    || Number(v.expires_at) < Number(v.prepared_at) || Number(v.expires_at) > Number(v.prepared_at) + 300) return false;
  if (v.state === 'PREPARED' || v.state === 'EXPIRED') return v.attempts === 0 && v.result === null;
  if (Number(v.attempts) < 1) return false;
  return v.state === 'CONFIRMED' ? object(v.result)
    && (v.operation === 'REQUEST_VERIFICATION' ? uuid(v.result.scan_id) : v.result.scan_id === null) : v.result === null;
}
const actorBound = (v: PreparedOperation, identity: Identity) => v.actor.issuer === identity.issuer && v.actor.subject === identity.subject;
export function samePrepared(a: PreparedOperation, b: PreparedOperation): boolean {
  return a.operation_id === b.operation_id && a.operation === b.operation && a.target_id === b.target_id
    && sameImmutable(a.input, b.input) && sameImmutable(a.actor, b.actor)
    && a.prepared_at === b.prepared_at && a.expires_at === b.expires_at;
}
export function sameIntentTarget(a: PreparedOperation, b: Preparation): boolean {
  return a.operation === b.operation && (a.operation === 'PROPOSE' && b.operation === 'PROPOSE'
    ? a.input.finding_id === b.input.finding_id && a.input.occurrence_id === b.input.occurrence_id
    : b.operation !== 'PROPOSE' && a.target_id === b.target_id);
}

export class OperationError extends APIError {
  constructor(public stage: 'PREPARE' | 'SUBMIT' | 'RECOVER', status: number) {
    super(status);
    if (status !== 401) this.message = stage === 'PREPARE'
      ? 'Preparation could not be confirmed. Refresh same-session operations before preparing again.'
      : stage === 'RECOVER' ? 'Operation recovery is unavailable. Review immutable history; an empty or lost session does not prove no effect.'
      : 'Submission outcome is unconfirmed. Refresh operations or explicitly retry the original operation. Do not replace its key or assume cancellation.';
  }
}
const root = '/dashboard/api/remediation-operations';
async function decode(response: Response, stage: OperationError['stage']): Promise<unknown> {
  if (response.status !== (stage === 'PREPARE' ? 201 : 200)) throw new OperationError(stage, response.status);
  try { return await response.json(); } catch { throw new OperationError(stage, 0); }
}
export async function recoverOperations(identity: Identity, signal?: AbortSignal): Promise<PreparedOperation[]> {
  try {
    const value = await decode(await fetch(root, { signal, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      headers: { 'X-Dashboard-Context': identity.session_context } }), 'RECOVER');
    if (!shape(value, { schema_version: literal('1.0.0'), items: Array.isArray }) || !Array.isArray(value.items)
      || value.items.length > 16 || !value.items.every(isPreparedOperation)
      || new Set(value.items.map(v => v.operation_id)).size !== value.items.length
      || !value.items.every(v => actorBound(v, identity))) throw new OperationError('RECOVER', 0);
    return value.items;
  } catch (error) { throw error instanceof OperationError ? error : new OperationError('RECOVER', 0); }
}
export async function prepareOperation(session: RemediationSession, request: Preparation, signal?: AbortSignal): Promise<PreparedOperation> {
  try {
    if (!remediationEnabled(session) || !canPrepare(session, request.operation)) throw new OperationError('PREPARE', 403);
    const normalized = normalizedPreparation(request), body = JSON.stringify(normalized);
    if (new TextEncoder().encode(body).length > 12 * 1024) throw new OperationError('PREPARE', 413);
    const value = await decode(await fetch(root, { method: 'POST', body, signal, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf_token, 'X-Dashboard-Context': session.session_context } }), 'PREPARE');
    const expectedInput = normalized.operation === 'PROPOSE'
      ? { ...normalized.input, action_id: actionId, action_version: '1.0.0' } : normalized.input;
    if (!isPreparedOperation(value) || !actorBound(value, session) || value.operation !== normalized.operation
      || value.state !== 'PREPARED' || !sameImmutable(value.input, expectedInput)
      || value.target_id !== (normalized.operation === 'PROPOSE' ? null : normalized.target_id)) throw new OperationError('PREPARE', 0);
    return value;
  } catch (error) { throw error instanceof OperationError ? error : new OperationError('PREPARE', 0); }
}
export async function submitOperation(session: RemediationSession, operation: PreparedOperation, signal?: AbortSignal): Promise<PreparedOperation> {
  try {
    if (!remediationEnabled(session) || !isPreparedOperation(operation) || !actorBound(operation, session)
      || !canPrepare(session, operation.operation) || !['PREPARED', 'UNCONFIRMED'].includes(operation.state)) throw new OperationError('SUBMIT', 403);
    const value = await decode(await fetch(`${root}/${operation.operation_id}/submit`, { method: 'POST', body: '{}', signal,
      credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: { 'Content-Type': 'application/json',
        'X-CSRF-Token': session.csrf_token, 'X-Dashboard-Context': session.session_context } }), 'SUBMIT');
    if (!isPreparedOperation(value) || !samePrepared(value, operation) || Number(value.attempts) < operation.attempts
      || value.state === 'PREPARED') throw new OperationError('SUBMIT', 0);
    return value;
  } catch (error) { throw error instanceof OperationError ? error : new OperationError('SUBMIT', 0); }
}
