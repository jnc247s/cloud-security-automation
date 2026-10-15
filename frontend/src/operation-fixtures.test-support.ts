import { actionId, actionRisk } from './remediation-api';
import { isPreparedOperation, type OperationKind, type Preparation, type PreparedOperation, type RemediationSession } from './remediation-operations';

export const operationId = '11111111-1111-4111-8111-111111111111';
export const targetId = '22222222-2222-2222-2222-222222222222';
export const occurrenceId = '33333333-3333-3333-3333-333333333333';
export const approvalId = '44444444-4444-4444-4444-444444444444';
export const resultId = '55555555-5555-5555-5555-555555555555';
export const operationSession = (): RemediationSession => ({ authenticated: true,
  subject: 'operator', issuer: 'https://identity.example.test', roles: ['ADMIN'],
  csrf_token: 'C'.repeat(43), session_context: 'A'.repeat(43), features: { remediation: true },
  expires_at: Date.now() / 1000 + 3600, idle_expires_at: Date.now() / 1000 + 900 });
export function operationRequest(kind: OperationKind = 'PROPOSE'): Preparation {
  const base = { schema_version: '1.0.0' as const };
  const reason = 'Reviewed exact target, future volumes and KMS compatibility.';
  if (kind === 'PROPOSE') return { ...base, operation: kind, input: { finding_id: targetId, occurrence_id: occurrenceId, reason } };
  if (kind === 'DECIDE') return { ...base, operation: kind, target_id: targetId, input: { proposal_sha256: 'a'.repeat(64), decision: 'APPROVE', reason } };
  if (kind === 'REQUEST_VERIFICATION') return { ...base, operation: kind, target_id: targetId, input: { reason } };
  return { ...base, operation: kind, target_id: targetId, input: { proposal_sha256: 'a'.repeat(64), approval_decision_id: approvalId, reason } };
}
export function preparedOperation(kind: OperationKind = 'PROPOSE'): PreparedOperation {
  const request = operationRequest(kind), session = operationSession();
  const preparedAt = Date.now() / 1000;
  const value = { schema_version: '1.0.0', operation_id: operationId, operation: kind,
    target_id: request.operation === 'PROPOSE' ? null : request.target_id,
    input: request.operation === 'PROPOSE' ? { ...request.input, action_id: actionId, action_version: '1.0.0' } : request.input,
    actor: { issuer: session.issuer, subject: session.subject }, risk_summary: actionRisk,
    prepared_at: preparedAt, expires_at: preparedAt + 300, state: 'PREPARED', attempts: 0, result: null };
  if (!isPreparedOperation(value)) throw new Error('Invalid coordination fixture');
  return value;
}
