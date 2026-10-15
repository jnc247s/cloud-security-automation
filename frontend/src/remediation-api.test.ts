import { describe, expect, it } from 'vitest';
import { exactOccurrence, executionBound, isExecution, isProposal, isVerification, proposalPage, sameImmutable, verificationBound } from './remediation-api';
import { anchor, digest, execution, id, page, proposal, verification } from './remediation-fixtures.test-support';

function corrupt<T>(input: T, path: string, value: unknown): T {
  const out = structuredClone(input), keys = path.split('.');
  let cursor = out as Record<string, unknown>;
  for (const key of keys.slice(0, -1)) cursor = cursor[key] as Record<string, unknown>;
  cursor[keys[keys.length - 1]] = value;
  return out;
}
describe('closed remediation history display contracts', () => {
  it('accepts separate historical approval, expired authority, normal acknowledgment and later verification', () => {
    expect(isProposal(proposal)).toBe(true); expect(isExecution(execution)).toBe(true); expect(isVerification(verification)).toBe(true);
    expect(exactOccurrence(proposal.content, anchor)).toBe(true);
    expect(executionBound(execution, proposal)).toBe(true); expect(verificationBound(verification, execution)).toBe(true);
  });
  it.each([
    ['content.schema_version', '2.0.0'], ['content.action_version', '2.0.0'], ['content.action_id', 'aws.ec2.disable'],
    ['content.risk_summary', 'Guaranteed encryption'], ['content.expected_encryption_by_default', 0],
    ['content.desired_encryption_by_default', 1], ['content.account_id', 'attacker'], ['content.expires_at', '2026-10-01'],
    ['content.baseline.default_kms_key_expected_absence', false], ['content.baseline.snapshot_id', 'latest'],
    ['content.proposer.capability', 'EXECUTE'], ['content.proposer.roles', ['ROOT']], ['content.extra', true],
    ['proposal_sha256', 'bad'], ['approval_status', 'PROPOSED'], ['blocking_reasons', ['UNKNOWN']],
    ['validity_checked_at', '2026-10-03T12:00:00'], ['decisions.0.actor.subject', 'proposer'],
    ['decisions.0.proposal_id', id(999)], ['decisions.0.approval_decision_id', id(999)]
  ])('rejects unsupported/coercive/misbound proposal %s', (path, value) => expect(isProposal(corrupt(proposal, path, value))).toBe(false));
  it('preserves all four historical decision states and permits proposer revocation without self-approval', () => {
    expect(isProposal({ ...proposal, approval_status: 'PROPOSED', decisions: [] })).toBe(true);
    expect(isProposal({ ...proposal, approval_status: 'REJECTED', decisions: [{ ...proposal.decisions[0], kind: 'REJECT' }] })).toBe(true);
    expect(isProposal({ ...proposal, approval_status: 'REVOKED', decisions: [...proposal.decisions,
      { ...proposal.decisions[0], decision_id: id(999), kind: 'REVOKE', approval_decision_id: proposal.decisions[0].decision_id,
        actor: { ...proposal.decisions[0].actor, subject: proposal.content.proposer.subject } }] })).toBe(true);
  });
  it.each([
    ['content.schema_version', '2.0.0'], ['content.requested_by.subject', 'approver'], ['phase', 'VERIFIED'],
    ['reservation_held', 1], ['events.1.content.schema_version', '3.0.0'], ['events.1.content.sequence', 9],
    ['events.1.content.previous_event_sha256', 'b'.repeat(64)], ['events.2.content.observation.encryption_by_default', true],
    ['events.2.content.observation.default_kms_key_id', 'key-other'], ['events.3.content.request_id', null],
    ['events.3.content.phase', 'QUARANTINED'], ['events.3.content.execution_id', id(999)],
    ['events.3.content.actor.expected_role_arn', 'arn:aws:iam::999999999999:role/writer'],
    ['events.3.content.polls', 1], ['events.3.content.blocking_reasons', ['WRITE_UNCERTAIN']]
  ])('rejects unsupported/coercive/misbound execution %s', (path, value) => expect(isExecution(corrupt(execution, path, value))).toBe(false));
  it('accepts retained v1 admission and no-dispatch terminal events', () => {
    const queued = { ...execution, phase: 'QUEUED', reservation_held: true, events: execution.events.slice(0, 1) };
    expect(isExecution(queued)).toBe(true);
    for (const phase of ['EXPIRED', 'BLOCKED']) expect(isExecution({ ...queued, phase, reservation_held: false,
      events: [...queued.events, { ...queued.events[0], content: { ...queued.events[0].content, event_id: id(999), sequence: 2,
        kind: phase, phase, previous_event_sha256: digest, blocking_reasons: ['EXECUTION_EXPIRED'] } }] })).toBe(true);
  });
  it('keeps quarantine sticky after a late acknowledgment; never binds it as verified', () => {
    const quarantine = structuredClone(execution);
    quarantine.phase = 'QUARANTINED'; quarantine.reservation_held = true;
    const last = quarantine.events[3].content;
    if (last.schema_version !== '2.0.0') throw new Error('Expected worker fixture');
    last.kind = 'QUARANTINED'; last.phase = 'QUARANTINED'; last.request_id = null; last.blocking_reasons = ['WRITE_UNCERTAIN'];
    quarantine.events.push({ ...execution.events[3], content: { ...execution.events[3].content, event_id: id(999), sequence: 5, phase: 'QUARANTINED' } });
    expect(isExecution(quarantine)).toBe(true); expect(verificationBound(verification, quarantine)).toBe(false);
  });
  it.each([
    ['content.schema_version', '9.0.0'], ['content.attempt', 0], ['content.attempt', 4], ['content.attempt', '1'],
    ['receipt.schema_version', '2.0.0'], ['receipt.verification_id', id(999)], ['receipt.scan_id', id(999)],
    ['receipt.evidence.technical_result', 'FAIL'], ['receipt.evidence.observed_at', '2026-10-04T12:00:05Z'],
    ['receipt.scan_status', 'PARTIAL'], ['receipt.reason', 'KMS_CONTEXT_CHANGED'], ['receipt.inventory_sha256', null],
    ['receipt_sha256', null], ['receipt_audit_event_id', null]
  ])('never invents VERIFIED for malformed receipts %s', (path, value) => expect(isVerification(corrupt(verification, path, value))).toBe(false));
  it('preserves pending, NOT_VERIFIED and KMS-drift INCONCLUSIVE independently from PASS', () => {
    expect(isVerification({ ...verification, receipt: null, receipt_sha256: null, receipt_audit_event_id: null })).toBe(true);
    expect(isVerification({ ...verification, receipt: { ...verification.receipt!, outcome: 'NOT_VERIFIED', reason: 'POSTCONDITION_FAIL',
      evidence: { ...verification.receipt!.evidence!, technical_result: 'FAIL' } } })).toBe(true);
    expect(isVerification({ ...verification, receipt: { ...verification.receipt!, outcome: 'INCONCLUSIVE', reason: 'KMS_CONTEXT_CHANGED' } })).toBe(true);
    expect(isVerification({ ...verification, receipt: null })).toBe(false);
  });
  it('rejects crossed occurrence/policy, embedded content and execution/receipt linkage', () => {
    expect(exactOccurrence(corrupt(proposal.content, 'baseline.occurrence_id', id(999)), anchor)).toBe(false);
    expect(exactOccurrence(corrupt(proposal.content, 'baseline.profile_sha256', 'b'.repeat(64)), anchor)).toBe(false);
    expect(executionBound(corrupt(execution, 'content.proposal.account_id', '999999999999'), proposal)).toBe(false);
    expect(verificationBound(corrupt(verification, 'content.execution_sha256', 'b'.repeat(64)), execution)).toBe(false);
    expect(verificationBound(corrupt(verification, 'receipt.evidence.resource_id', id(999)), execution)).toBe(false);
    expect(sameImmutable({ x: 1, y: [2] }, { y: [2], x: 1 })).toBe(true);
    expect(sameImmutable({ x: 1 }, { x: '1' })).toBe(false);
  });
  it('bounds list shapes independently of current validity', () => {
    expect(proposalPage(page([proposal]))).toBe(true);
    expect(proposalPage({ ...page([proposal]), limit: 0 })).toBe(false);
    expect(proposalPage({ ...page([proposal]), items: Array(26).fill(proposal) })).toBe(false);
  });
});
