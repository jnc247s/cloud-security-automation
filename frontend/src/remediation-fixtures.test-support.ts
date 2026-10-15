import { assessment, scope, id, digest, at } from './investigation-fixtures.test-support';
import { actionId, actionRisk, type Actor, type Execution, type Proposal, type RemediationAnchor, type Verification } from './remediation-api';
export { id, digest, at };
const actor = (subject: string, role: string, capability: Actor['capability']): Actor => ({ issuer: 'https://identity.example.test', subject, roles: [role], capability });
export const anchor: RemediationAnchor = { assessment, scope: { ...scope, controls: [{ ...scope.controls[0], control_key: 'EC2-004' }] } };
export const proposal: Proposal = {
  content: { schema_version: '1.0.0', proposal_id: id(101), finding_id: id(13), resource_id: id(3), control_id: id(5),
    control_key: 'EC2-004', account_id: '123456789012', region: 'us-east-1', action_id: actionId, action_version: '1.0.0',
    risk_summary: actionRisk, expected_encryption_by_default: false, desired_encryption_by_default: true,
    governance_sha256: digest, proposer: actor('proposer', 'ANALYST', 'PROPOSE'), reason: 'Reviewed compatibility <img src=x onerror=alert(1)>',
    created_at: at, expires_at: '2026-10-05T12:00:00Z', baseline: { occurrence_id: id(14), assessment_id: id(2), scan_id: id(1),
      snapshot_id: id(4), state_sha256: digest, observed_at: at, profile_id: 'test', profile_version: '1.0.0', profile_sha256: digest,
      catalog_id: 'catalog', catalog_version: '1.0.0', catalog_sha256: digest, control_version_id: id(6), control_definition_sha256: digest,
      inventory_sha256: digest, assessment_evidence: [{ evidence_id: id(7), payload_sha256: digest }],
      encryption_source: { source_outcome_id: id(10), artifact_id: id(11), evidence_reference: 'normalized://ec2', evidence_sha256: digest },
      kms_source: { source_outcome_id: id(20), artifact_id: id(21), evidence_reference: 'normalized://kms', evidence_sha256: digest },
      default_kms_key_id: null, default_kms_key_expected_absence: true } },
  proposal_sha256: digest, approval_status: 'APPROVED', blocking_reasons: ['EXPIRED'], validity_checked_at: '2026-10-06T12:00:00Z',
  decisions: [{ decision_id: id(102), proposal_id: id(101), kind: 'APPROVE', proposal_sha256: digest, approval_decision_id: null,
    actor: actor('approver', 'APPROVER', 'APPROVE'), created_at: '2026-10-04T12:00:01Z', reason: 'Reviewed immutable baseline.' }]
};
const workerActor = { service_id: 'remediation-worker' as const, expected_role_arn: 'arn:aws:iam::123456789012:role/remediation-writer' };
export const execution: Execution = {
  content: { schema_version: '1.0.0', execution_id: id(103), proposal: proposal.content, proposal_sha256: digest,
    approval: proposal.decisions[0], approval_sha256: digest, requested_by: actor('executor', 'ADMIN', 'EXECUTE'),
    idempotency_key: id(104), reason: 'Request admission, not worker launch.', created_at: '2026-10-04T12:00:02Z', expires_at: '2026-10-04T12:05:02Z' },
  execution_sha256: digest, phase: 'ACKNOWLEDGED', blocking_reasons: ['EXECUTION_EXPIRED'], validity_checked_at: '2026-10-06T12:00:00Z',
  reservation_held: false, events: [
    { content: { schema_version: '1.0.0', event_id: id(105), execution_id: id(103), execution_sha256: digest, sequence: 1,
      kind: 'REQUESTED', phase: 'QUEUED', previous_event_sha256: null, actor: actor('executor', 'ADMIN', 'EXECUTE'),
      created_at: '2026-10-04T12:00:02Z', blocking_reasons: [] }, event_sha256: digest, audit_event_id: id(205) },
    { content: { schema_version: '2.0.0', event_id: id(106), execution_id: id(103), execution_sha256: digest, sequence: 2,
      kind: 'CLAIMED', phase: 'CLAIMED', previous_event_sha256: digest, actor: workerActor, created_at: '2026-10-04T12:00:03Z',
      blocking_reasons: [], observation: null, observed_at: null, request_id: null, polls: 0 }, event_sha256: digest, audit_event_id: id(206) },
    { content: { schema_version: '2.0.0', event_id: id(107), execution_id: id(103), execution_sha256: digest, sequence: 3,
      kind: 'WRITE_INTENT', phase: 'WRITE_INTENT', previous_event_sha256: digest, actor: workerActor, created_at: '2026-10-04T12:00:04Z',
      blocking_reasons: [], observation: { encryption_by_default: false, default_kms_key_id: null, default_kms_key_expected_absence: true },
      observed_at: '2026-10-04T12:00:04Z', request_id: null, polls: 0 }, event_sha256: digest, audit_event_id: id(207) },
    { content: { schema_version: '2.0.0', event_id: id(108), execution_id: id(103), execution_sha256: digest, sequence: 4,
      kind: 'ACKNOWLEDGED', phase: 'ACKNOWLEDGED', previous_event_sha256: digest, actor: workerActor, created_at: '2026-10-04T12:00:05Z',
      blocking_reasons: [], observation: null, observed_at: null, request_id: 'offline-receipt', polls: 0 }, event_sha256: digest, audit_event_id: id(208) }
  ]
};
export const verification: Verification = {
  content: { schema_version: '1.0.0', verification_id: id(109), execution_id: id(103), execution_sha256: digest,
    acknowledgment_event_id: id(108), acknowledgment_sha256: digest, acknowledged_at: '2026-10-04T12:00:05Z', baseline_scan_id: id(1),
    scan_id: id(110), attempt: 1, account_id: '123456789012', region: 'us-east-1', requested_services: ['ec2'],
    requested_collectors: ['ec2', 'ebs'], resource_types: [], profile_id: 'test', profile_version: '1.0.0', profile_sha256: digest,
    catalog_id: 'catalog', catalog_version: '1.0.0', catalog_sha256: digest, requested_by: actor('executor', 'ADMIN', 'EXECUTE'),
    idempotency_key: id(111), reason: 'Read-only exact-policy observation.', created_at: '2026-10-04T12:00:06Z' },
  verification_sha256: digest, request_audit_event_id: id(112), receipt_sha256: digest, receipt_audit_event_id: id(113),
  receipt: { schema_version: '1.0.0', verification_id: id(109), verification_sha256: digest, scan_id: id(110), scan_status: 'COMPLETED',
    result_sha256: digest, inventory_sha256: digest, outcome: 'VERIFIED', reason: 'POSTCONDITION_PASS', created_at: '2026-10-04T12:00:08Z',
    evidence: { resource_id: id(3), snapshot_id: id(114), state_sha256: digest, assessment_id: id(115), control_version_id: id(6),
      control_definition_sha256: digest, observed_at: '2026-10-04T12:00:07Z', technical_result: 'PASS',
      assessment_evidence: proposal.content.baseline.assessment_evidence, encryption_source: proposal.content.baseline.encryption_source,
      kms_source: proposal.content.baseline.kms_source } }
};
export const page = <T,>(items: T[], offset = 0, total = items.length) => ({ items, total, offset, limit: 25 });
