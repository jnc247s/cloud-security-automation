// Display contracts only. Real API provenance/authorization remains authoritative.
import { isUUID } from './api';
import { instant, object, pageOf, type AssessmentDetail, type Scope } from './investigation-api';

export const actionId = 'aws.ec2.enable-ebs-encryption-by-default';
export const actionRisk = 'Enables encryption for future EBS volumes and snapshot copies in this account/Region. '
  + 'Existing volumes are unchanged. Review workload and KMS compatibility; '
  + 'this action does not change the default KMS key or support automatic rollback.';
const proposalBlockers = ['EXPIRED', 'STALE_TARGET', 'STALE_GOVERNANCE', 'INELIGIBLE_FINDING', 'ACTIVE_EXCEPTION', 'INVALID_PROVENANCE'];
const executionBlockers = [...proposalBlockers, 'EXECUTION_EXPIRED', 'APPROVAL_REVOKED'];
const workerBlockers = [...executionBlockers, 'PRECONDITION_CHANGED', 'READ_UNAVAILABLE', 'WRITER_SCOPE_MISMATCH',
  'READ_BUDGET_EXHAUSTED', 'WRITE_UNCERTAIN', 'LATE_DISPATCH', 'RECOVERY_UNCERTAIN'];
const phases = ['QUEUED', 'EXPIRED', 'BLOCKED', 'CLAIMED', 'WRITE_INTENT', 'NO_WRITE', 'ACKNOWLEDGED', 'QUARANTINED'] as const;
export type Phase = typeof phases[number];
export interface Actor { issuer: string; subject: string; roles: string[]; capability: 'READ' | 'PROPOSE' | 'APPROVE' | 'EXECUTE' }
interface Source { source_outcome_id: string; artifact_id: string; evidence_reference: string; evidence_sha256: string }
interface EvidenceBinding { evidence_id: string; payload_sha256: string }
export interface Baseline {
  occurrence_id: string; assessment_id: string; scan_id: string; snapshot_id: string; state_sha256: string;
  observed_at: string; profile_id: string; profile_version: string; profile_sha256: string;
  catalog_id: string; catalog_version: string; catalog_sha256: string; control_version_id: string;
  control_definition_sha256: string; inventory_sha256: string; assessment_evidence: EvidenceBinding[];
  encryption_source: Source; kms_source: Source; default_kms_key_id: string | null; default_kms_key_expected_absence: boolean;
}
export interface ProposalContent {
  schema_version: '1.0.0'; proposal_id: string; finding_id: string; resource_id: string; control_id: string;
  control_key: 'EC2-004'; account_id: string; region: string; action_id: typeof actionId; action_version: '1.0.0';
  risk_summary: string; expected_encryption_by_default: false; desired_encryption_by_default: true;
  baseline: Baseline; governance_sha256: string; proposer: Actor; reason: string; created_at: string; expires_at: string;
}
export interface Decision { decision_id: string; proposal_id: string; kind: 'APPROVE' | 'REJECT' | 'REVOKE';
  proposal_sha256: string; approval_decision_id: string | null; actor: Actor; created_at: string; reason: string }
export interface Proposal { content: ProposalContent; proposal_sha256: string;
  approval_status: 'PROPOSED' | 'APPROVED' | 'REJECTED' | 'REVOKED'; blocking_reasons: string[];
  validity_checked_at: string; decisions: Decision[] }
export interface ExecutionContent { schema_version: '1.0.0'; execution_id: string; proposal: ProposalContent;
  proposal_sha256: string; approval: Decision; approval_sha256: string; requested_by: Actor;
  idempotency_key: string; reason: string; created_at: string; expires_at: string }
interface Observation { encryption_by_default: boolean; default_kms_key_id: string | null; default_kms_key_expected_absence: boolean }
interface EventCommon { event_id: string; execution_id: string; execution_sha256: string; sequence: number;
  phase: Phase; previous_event_sha256: string | null; created_at: string; blocking_reasons: string[] }
export type EventContent = EventCommon & ({ schema_version: '1.0.0'; kind: 'REQUESTED' | 'EXPIRED' | 'BLOCKED'; actor: Actor }
  | { schema_version: '2.0.0'; kind: 'CLAIMED' | 'WRITE_INTENT' | 'NO_WRITE' | 'ACKNOWLEDGED' | 'QUARANTINED' | 'OBSERVED' | 'OBSERVATION_FAILED';
    actor: { service_id: 'remediation-worker'; expected_role_arn: string }; observation: Observation | null;
    observed_at: string | null; request_id: string | null; polls: number });
export interface ExecutionEvent { content: EventContent; event_sha256: string; audit_event_id: string }
export interface Execution { content: ExecutionContent; execution_sha256: string; phase: Phase;
  blocking_reasons: string[]; validity_checked_at: string; reservation_held: boolean; events: ExecutionEvent[] }
export interface VerificationContent { schema_version: '1.0.0'; verification_id: string; execution_id: string;
  execution_sha256: string; acknowledgment_event_id: string; acknowledgment_sha256: string; acknowledged_at: string;
  baseline_scan_id: string; scan_id: string; attempt: number; account_id: string; region: string;
  requested_services: string[]; requested_collectors: string[]; resource_types: string[];
  profile_id: string; profile_version: string; profile_sha256: string; catalog_id: string; catalog_version: string;
  catalog_sha256: string; requested_by: Actor; idempotency_key: string; reason: string; created_at: string }
interface VerificationEvidence { resource_id: string; snapshot_id: string; state_sha256: string; assessment_id: string;
  control_version_id: string; control_definition_sha256: string; observed_at: string; technical_result: 'PASS' | 'FAIL';
  assessment_evidence: EvidenceBinding[]; encryption_source: Source; kms_source: Source }
export interface VerificationReceipt { schema_version: '1.0.0'; verification_id: string; verification_sha256: string;
  scan_id: string; scan_status: 'COMPLETED' | 'PARTIAL' | 'FAILED'; result_sha256: string; inventory_sha256: string | null;
  outcome: 'VERIFIED' | 'NOT_VERIFIED' | 'INCONCLUSIVE'; reason: string; evidence: VerificationEvidence | null; created_at: string }
export interface Verification { content: VerificationContent; verification_sha256: string; request_audit_event_id: string;
  receipt: VerificationReceipt | null; receipt_sha256: string | null; receipt_audit_event_id: string | null }

type Guard = (v: unknown) => boolean;
const text: Guard = v => typeof v === 'string' && v.trim().length > 0;
const uuid: Guard = v => typeof v === 'string' && isUUID(v);
const sha: Guard = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const time: Guard = v => instant(v) !== null;
const boolean: Guard = v => typeof v === 'boolean';
const reason: Guard = v => typeof v === 'string' && v.trim().length > 0 && [...v].length <= 2000;
const account: Guard = v => typeof v === 'string' && /^[0-9]{12}$/.test(v);
const region: Guard = v => typeof v === 'string' && v.length > 0 && v.length <= 64;
const oneOf = (values: readonly string[]): Guard => v => typeof v === 'string' && values.includes(v);
const literal = (value: unknown): Guard => v => v === value;
const nullable = (guard: Guard): Guard => v => v === null || guard(v);
const array = (guard: Guard): Guard => v => Array.isArray(v) && v.every(guard);
const unique = (values: readonly string[]): Guard => v => Array.isArray(v) && v.every(oneOf(values)) && new Set(v).size === v.length;
function shape(v: unknown, fields: Record<string, Guard>): v is Record<string, unknown> {
  return object(v) && Object.keys(v).length === Object.keys(fields).length
    && Object.entries(fields).every(([key, guard]) => Object.hasOwn(v, key) && guard(v[key]));
}
function actor(v: unknown, capability: Actor['capability']): v is Actor {
  return shape(v, { issuer: text, subject: text, roles: unique(['VIEWER', 'ANALYST', 'APPROVER', 'ADMIN']), capability: literal(capability) })
    && (v.roles as string[]).length > 0;
}
const sameActor = (a: Actor, b: Actor) => a.issuer === b.issuer && a.subject === b.subject;
const source: Guard = v => shape(v, { source_outcome_id: uuid, artifact_id: uuid, evidence_reference: text, evidence_sha256: sha });
const evidenceBindings: Guard = array(v => shape(v, { evidence_id: uuid, payload_sha256: sha }));
const keyContext = (v: Record<string, unknown>) => v.default_kms_key_expected_absence === (v.default_kms_key_id === null);
function baseline(v: unknown): v is Baseline {
  return shape(v, { occurrence_id: uuid, assessment_id: uuid, scan_id: uuid, snapshot_id: uuid, state_sha256: sha,
    observed_at: time, profile_id: text, profile_version: text, profile_sha256: sha, catalog_id: text, catalog_version: text,
    catalog_sha256: sha, control_version_id: uuid, control_definition_sha256: sha, inventory_sha256: sha,
    assessment_evidence: evidenceBindings, encryption_source: source, kms_source: source,
    default_kms_key_id: nullable(text), default_kms_key_expected_absence: boolean }) && keyContext(v);
}
function proposalContent(v: unknown): v is ProposalContent {
  return shape(v, { schema_version: literal('1.0.0'), proposal_id: uuid, finding_id: uuid, resource_id: uuid, control_id: uuid,
    control_key: literal('EC2-004'), account_id: account, region, action_id: literal(actionId), action_version: literal('1.0.0'),
    risk_summary: literal(actionRisk), expected_encryption_by_default: literal(false), desired_encryption_by_default: literal(true),
    baseline, governance_sha256: sha, proposer: v => actor(v, 'PROPOSE'), reason, created_at: time, expires_at: time })
    && instant(v.expires_at)! > instant(v.created_at)!;
}
function decision(v: unknown): v is Decision {
  return shape(v, { decision_id: uuid, proposal_id: uuid, kind: oneOf(['APPROVE', 'REJECT', 'REVOKE']), proposal_sha256: sha,
    approval_decision_id: nullable(uuid), actor: v => actor(v, 'APPROVE'), created_at: time, reason })
    && (v.kind === 'REVOKE') === (v.approval_decision_id !== null);
}
export function isProposal(v: unknown): v is Proposal {
  if (!shape(v, { content: proposalContent, proposal_sha256: sha, approval_status: oneOf(['PROPOSED', 'APPROVED', 'REJECTED', 'REVOKED']),
    blocking_reasons: unique(proposalBlockers), validity_checked_at: time, decisions: array(decision) })) return false;
  const p = v as unknown as Proposal, d = p.decisions;
  if (d.length > 2 || new Set(d.map(x => x.decision_id)).size !== d.length
    || d.some(x => x.proposal_id !== p.content.proposal_id || x.proposal_sha256 !== p.proposal_sha256)) return false;
  if (d.length && (d[0].kind === 'REVOKE' || sameActor(d[0].actor, p.content.proposer))) return false;
  if (d.length === 2 && (d[0].kind !== 'APPROVE' || d[1].kind !== 'REVOKE' || d[1].approval_decision_id !== d[0].decision_id)) return false;
  return p.approval_status === (!d.length ? 'PROPOSED' : d.length === 2 ? 'REVOKED' : d[0].kind === 'APPROVE' ? 'APPROVED' : 'REJECTED');
}
function executionContent(v: unknown): v is ExecutionContent {
  if (!shape(v, { schema_version: literal('1.0.0'), execution_id: uuid, proposal: proposalContent, proposal_sha256: sha,
    approval: decision, approval_sha256: sha, requested_by: v => actor(v, 'EXECUTE'), idempotency_key: uuid,
    reason, created_at: time, expires_at: time })) return false;
  const c = v as unknown as ExecutionContent;
  return c.approval.kind === 'APPROVE' && c.approval.proposal_id === c.proposal.proposal_id
    && c.approval.proposal_sha256 === c.proposal_sha256 && !sameActor(c.approval.actor, c.proposal.proposer)
    && !sameActor(c.requested_by, c.proposal.proposer) && !sameActor(c.requested_by, c.approval.actor)
    && instant(c.expires_at)! > instant(c.created_at)!;
}
function event(v: unknown): v is ExecutionEvent {
  if (!shape(v, { content: object, event_sha256: sha, audit_event_id: uuid })) return false;
  const common = { event_id: uuid, execution_id: uuid, execution_sha256: sha,
    sequence: (v: unknown) => typeof v === 'number' && Number.isSafeInteger(v) && v >= 1,
    phase: oneOf(phases), previous_event_sha256: nullable(sha), created_at: time, blocking_reasons: unique(workerBlockers) };
  const c = v.content as Record<string, unknown>;
  if (c.schema_version === '1.0.0') return shape(c, { ...common, schema_version: literal('1.0.0'),
    kind: oneOf(['REQUESTED', 'EXPIRED', 'BLOCKED']), actor: v => actor(v, 'EXECUTE'), blocking_reasons: unique(executionBlockers) });
  return c.schema_version === '2.0.0' && shape(c, { ...common, schema_version: literal('2.0.0'),
    kind: oneOf(['CLAIMED', 'WRITE_INTENT', 'NO_WRITE', 'ACKNOWLEDGED', 'QUARANTINED', 'OBSERVED', 'OBSERVATION_FAILED']),
    actor: v => shape(v, { service_id: literal('remediation-worker'), expected_role_arn: v => typeof v === 'string'
      && v.length <= 2048 && /^arn:(aws|aws-cn|aws-us-gov):iam::[0-9]{12}:role\/(?:[A-Za-z0-9+=,.@_-]+\/)*[A-Za-z0-9+=,.@_-]{1,64}$/.test(v) }),
    observation: nullable(v => shape(v, { encryption_by_default: boolean, default_kms_key_id: nullable(text), default_kms_key_expected_absence: boolean }) && keyContext(v)),
    observed_at: nullable(time), request_id: nullable(v => typeof v === 'string' && /^[A-Za-z0-9-]{1,128}$/.test(v)),
    polls: v => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= 3 });
}
function workerNext(c: Extract<EventContent, { schema_version: '2.0.0' }>, previous: Phase): Phase {
  return c.kind === 'OBSERVED' || c.kind === 'OBSERVATION_FAILED' || (c.kind === 'ACKNOWLEDGED' && previous === 'QUARANTINED') ? previous : c.kind;
}
export function isExecution(v: unknown): v is Execution {
  if (!shape(v, { content: executionContent, execution_sha256: sha, phase: oneOf(phases), blocking_reasons: unique(workerBlockers),
    validity_checked_at: time, reservation_held: boolean, events: array(event) })) return false;
  const e = v as unknown as Execution;
  if (!e.events.length || new Set(e.events.map(x => x.content.event_id)).size !== e.events.length) return false;
  let phase: Phase = 'QUEUED';
  for (const [index, entry] of e.events.entries()) {
    const c = entry.content;
    if (c.sequence !== index + 1 || c.execution_id !== e.content.execution_id || c.execution_sha256 !== e.execution_sha256
      || c.previous_event_sha256 !== (index === 0 ? null : e.events[index - 1].event_sha256)) return false;
    if (c.schema_version === '1.0.0') {
      if (!sameActor(c.actor, e.content.requested_by)) return false;
      if (index === 0) { if (c.kind !== 'REQUESTED' || c.phase !== 'QUEUED' || c.blocking_reasons.length) return false; }
      else { if (index !== 1 || phase !== 'QUEUED' || !['EXPIRED', 'BLOCKED'].includes(c.kind)
        || c.phase !== c.kind || !c.blocking_reasons.length) return false; phase = c.phase; }
    } else {
      const allowed: Record<string, readonly Phase[]> = { CLAIMED: ['QUEUED', 'CLAIMED'], WRITE_INTENT: ['CLAIMED'],
        NO_WRITE: ['QUEUED', 'CLAIMED'], ACKNOWLEDGED: ['WRITE_INTENT', 'QUARANTINED'], QUARANTINED: ['WRITE_INTENT', 'QUARANTINED'],
        OBSERVED: ['ACKNOWLEDGED', 'QUARANTINED'], OBSERVATION_FAILED: ['ACKNOWLEDGED', 'QUARANTINED'] };
      if (index === 0 || !allowed[c.kind].includes(phase) || c.actor.expected_role_arn.split(':')[4] !== e.content.proposal.account_id) return false;
      const next = workerNext(c, phase);
      if (c.phase !== next || (c.observation === null) !== (c.observed_at === null)
        || (c.request_id !== null) !== (c.kind === 'ACKNOWLEDGED')) return false;
      const observationKind = c.kind === 'OBSERVED' || c.kind === 'OBSERVATION_FAILED';
      if (observationKind ? c.polls < 1 : c.polls !== 0) return false;
      if (['NO_WRITE', 'QUARANTINED', 'OBSERVATION_FAILED'].includes(c.kind) ? !c.blocking_reasons.length : c.blocking_reasons.length > 0) return false;
      if (c.kind === 'WRITE_INTENT') {
        const b = e.content.proposal.baseline;
        if (!c.observation || c.observation.encryption_by_default !== false || c.observation.default_kms_key_id !== b.default_kms_key_id
          || c.observation.default_kms_key_expected_absence !== b.default_kms_key_expected_absence) return false;
      } else if (c.kind === 'OBSERVED' ? c.observation === null : c.kind !== 'NO_WRITE' && c.observation !== null) return false;
      phase = c.phase;
    }
  }
  return phase === e.phase;
}
function verificationContent(v: unknown): v is VerificationContent {
  return shape(v, { schema_version: literal('1.0.0'), verification_id: uuid, execution_id: uuid, execution_sha256: sha,
    acknowledgment_event_id: uuid, acknowledgment_sha256: sha, acknowledged_at: time, baseline_scan_id: uuid, scan_id: uuid,
    attempt: v => typeof v === 'number' && Number.isInteger(v) && v >= 1 && v <= 3, account_id: account, region,
    requested_services: array(text), requested_collectors: array(text), resource_types: array(text), profile_id: text,
    profile_version: text, profile_sha256: sha, catalog_id: text, catalog_version: text, catalog_sha256: sha,
    requested_by: v => actor(v, 'EXECUTE'), idempotency_key: uuid, reason, created_at: time });
}
function receipt(v: unknown): v is VerificationReceipt {
  return shape(v, { schema_version: literal('1.0.0'), verification_id: uuid, verification_sha256: sha, scan_id: uuid,
    scan_status: oneOf(['COMPLETED', 'PARTIAL', 'FAILED']), result_sha256: sha, inventory_sha256: nullable(sha),
    outcome: oneOf(['VERIFIED', 'NOT_VERIFIED', 'INCONCLUSIVE']), reason: oneOf(['POSTCONDITION_PASS', 'POSTCONDITION_FAIL',
      'SCAN_INCOMPLETE', 'PROVENANCE_UNAVAILABLE', 'OBSERVATION_NOT_LATER', 'KMS_CONTEXT_CHANGED']), created_at: time,
    evidence: nullable(v => shape(v, { resource_id: uuid, snapshot_id: uuid, state_sha256: sha, assessment_id: uuid,
      control_version_id: uuid, control_definition_sha256: sha, observed_at: time, technical_result: oneOf(['PASS', 'FAIL']),
      assessment_evidence: evidenceBindings, encryption_source: source, kms_source: source })) });
}
export function isVerification(v: unknown): v is Verification {
  if (!shape(v, { content: verificationContent, verification_sha256: sha, request_audit_event_id: uuid,
    receipt: nullable(receipt), receipt_sha256: nullable(sha), receipt_audit_event_id: nullable(uuid) })) return false;
  const verification = v as unknown as Verification, r = verification.receipt;
  if (!r) return verification.receipt_sha256 === null && verification.receipt_audit_event_id === null;
  if (!verification.receipt_sha256 || !verification.receipt_audit_event_id || r.verification_id !== verification.content.verification_id
    || r.verification_sha256 !== verification.verification_sha256 || r.scan_id !== verification.content.scan_id) return false;
  if (r.outcome === 'VERIFIED' || r.outcome === 'NOT_VERIFIED') return r.scan_status === 'COMPLETED' && r.inventory_sha256 !== null
    && r.evidence !== null && r.evidence.technical_result === (r.outcome === 'VERIFIED' ? 'PASS' : 'FAIL')
    && instant(r.evidence.observed_at)! > instant(verification.content.acknowledged_at)!
    && r.reason === (r.outcome === 'VERIFIED' ? 'POSTCONDITION_PASS' : 'POSTCONDITION_FAIL');
  return !['POSTCONDITION_PASS', 'POSTCONDITION_FAIL'].includes(r.reason);
}
export interface RemediationAnchor { assessment: AssessmentDetail; scope: Scope }
export function sameFinding(p: ProposalContent, anchor: RemediationAnchor): boolean {
  return p.finding_id === anchor.assessment.finding_id && p.resource_id === anchor.assessment.resource_id
    && p.control_id === anchor.assessment.control_id && p.account_id === anchor.scope.scan.aws_account_id
    && anchor.scope.scan.requested_regions.includes(p.region);
}
export function exactOccurrence(p: ProposalContent, anchor: RemediationAnchor): boolean {
  const { assessment: a, scope: s } = anchor, b = p.baseline;
  const control = s.controls.find(c => c.control_version_id === a.control_version_id && c.control_id === a.control_id);
  return sameFinding(p, anchor) && b.occurrence_id === a.finding_occurrence_id && b.assessment_id === a.assessment_id
    && b.scan_id === a.scan_id && b.snapshot_id === a.resource_snapshot_id && b.control_version_id === a.control_version_id
    && b.control_definition_sha256 === control?.definition_checksum && control?.control_key === 'EC2-004'
    && b.profile_id === s.scan.assessment_profile_id && b.profile_version === s.scan.assessment_profile_version
    && b.profile_sha256 === s.scan.assessment_profile_checksum && b.catalog_id === s.scan.control_catalog_id
    && b.catalog_version === s.scan.control_catalog_version && b.catalog_sha256 === s.catalog.content_checksum
    && b.inventory_sha256 === s.scan.inventory_sha256;
}
// Structural comparison is not digest verification. Never infer absent source bytes.
export function sameImmutable(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((v, i) => sameImmutable(v, b[i]));
  return object(a) && object(b) && Object.keys(a).length === Object.keys(b).length
    && Object.keys(a).every(k => Object.hasOwn(b, k) && sameImmutable(a[k], b[k]));
}
export const executionBound = (e: Execution, p: Proposal) => sameImmutable(e.content.proposal, p.content)
  && e.content.proposal_sha256 === p.proposal_sha256
  && p.decisions.some(d => d.kind === 'APPROVE' && sameImmutable(d, e.content.approval));
export function verificationBound(v: Verification, e: Execution): boolean {
  const c = v.content, p = e.content.proposal, b = p.baseline;
  const ack = e.events.find(x => x.content.event_id === c.acknowledgment_event_id);
  return c.execution_id === e.content.execution_id && c.execution_sha256 === e.execution_sha256
    && c.baseline_scan_id === b.scan_id && c.account_id === p.account_id && c.region === p.region
    && c.profile_id === b.profile_id && c.profile_version === b.profile_version && c.profile_sha256 === b.profile_sha256
    && c.catalog_id === b.catalog_id && c.catalog_version === b.catalog_version && c.catalog_sha256 === b.catalog_sha256
    && ack?.event_sha256 === c.acknowledgment_sha256 && ack.content.schema_version === '2.0.0'
    && ack.content.kind === 'ACKNOWLEDGED' && ack.content.phase === 'ACKNOWLEDGED'
    && ack.content.created_at === c.acknowledged_at
    && (!v.receipt?.evidence || (v.receipt.evidence.resource_id === p.resource_id
      && v.receipt.evidence.control_version_id === b.control_version_id
      && v.receipt.evidence.control_definition_sha256 === b.control_definition_sha256));
}
export const proposalPage = pageOf(isProposal), executionPage = pageOf(isExecution), verificationPage = pageOf(isVerification);
