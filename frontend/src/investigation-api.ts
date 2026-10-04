// Runtime guards and exact identity bindings, not authorization or rule evaluation.
import { isPosture, isUUID, type Posture } from './api';

export const object = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const string = (v: unknown): v is string => typeof v === 'string';
const uuid = (v: unknown): v is string => string(v) && isUUID(v);
const nullable = (v: unknown) => v === null || string(v);
const sha = (v: unknown): v is string => string(v) && /^[a-f0-9]{64}$/i.test(v);
const integer = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const ids = (v: unknown): v is string[] => Array.isArray(v) && v.every(uuid);
const fields = (v: Record<string, unknown>, names: string[]) => names.every(name => string(v[name]));
export const results = ['PASS', 'FAIL', 'INSUFFICIENT_EVIDENCE', 'NOT_APPLICABLE'] as const;
export const findingStates = ['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'] as const;
export const sourceStates = ['PRESENT', 'EXPECTED_ABSENCE', 'UNAVAILABLE', 'MALFORMED', 'CONFLICT', 'RESOURCE_DISAPPEARED'] as const;
export const resolutions = ['RESOLVED', 'TARGET_NOT_COLLECTED', 'TARGET_OUTSIDE_SCAN_SCOPE', 'TARGET_ACCESS_DENIED', 'TARGET_EVIDENCE_INCOMPLETE', 'TARGET_IDENTITY_INCOMPLETE'] as const;
const relationshipTypes = ['uses_volume', 'attached_to_security_group', 'in_subnet', 'in_vpc', 'contains_subnet', 'has_flow_log', 'member_of_group', 'has_access_key', 'has_mfa_device', 'attached_managed_policy', 'attached_inline_policy', 'permissions_boundary', 'selects_default_version', 'references_resource', 'encrypted_with', 'delivers_to_bucket'];
export type Result = typeof results[number];
export interface Page<T> { items: T[]; total: number; limit: number; offset: number }
export function pageOf<T>(guard: (v: unknown) => v is T) {
  return (v: unknown): v is Page<T> => object(v) && Array.isArray(v.items) && integer(v.limit)
    && v.limit >= 1 && v.limit <= 100 && v.items.length <= v.limit && v.items.every(guard)
    && integer(v.total) && integer(v.offset);
}
export type Scope = Posture & { assessment_profile_version_id: string; catalog: {
  catalog_id: string; catalog_key: string; version: string; content_checksum: string };
  controls: { control_id: string; control_version_id: string; control_key: string; definition_checksum: string }[] };
export function isScope(v: unknown): v is Scope {
  return isPosture(v) && object(v) && uuid(v.assessment_profile_version_id) && object(v.catalog)
    && uuid(v.catalog.catalog_id) && string(v.catalog.catalog_key) && string(v.catalog.version)
    && sha(v.catalog.content_checksum) && v.catalog.catalog_key === v.scan.control_catalog_id
    && v.catalog.version === v.scan.control_catalog_version && Array.isArray(v.controls)
    && v.controls.every(c => object(c) && uuid(c.control_id) && uuid(c.control_version_id)
      && string(c.control_key) && sha(c.definition_checksum))
    && new Set(v.controls.map(c => c.control_version_id)).size === v.controls.length;
}
export interface Assessment { assessment_id: string; scan_id: string; resource_snapshot_id: string;
  resource_id: string; control_version_id: string; control_id: string; assessment_profile_version_id: string;
  assessment_result: Result; reason: string; missing_evidence: unknown[]; evaluated_at: string; evidence_count: number }
export interface Evidence { evidence_id: string; assessment_id: string; scan_id: string;
  resource_snapshot_id: string; control_version_id: string; control_id: string; collector: string;
  source: string; source_api: string; collected_at: string; schema_name: string; schema_version: string;
  evidence_key: string; payload: Record<string, unknown>; payload_sha256: string }
export interface AssessmentDetail extends Assessment { evidence: Evidence[]; framework_mappings: unknown[];
  finding_id: string | null; finding_occurrence_id: string | null }
export function isAssessment(v: unknown): v is Assessment {
  return object(v) && ['assessment_id', 'scan_id', 'resource_snapshot_id', 'resource_id', 'control_version_id', 'control_id', 'assessment_profile_version_id'].every(k => uuid(v[k]))
    && string(v.assessment_result) && (results as readonly string[]).includes(v.assessment_result)
    && fields(v, ['reason', 'evaluated_at']) && Array.isArray(v.missing_evidence) && integer(v.evidence_count);
}
function isEvidence(v: unknown): v is Evidence {
  return object(v) && ['evidence_id', 'assessment_id', 'scan_id', 'resource_snapshot_id', 'control_version_id', 'control_id'].every(k => uuid(v[k]))
    && fields(v, ['collector', 'source', 'source_api', 'collected_at', 'schema_name', 'schema_version', 'evidence_key'])
    && object(v.payload) && sha(v.payload_sha256);
}
export function isAssessmentDetail(v: unknown): v is AssessmentDetail {
  return isAssessment(v) && object(v) && Array.isArray(v.evidence) && v.evidence.every(isEvidence)
    && v.evidence.length === v.evidence_count && v.evidence.every(e => e.assessment_id === v.assessment_id
      && e.scan_id === v.scan_id && e.resource_snapshot_id === v.resource_snapshot_id
      && e.control_version_id === v.control_version_id && e.control_id === v.control_id)
    && Array.isArray(v.framework_mappings) && (v.finding_id === null || uuid(v.finding_id))
    && (v.finding_occurrence_id === null || uuid(v.finding_occurrence_id))
    && ((v.finding_id === null) === (v.finding_occurrence_id === null));
}
export function assessmentBound(v: Assessment, scope: Scope) {
  return v.scan_id === scope.scan.scan_id && v.assessment_profile_version_id === scope.assessment_profile_version_id
    && scope.controls.some(c => c.control_id === v.control_id && c.control_version_id === v.control_version_id);
}
export interface Snapshot { snapshot_id: string; resource_id: string; scan_id: string; scope: 'global' | 'regional';
  region: string | null; arn: string | null; name: string | null; tags: Record<string, unknown>;
  normalized_configuration: Record<string, unknown>; state_sha256: string; observed_at: string }
export function isSnapshot(v: unknown): v is Snapshot {
  return object(v) && ['snapshot_id', 'resource_id', 'scan_id'].every(k => uuid(v[k]))
    && ((v.scope === 'global' && v.region === null) || (v.scope === 'regional' && string(v.region) && v.region.length > 0))
    && nullable(v.arn) && nullable(v.name) && object(v.tags) && object(v.normalized_configuration)
    && sha(v.state_sha256) && string(v.observed_at);
}
export interface Resource { resource_id: string; provider: string; aws_account_id: string;
  aws_resource_id: string; arn: string | null; service: string; resource_type: string; scope: string; region: string }
export function isResource(v: unknown): v is Resource {
  return object(v) && uuid(v.resource_id) && v.provider === 'aws' && fields(v, ['aws_account_id', 'aws_resource_id', 'service', 'resource_type', 'region'])
    && string(v.scope) && ['global', 'regional'].includes(v.scope) && nullable(v.arn);
}
export interface Version extends Record<string, unknown> { control_version_id: string; catalog_id: string;
  catalog_key: string; catalog_version: string; title: string; severity: string; definition_checksum: string }
export interface Control { control_id: string; control_key: string; versions: Version[] }
export function isControl(v: unknown): v is Control {
  return object(v) && uuid(v.control_id) && string(v.control_key) && Array.isArray(v.versions)
    && v.versions.every(x => object(x) && uuid(x.control_version_id) && uuid(x.catalog_id)
      && fields(x, ['catalog_key', 'catalog_version', 'title', 'severity']) && sha(x.definition_checksum));
}
export interface Finding { finding_id: string; fingerprint: string; aws_account_id: string; resource_id: string;
  control_id: string; region: string | null; status: string; first_detected_at: string; last_detected_at: string;
  resolved_at: string | null; occurrence_count: number; active_exception_ids: string[] }
export function isFinding(v: unknown): v is Finding {
  return object(v) && ['finding_id', 'resource_id', 'control_id'].every(k => uuid(v[k]))
    && fields(v, ['fingerprint', 'aws_account_id', 'first_detected_at', 'last_detected_at'])
    && nullable(v.region) && nullable(v.resolved_at) && findingStates.includes(v.status as typeof findingStates[number])
    && integer(v.occurrence_count) && ids(v.active_exception_ids);
}
export interface Exception { exception_id: string; finding_id: string; resource_id: string; control_id: string;
  reason: string; approved_by: string; created_at: string; expires_at: string; status: string; revoked_at: string | null }
export function isException(v: unknown): v is Exception {
  return object(v) && ['exception_id', 'finding_id', 'resource_id', 'control_id'].every(k => uuid(v[k]))
    && fields(v, ['reason', 'approved_by', 'created_at', 'expires_at', 'status']) && ['ACTIVE', 'EXPIRED', 'REVOKED'].includes(v.status as string) && nullable(v.revoked_at);
}
export interface FindingDetail extends Finding { occurrences: Record<string, unknown>[]; exceptions: Exception[] }
export function isFindingDetail(v: unknown): v is FindingDetail {
  return isFinding(v) && object(v) && Array.isArray(v.occurrences)
    && v.occurrences.every(x => object(x) && x.finding_id === v.finding_id && x.resource_id === v.resource_id
      && x.control_id === v.control_id && ['occurrence_id', 'assessment_id', 'scan_id', 'resource_snapshot_id', 'control_version_id'].every(k => uuid(x[k]))
      && results.includes(x.assessment_result as Result) && string(x.detected_at))
    && Array.isArray(v.exceptions) && v.exceptions.every(x => isException(x) && x.finding_id === v.finding_id
      && x.resource_id === v.resource_id && x.control_id === v.control_id);
}
export interface Endpoint { identity_state: 'stable' | 'unresolved'; provider: 'aws'; aws_account_id: string | null;
  service: string; resource_type: string; aws_resource_id: string; scope: 'global' | 'regional' | null;
  region: string | null; stable_resource_id: string | null; resource_snapshot_id: string | null; reference_id?: string }
export function sameEndpoint(a: Endpoint, b: Endpoint) {
  return (['identity_state', 'provider', 'aws_account_id', 'service', 'resource_type', 'aws_resource_id',
    'scope', 'region', 'stable_resource_id', 'resource_snapshot_id', 'reference_id'] as const).every(k => a[k] === b[k]);
}
export function isEndpoint(v: unknown): v is Endpoint {
  if (!object(v) || v.provider !== 'aws' || !fields(v, ['service', 'resource_type', 'aws_resource_id']) || !nullable(v.aws_account_id) || !nullable(v.region)) return false;
  if (v.identity_state === 'unresolved') return uuid(v.reference_id) && v.stable_resource_id === null
    && v.resource_snapshot_id === null && [null, 'global', 'regional'].includes(v.scope as null | string)
    && (v.scope !== 'global' || v.region === null);
  return v.identity_state === 'stable' && uuid(v.stable_resource_id) && (v.resource_snapshot_id === null || uuid(v.resource_snapshot_id))
    && string(v.aws_account_id) && ((v.scope === 'global' && v.region === null) || (v.scope === 'regional' && string(v.region) && v.region.length > 0));
}
export interface Outcome { source_outcome_id: string; scan_id: string; collection_account_id: string; phase: string;
  subject: Record<string, unknown>; evidence_kind: string; state: string; failure_category: string | null;
  collector: string; collector_version: string; source: string; source_api: string; collected_at: string;
  artifact_id: string; evidence_reference: string; evidence_sha256: string; schema_version: string }
export function isOutcome(v: unknown): v is Outcome {
  if (!object(v) || !['source_outcome_id', 'scan_id', 'artifact_id'].every(k => uuid(v[k]))
    || !fields(v, ['collection_account_id', 'evidence_kind', 'collector', 'collector_version', 'source', 'source_api', 'collected_at', 'evidence_reference'])
    || !string(v.phase) || !['DISCOVERY', 'ENRICHMENT'].includes(v.phase) || !sourceStates.includes(v.state as typeof sourceStates[number])
    || !nullable(v.failure_category) || !sha(v.evidence_sha256) || v.schema_version !== '1.0.0' || !object(v.subject)) return false;
  const subject = v.subject;
  return subject.subject_kind === 'account' ? subject.provider === 'aws' && string(subject.aws_account_id)
    && ((subject.scope === 'global' && subject.region === null) || (subject.scope === 'regional' && string(subject.region)))
    : subject.subject_kind === 'resource' && isEndpoint({ ...subject, identity_state: 'stable' }) && uuid(subject.resource_snapshot_id);
}
export interface OutcomeDetail extends Outcome { artifact: { artifact_id: string; scan_id: string;
  collection_account_id: string; evidence_reference: string; evidence_sha256: string; evidence_schema: string;
  evidence_schema_version: string; collected_at: string; normalized_payload: Record<string, unknown>; schema_version: string } }
export function sameOutcome(a: Outcome, b: Outcome) {
  return (['source_outcome_id', 'scan_id', 'collection_account_id', 'phase', 'evidence_kind', 'state',
    'failure_category', 'collector', 'collector_version', 'source', 'source_api', 'collected_at',
    'artifact_id', 'evidence_reference', 'evidence_sha256', 'schema_version'] as const).every(k => a[k] === b[k])
    && ['subject_kind', 'provider', 'aws_account_id', 'service', 'resource_type', 'aws_resource_id',
      'scope', 'region', 'stable_resource_id', 'resource_snapshot_id'].every(k => a.subject[k] === b.subject[k]);
}
export function isOutcomeDetail(v: unknown): v is OutcomeDetail {
  if (!isOutcome(v) || !object(v) || !object(v.artifact)) return false;
  const a = v.artifact;
  return a.artifact_id === v.artifact_id && a.scan_id === v.scan_id && a.collection_account_id === v.collection_account_id
    && a.evidence_reference === v.evidence_reference && a.evidence_sha256 === v.evidence_sha256
    && a.collected_at === v.collected_at && a.schema_version === '1.0.0'
    && fields(a, ['evidence_schema', 'evidence_schema_version']) && object(a.normalized_payload);
}
export interface Relationship { observation_id: string; relationship_id: string; scan_id: string; collection_account_id: string;
  relationship_type: string; source: Endpoint; target: Endpoint; resolution: string;
  provenance: { collector: string; collector_version: string; source: string; source_api: string; evidence_reference: string; collected_at: string };
  source_outcome_id: string; schema_version: string }
export function isRelationship(v: unknown): v is Relationship {
  return object(v) && ['observation_id', 'relationship_id', 'scan_id', 'source_outcome_id'].every(k => uuid(v[k]))
    && string(v.collection_account_id) && string(v.relationship_type) && relationshipTypes.includes(v.relationship_type)
    && isEndpoint(v.source) && v.source.identity_state === 'stable' && uuid(v.source.resource_snapshot_id)
    && isEndpoint(v.target) && resolutions.includes(v.resolution as typeof resolutions[number])
    && (v.resolution !== 'RESOLVED' || (v.target.identity_state === 'stable' && uuid(v.target.resource_snapshot_id)))
    && (v.resolution === 'RESOLVED' || v.target.resource_snapshot_id === null)
    && object(v.provenance) && fields(v.provenance, ['collector', 'collector_version', 'source', 'source_api', 'evidence_reference', 'collected_at'])
    && v.schema_version === '1.0.0';
}
export interface Citation { source_outcome_id: string; artifact_id: string; evidence_sha256: string }
export function proofLinks(evidence: Evidence, controlKey: string): { sources: Citation[]; edges: string[] } | null {
  const p = evidence.payload.source_proof;
  if (evidence.schema_name !== `control.${controlKey.toLowerCase()}.evidence` || evidence.schema_version !== '1.0.0'
    || !object(p) || p.scan_id !== evidence.scan_id || !string(p.schema_version) || !/^1\.(?:[0-9]|10)\.0$/.test(p.schema_version)
    || !Array.isArray(p.sources) || !p.sources.every(x => object(x) && uuid(x.source_outcome_id) && uuid(x.artifact_id) && sha(x.evidence_sha256))
    || !ids(p.relationship_observation_ids)) return null;
  return { sources: p.sources as Citation[], edges: p.relationship_observation_ids };
}
// Explicit offsets only. Never use browser wall time or assume a naive timestamp is local/UTC.
export function instant(value: unknown): bigint | null {
  if (!string(value)) return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!m) return null;
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1] || hour > 23 || minute > 59 || second > 59) return null;
  const milliseconds = Date.parse(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[8]}`);
  return Number.isFinite(milliseconds) ? BigInt(milliseconds) * 1000n + BigInt((m[7] ?? '').padEnd(6, '0')) : null;
}
export function eligibility(v: Exception, reference: string | null): string {
  const at = reference && /(?:Z|\+00:00)$/.test(reference) ? instant(reference) : null;
  const created = instant(v.created_at), expires = instant(v.expires_at);
  if (at === null || created === null || expires === null || expires <= created
    || (v.revoked_at !== null && instant(v.revoked_at) === null)) return 'Eligibility unavailable';
  if (v.revoked_at !== null || v.status === 'REVOKED') return 'Not eligible — revoked';
  if (expires <= at) return 'Expired at server reference time';
  if (created > at) return 'Not yet effective at server reference time';
  return v.status === 'ACTIVE' ? 'Eligible at server reference time' : 'Not eligible at server reference time';
}
export const assessmentPage = pageOf(isAssessment), snapshotPage = pageOf(isSnapshot), findingPage = pageOf(isFinding), exceptionPage = pageOf(isException), outcomePage = pageOf(isOutcome), relationshipPage = pageOf(isRelationship);
