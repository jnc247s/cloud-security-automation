import type { AssessmentDetail, Control, Exception, Finding, OutcomeDetail, Relationship, Resource, Scope, Snapshot } from './investigation-api';
export const id = (n: number) => `00000000-0000-0000-0000-${String(n).padStart(12, '0')}`;
export const digest = 'a'.repeat(64), at = '2026-10-04T12:00:00.000100Z';
export const scope: Scope = {
  availability: 'AVAILABLE', schema_version: '1.0.0', interpretation: 'TECHNICAL_CONTEXT_ONLY',
  controls: [{ control_id: id(5), control_version_id: id(6), control_key: 'EC2-001', definition_checksum: digest }],
  assessment_profile_version_id: id(9), catalog: { catalog_id: id(8), catalog_key: 'catalog', version: '1.0.0', content_checksum: digest },
  scan: { scan_id: id(1), status: 'COMPLETED', aws_account_id: '123456789012', requested_regions: ['us-east-1'],
    successful_regions: ['us-east-1'], requested_services: ['ec2'], successful_collectors: ['test'],
    started_at: at, completed_at: at, failure: null, scanner_version: 'test', control_catalog_id: 'catalog',
    control_catalog_version: '1.0.0', assessment_profile_id: 'test', assessment_profile_version: '1.0.0',
    assessment_profile_checksum: digest, inventory_sha256: digest, result_checksum: digest, scope: null }
};
export const report = { ...scope, assessment_counts: { pass_count: 0, fail_count: 1, insufficient_evidence_count: 0, not_applicable_count: 0 } };
export const assessment: AssessmentDetail = { assessment_id: id(2), scan_id: id(1), resource_snapshot_id: id(4), resource_id: id(3),
  control_id: id(5), control_version_id: id(6), assessment_profile_version_id: id(9), assessment_result: 'FAIL',
  reason: 'Historical failure <img src=x onerror=alert(1)>', missing_evidence: [], evaluated_at: at, evidence_count: 1,
  evidence: [{ evidence_id: id(7), assessment_id: id(2), scan_id: id(1), resource_snapshot_id: id(4), control_id: id(5),
    control_version_id: id(6), collector: 'test', source: 'normalized-inventory', source_api: 'ec2:DescribeInstances',
    collected_at: at, schema_name: 'control.ec2-001.evidence', schema_version: '1.0.0', evidence_key: 'key',
    payload_sha256: digest, payload: { source_proof: { schema_version: '1.0.0', scan_id: id(1),
      sources: [{ source_outcome_id: id(10), artifact_id: id(11), evidence_sha256: digest }], relationship_observation_ids: [id(12)] } } }],
  finding_id: id(13), finding_occurrence_id: id(14), framework_mappings: [] };
export const resource: Resource = { resource_id: id(3), provider: 'aws', aws_account_id: '123456789012', aws_resource_id: 'i-test',
  arn: 'first-seen ARN', service: 'ec2', resource_type: 'ec2_instance', scope: 'regional', region: 'us-east-1' };
export const snapshot: Snapshot = { snapshot_id: id(4), resource_id: id(3), scan_id: id(1), scope: 'regional', region: 'us-east-1',
  arn: 'historical ARN', name: 'old name', tags: { observed: 'old' }, normalized_configuration: { http_tokens: 'optional' }, state_sha256: digest, observed_at: at };
export const control: Control = { control_id: id(5), control_key: 'EC2-001', versions: [{ control_version_id: id(6), catalog_id: id(8),
  catalog_key: 'catalog', catalog_version: '1.0.0', title: 'Historical definition', severity: 'high', definition_checksum: digest }] };
export const finding: Finding = { finding_id: id(13), fingerprint: digest, aws_account_id: '123456789012', resource_id: id(3), control_id: id(5),
  region: 'us-east-1', status: 'ACCEPTED_RISK', first_detected_at: at, last_detected_at: at, resolved_at: null, occurrence_count: 2, active_exception_ids: [] };
export const exception: Exception = { exception_id: id(15), finding_id: id(13), resource_id: id(3), control_id: id(5), status: 'ACTIVE',
  reason: 'Accepted risk does not change FAIL', approved_by: 'test-approver', created_at: '2026-10-01T00:00:00Z', expires_at: '2026-10-03T00:00:00Z', revoked_at: null };
export const outcome: OutcomeDetail = { source_outcome_id: id(10), scan_id: id(1), collection_account_id: '123456789012', phase: 'ENRICHMENT',
  subject: { subject_kind: 'resource', provider: 'aws', aws_account_id: '123456789012', service: 'ec2', resource_type: 'ec2_instance',
    aws_resource_id: 'i-test', scope: 'regional', region: 'us-east-1', stable_resource_id: id(3), resource_snapshot_id: id(4) },
  evidence_kind: 'ec2.instance', state: 'PRESENT', failure_category: null, collector: 'test', collector_version: '1.0.0', source: 'aws-api',
  source_api: 'ec2:DescribeInstances', collected_at: at, artifact_id: id(11), evidence_reference: 'normalized://test', evidence_sha256: digest, schema_version: '1.0.0',
  artifact: { artifact_id: id(11), scan_id: id(1), collection_account_id: '123456789012', evidence_reference: 'normalized://test', evidence_sha256: digest,
    collected_at: at, evidence_schema: 'ec2.instance', evidence_schema_version: '1.0.0', normalized_payload: { complete: true }, schema_version: '1.0.0' } };
export const relationship: Relationship = { observation_id: id(12), relationship_id: id(16), scan_id: id(1), collection_account_id: '123456789012',
  relationship_type: 'in_vpc', source: { identity_state: 'stable', provider: 'aws', aws_account_id: '123456789012', service: 'ec2', resource_type: 'ec2_instance',
    aws_resource_id: 'i-test', scope: 'regional', region: 'us-east-1', stable_resource_id: id(3), resource_snapshot_id: id(4) },
  target: { identity_state: 'unresolved', provider: 'aws', aws_account_id: null, service: 'ec2', resource_type: 'vpc', aws_resource_id: 'vpc-unresolved',
    scope: 'regional', region: 'us-east-1', stable_resource_id: null, resource_snapshot_id: null, reference_id: id(17) }, resolution: 'TARGET_IDENTITY_INCOMPLETE',
  provenance: { collector: 'test', collector_version: '1.0.0', source: 'aws-api', source_api: 'ec2:DescribeInstances', evidence_reference: 'normalized://test', collected_at: at },
  source_outcome_id: id(10), schema_version: '1.0.0' };
export const page = <T,>(items: T[], offset = 0, total = items.length) => ({ items, offset, total, limit: 25 });
