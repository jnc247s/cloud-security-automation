import { describe, expect, it, vi } from 'vitest';
import { assessmentBound, eligibility, instant, isAssessment, isAssessmentDetail, isControl, isEndpoint,
  isException, isFindingDetail, isOutcomeDetail, isRelationship, isResource, isScope, pageOf, proofLinks, results, sourceStates } from './investigation-api';
import { assessment, at, control, exception, finding, id, outcome, page, relationship, report, resource } from './investigation-fixtures.test-support';

describe('runtime shape and exact bindings', () => {
  it.each(results)('preserves explicit technical state %s', result => expect(isAssessment({ ...assessment, assessment_result: result })).toBe(true));
  it('rejects malformed shapes, pages and substituted evidence/profile/control IDs', () => {
    expect(isScope(report)).toBe(true); expect(isScope({ ...report, catalog: { ...report.catalog, version: 'new' } })).toBe(false);
    expect(isAssessmentDetail(assessment)).toBe(true);
    for (const key of ['assessment_id', 'scan_id', 'resource_snapshot_id', 'control_version_id', 'control_id'])
      expect(isAssessmentDetail({ ...assessment, evidence: [{ ...assessment.evidence[0], [key]: id(99) }] })).toBe(false);
    expect(assessmentBound({ ...assessment, assessment_profile_version_id: id(99) }, report)).toBe(false);
    expect(isAssessment({ ...assessment, assessment_result: 'UNASSESSED' })).toBe(false);
    expect(isAssessment({ ...assessment, evidence_count: NaN })).toBe(false);
    expect(pageOf(isAssessment)(page([assessment]))).toBe(true);
    expect(pageOf(isAssessment)({ ...page([assessment]), limit: 101 })).toBe(false);
    expect(pageOf(isAssessment)({ ...page([assessment]), limit: 0 })).toBe(false);
    expect(pageOf(isAssessment)({ ...page([assessment]), items: Array(26).fill(assessment) })).toBe(false);
    expect(isControl(control)).toBe(true); expect(isControl({ ...control, versions: [{ ...control.versions[0], catalog_id: 'latest' }] })).toBe(false);
    expect(isException(exception)).toBe(true);
    expect(isFindingDetail({ ...finding, occurrences: [], exceptions: [exception] })).toBe(true);
    expect(isFindingDetail({ ...finding, occurrences: [], exceptions: [{ ...exception, resource_id: id(99) }] })).toBe(false);
  });
  it.each(sourceStates)('preserves source state %s without inventing assessment state', state => expect(isOutcomeDetail({ ...outcome, state })).toBe(true));
  it('binds artifact identity/digests and preserves unresolved references', () => {
    expect(isOutcomeDetail(outcome)).toBe(true);
    for (const key of ['artifact_id', 'scan_id', 'collection_account_id', 'evidence_sha256', 'evidence_reference', 'collected_at'])
      expect(isOutcomeDetail({ ...outcome, artifact: { ...outcome.artifact, [key]: 'substituted' } })).toBe(false);
    expect(isRelationship(relationship)).toBe(true);
    expect(isRelationship({ ...relationship, resolution: 'RESOLVED' })).toBe(false);
    expect(isRelationship({ ...relationship, relationship_type: 'reverse_edge' })).toBe(false);
    expect(isEndpoint({ ...relationship.target, stable_resource_id: id(99) })).toBe(false);
  });
  it('only links supported typed source proofs, never UUID-like prose', () => {
    const evidence = assessment.evidence[0];
    expect(proofLinks(evidence, 'EC2-001')?.edges).toEqual([id(12)]);
    expect(proofLinks(evidence, 'NEW-CONTROL')).toBeNull();
    expect(proofLinks({ ...evidence, payload: { reason: `source ${id(10)}` } }, 'EC2-001')).toBeNull();
    for (const schema_version of ['1.11.0', '999', true, null]) expect(proofLinks({ ...evidence,
      payload: { source_proof: { ...(evidence.payload.source_proof as object), schema_version } } }, 'EC2-001')).toBeNull();
    expect(proofLinks({ ...evidence, payload: { source_proof: { ...(evidence.payload.source_proof as object), scan_id: id(99) } } }, 'EC2-001')).toBeNull();
  });
  it.each(['array', 'object', 'null', 'boolean', 'number'])('rejects %s enum/proof fields without string coercion', kind => {
    const malformed = (valid: string): unknown => kind === 'array' ? [valid] : kind === 'object' ? { value: valid }
      : kind === 'null' ? null : kind === 'boolean' ? true : 1;
    expect(isResource({ ...resource, scope: malformed('regional') })).toBe(false);
    expect(isEndpoint({ ...relationship.source, scope: malformed('regional') })).toBe(false);
    expect(isException({ ...exception, status: malformed('ACTIVE') })).toBe(false);
    expect(isFindingDetail({ ...finding, status: malformed('ACCEPTED_RISK'), occurrences: [], exceptions: [] })).toBe(false);
    expect(isOutcomeDetail({ ...outcome, phase: malformed('ENRICHMENT') })).toBe(false);
    expect(isOutcomeDetail({ ...outcome, state: malformed('PRESENT') })).toBe(false);
    expect(isRelationship({ ...relationship, relationship_type: malformed('in_vpc') })).toBe(false);
    expect(isRelationship({ ...relationship, resolution: malformed('TARGET_IDENTITY_INCOMPLETE') })).toBe(false);
    const evidence = assessment.evidence[0];
    expect(proofLinks({ ...evidence, payload: { source_proof: { ...(evidence.payload.source_proof as object),
      schema_version: malformed('1.0.0') } } }, 'EC2-001')).toBeNull();
  });
});
describe('server-time exception eligibility', () => {
  it('keeps ACTIVE-but-expired separate and ignores client wall-clock', () => {
    vi.spyOn(Date, 'now').mockReturnValue(0);
    expect(eligibility(exception, at)).toBe('Expired at server reference time');
    vi.restoreAllMocks();
    expect(eligibility({ ...exception, expires_at: '2026-10-05T00:00:00Z' }, at)).toBe('Eligible at server reference time');
    expect(eligibility({ ...exception, expires_at: '2026-10-05T00:00:00Z', revoked_at: at }, at)).toContain('revoked');
  });
  it('preserves exact microsecond boundary and requires valid absolute times', () => {
    const x = { ...exception, expires_at: '2026-10-04T12:00:00.000200Z' };
    expect(eligibility(x, at)).toBe('Eligible at server reference time');
    expect(eligibility(x, x.expires_at)).toBe('Expired at server reference time');
    for (const reference of [null, '', 'invalid', '2026-10-04T12:00:00', '2026-02-30T12:00:00Z']) expect(eligibility(x, reference)).toBe('Eligibility unavailable');
    expect(instant('2026-02-30T12:00:00Z')).toBeNull();
    expect(instant('2026-10-04T25:00:00Z')).toBeNull();
    expect(eligibility({ ...x, created_at: '2026-10-04T12:00:00.000150Z' }, at)).toContain('Not yet');
    expect(eligibility({ ...x, created_at: 'naive' }, at)).toBe('Eligibility unavailable');
  });
});
