// Synthetic, internally consistent display fixtures. Real browser journeys use the persisted API.
import type { Counts, Coverage, Framework, Mapping, NistReport, Reference } from './nist-api';
export const id = (n: number) => `00000000-0000-0000-0000-${n.toString(16).padStart(12, '0')}`;
export const checksum = 'a'.repeat(64);
export const emptyCounts = (): Counts => ({ pass_count: 0, fail_count: 0, insufficient_evidence_count: 0, not_applicable_count: 0 });
export function nistFixture(): NistReport {
  const cov = (registered: number, enabled: number, assessed: number): Coverage => ({ registered_count: registered,
    enabled_count: enabled, disabled_count: registered - enabled, assessed_count: assessed, unassessed_count: enabled - assessed });
  const pass = { ...emptyCounts(), pass_count: 1 };
  const controls: NistReport['controls'] = Array.from({ length: 6 }, (_, n) => ({ control_id: id(10 + n), control_version_id: id(20 + n),
    control_key: `TEST-00${n}`, definition_checksum: checksum, title: `Control ${n}`, category: 'storage', resource_type: 's3_bucket',
    assessment_type: 'automated', severity: 'HIGH', enabled: n !== 4, assessment_coverage: n < 4 ? 'ASSESSED' : n === 4 ? 'DISABLED' : 'UNASSESSED',
    assessment_counts: { ...emptyCounts(), ...([ { pass_count: 1 }, { fail_count: 2 }, { insufficient_evidence_count: 3 }, { not_applicable_count: 4 } ][n] ?? {}) },
    framework_mappings: [] }));
  const frameworks: Framework[] = [0, 1].map(n => {
    const base = 100 + n * 10;
    const union = n === 0 ? [id(20), id(24), id(25)] : [id(20)];
    const refs: Reference[] = [
      { framework_reference_id: id(base + 1), reference_key: 'PR', level: 'function', title: 'Protect', parent_reference_id: null,
        mapped_control_version_ids: union, control_coverage: n === 0 ? cov(3, 2, 1) : cov(1, 1, 1), assessment_counts: { ...pass } },
      { framework_reference_id: id(base + 2), reference_key: 'PR.DS', level: 'category', title: 'Data security', parent_reference_id: id(base + 1),
        mapped_control_version_ids: union, control_coverage: n === 0 ? cov(3, 2, 1) : cov(1, 1, 1), assessment_counts: { ...pass } },
      { framework_reference_id: id(base + 3), reference_key: 'PR.DS-01', level: 'subcategory', title: 'First outcome', parent_reference_id: id(base + 2),
        mapped_control_version_ids: n === 0 ? [id(20), id(24)] : [id(20)], control_coverage: n === 0 ? cov(2, 1, 1) : cov(1, 1, 1), assessment_counts: { ...pass } },
      { framework_reference_id: id(base + 4), reference_key: 'PR.DS-02', level: 'subcategory', title: 'Second outcome', parent_reference_id: id(base + 2),
        mapped_control_version_ids: n === 0 ? [id(20), id(25)] : [], control_coverage: n === 0 ? cov(2, 2, 1) : cov(0, 0, 0), assessment_counts: n === 0 ? { ...pass } : emptyCounts() },
      { framework_reference_id: id(base + 5), reference_key: 'PR.DS-03', level: 'subcategory', title: 'Unmapped outcome', parent_reference_id: id(base + 2),
        mapped_control_version_ids: [], control_coverage: cov(0, 0, 0), assessment_counts: emptyCounts() }
    ];
    return { framework_id: id(base), framework_key: 'nist-csf', name: 'Retained CSF subset', version: n === 0 ? '2.0' : '2.0+subset.older',
      source: 'javascript:alert(1)', source_retrieved_at: '2026-09-01T00:00:00Z', source_checksum: checksum,
      interpretation: 'MAPPED_TECHNICAL_SUBSET', references: refs };
  });
  let mapping = 200;
  const add = (control: number, release: number, ref: number) => {
    const f = frameworks[release], r = f.references[ref];
    const m: Mapping = { mapping_id: id(mapping++), control_version_id: controls[control].control_version_id, framework_id: f.framework_id,
      framework_key: f.framework_key, framework_version: f.version, framework_reference_id: r.framework_reference_id,
      reference_key: r.reference_key, reference_level: r.level, reference_title: r.title,
      mapping_rationale: '<img src=x onerror=alert(1)>', mapping_source: 'javascript:alert(1)', mapping_source_version: '2.0',
      verified_at: '2026-09-01T01:00:00+01:00', mapping_checksum: checksum };
    controls[control].framework_mappings.push(m);
  };
  add(0, 0, 2); add(0, 0, 3); add(4, 0, 2); add(5, 0, 3); add(0, 1, 2);
  return { schema_version: '1.0.0', interpretation: 'TECHNICAL_CONTEXT_ONLY', availability: 'AVAILABLE',
    scan: { scan_id: id(1), status: 'COMPLETED', aws_account_id: '123456789012', requested_regions: ['us-east-1'], successful_regions: ['us-east-1'],
      requested_services: ['s3'], successful_collectors: ['s3_buckets'], started_at: '2026-09-01T00:00:00Z', completed_at: '2026-09-01T01:00:00Z', failure: null,
      scanner_version: 'test', control_catalog_id: 'test', control_catalog_version: '0.2.1', assessment_profile_id: 'retained', assessment_profile_version: '1.0.0',
      assessment_profile_checksum: checksum, inventory_sha256: checksum, result_checksum: checksum,
      scope: { requested_collectors: ['s3_buckets'], collector_outcomes: { s3_buckets: 'SUCCEEDED' }, resource_types: ['s3_bucket'],
        enabled_controls: controls.filter(c => c.enabled).map(c => c.control_key) } },
    catalog: { catalog_id: id(2), catalog_key: 'test', version: '0.2.1', content_checksum: checksum }, assessment_profile_version_id: id(3),
    enabled_controls: controls.filter(c => c.enabled).map(c => c.control_key), control_coverage: cov(6, 5, 4),
    assessment_counts: { pass_count: 1, fail_count: 2, insufficient_evidence_count: 3, not_applicable_count: 4 }, controls, frameworks };
}
export function unavailableFixture(running = false): NistReport {
  const v = nistFixture(); v.availability = running ? 'IN_PROGRESS' : 'UNAVAILABLE'; v.scan.status = running ? 'RUNNING' : 'FAILED';
  v.scan.scope = null; v.scan.result_checksum = null; v.scan.inventory_sha256 = null; v.assessment_counts = null;
  v.control_coverage.assessed_count = null; v.control_coverage.unassessed_count = null;
  for (const c of v.controls) { c.assessment_counts = null; c.assessment_coverage = c.enabled ? 'UNAVAILABLE' : 'DISABLED'; }
  for (const f of v.frameworks) for (const r of f.references) {
    r.assessment_counts = null; r.control_coverage.assessed_count = null; r.control_coverage.unassessed_count = null;
  }
  return v;
}
