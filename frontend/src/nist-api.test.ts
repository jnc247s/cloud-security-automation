import { describe, expect, it } from 'vitest';
import { isScope } from './investigation-api';
import { buildNistIndex, countTotal, type NistReport } from './nist-api';
import { id, nistFixture, unavailableFixture } from './nist-fixtures';

describe('exact NIST display graph', () => {
  it('keeps historical releases separate and unions fan-out before counting', () => {
    const index = buildNistIndex(nistFixture())!;
    expect(index.releases).toHaveLength(2);
    expect(countTotal(index.report.assessment_counts!)).toBe(10);
    expect(index.releases[0].roots[0].assessment_counts?.pass_count).toBe(1);
    expect(index.releases[0].contributors.get(id(101))?.get(id(20))).toHaveLength(2);
    expect(index.releases[1].contributors.get(id(111))?.get(id(20))).toHaveLength(1);
  });
  it.each([false, true])('retains unavailable definitions without replacing null with zero: running=%s', running => {
    const index = buildNistIndex(unavailableFixture(running))!;
    expect(index.report.assessment_counts).toBeNull();
    expect(index.releases[0].roots[0].assessment_counts).toBeNull();
  });
  it.each(['PARTIAL', 'FAILED'] as const)('retains terminal %s counts and collection gaps', status => {
    const v = nistFixture(); v.scan.status = status;
    expect(buildNistIndex(v)?.report.assessment_counts?.fail_count).toBe(2);
  });
  it('allows an exact catalog with no mappings and no frameworks', () => {
    const v = nistFixture(); v.frameworks = []; v.controls.forEach(c => { c.framework_mappings = []; });
    expect(buildNistIndex(v)?.releases).toEqual([]);
  });
  const mutations: [string, (v: NistReport) => void][] = [
    ['schema', v => { (v as unknown as Record<string, unknown>).schema_version = '2.0.0'; }],
    ['interpretation', v => { (v as unknown as Record<string, unknown>).interpretation = 'COMPLIANT'; }],
    ['catalog key', v => { v.catalog.catalog_key = 'latest'; }],
    ['catalog version', v => { v.catalog.version = '0.13.0'; }],
    ['catalog checksum', v => { v.catalog.content_checksum = 'not-a-digest'; }],
    ['profile UUID', v => { v.assessment_profile_version_id = 'latest'; }],
    ['profile checksum', v => { v.scan.assessment_profile_checksum = 'bad'; }],
    ['naive scan time', v => { v.scan.started_at = '2026-01-01T00:00:00'; }],
    ['invalid completed time', v => { v.scan.completed_at = '2026-02-30T00:00:00Z'; }],
    ['availability', v => { v.scan.status = 'RUNNING'; }],
    ['missing bundle', v => { v.scan.result_checksum = null; }],
    ['enablement membership', v => { v.controls[0].enabled = false; }],
    ['duplicate enabled', v => { v.enabled_controls.push(v.enabled_controls[0]); }],
    ['retained scope', v => { v.scan.scope!.enabled_controls = []; }],
    ['duplicate control', v => { v.controls[1].control_id = v.controls[0].control_id; }],
    ['duplicate version', v => { v.controls[1].control_version_id = v.controls[0].control_version_id; }],
    ['duplicate key', v => { v.controls[1].control_key = v.controls[0].control_key; }],
    ['disabled assessments', v => { v.controls[4].assessment_counts!.pass_count = 1; }],
    ['unassessed coverage', v => { v.controls[5].assessment_coverage = 'ASSESSED'; }],
    ['unknown type', v => { (v.controls[0] as unknown as Record<string, unknown>).assessment_type = 'manual'; }],
    ['unknown severity', v => { v.controls[0].severity = 'SAFE'; }],
    ['unknown category', v => { v.controls[0].category = 'score'; }],
    ['string count', v => { (v.assessment_counts as unknown as Record<string, unknown>).pass_count = '1'; }],
    ['negative count', v => { v.assessment_counts!.pass_count = -1; }],
    ['fraction count', v => { v.assessment_counts!.pass_count = 0.5; }],
    ['unsafe total', v => { v.controls[0].assessment_counts!.pass_count = Number.MAX_SAFE_INTEGER; }],
    ['null available', v => { v.controls[0].assessment_counts = null; }],
    ['headline fanout', v => { v.assessment_counts!.pass_count = 2; }],
    ['coverage totals', v => { v.control_coverage.registered_count++; }],
    ['unavailable reference coverage', v => { v.frameworks[0].references[0].control_coverage.assessed_count = null; }],
    ['duplicate release', v => { v.frameworks[1].framework_id = v.frameworks[0].framework_id; }],
    ['duplicate release key/version', v => { v.frameworks[1].version = v.frameworks[0].version; }],
    ['unknown framework interpretation', v => { (v.frameworks[0] as unknown as Record<string, unknown>).interpretation = 'COMPLIANT'; }],
    ['invalid source time', v => { v.frameworks[0].source_retrieved_at = '2026-09-01'; }],
    ['source checksum', v => { v.frameworks[0].source_checksum = 'bad'; }],
    ['duplicate reference UUID', v => { v.frameworks[0].references.push(v.frameworks[0].references[0]); }],
    ['duplicate reference key', v => { v.frameworks[0].references[1].reference_key = 'PR'; }],
    ['foreign parent', v => { v.frameworks[0].references[1].parent_reference_id = id(111); }],
    ['cycle', v => { v.frameworks[0].references[1].parent_reference_id = id(103); }],
    ['orphan', v => { v.frameworks[0].references[1].parent_reference_id = id(999); }],
    ['root parent', v => { v.frameworks[0].references[0].parent_reference_id = id(102); }],
    ['duplicate union', v => { v.frameworks[0].references[0].mapped_control_version_ids.push(id(20)); }],
    ['wrong union', v => { v.frameworks[0].references[0].mapped_control_version_ids = []; }],
    ['parent double count', v => { v.frameworks[0].references[0].assessment_counts!.pass_count = 2; }],
    ['unmapped pass', v => { v.frameworks[0].references[4].assessment_counts!.pass_count = 1; }],
    ['mapping foreign version', v => { v.controls[0].framework_mappings[0].control_version_id = id(21); }],
    ['mapping foreign release', v => { v.controls[0].framework_mappings[0].framework_id = id(110); }],
    ['mapping key', v => { v.controls[0].framework_mappings[0].framework_key = 'other'; }],
    ['mapping release version', v => { v.controls[0].framework_mappings[0].framework_version = 'latest'; }],
    ['mapping foreign reference', v => { v.controls[0].framework_mappings[0].framework_reference_id = id(113); }],
    ['mapping reference key', v => { v.controls[0].framework_mappings[0].reference_key = 'other'; }],
    ['mapping level', v => { v.controls[0].framework_mappings[0].reference_level = 'function'; }],
    ['mapping title', v => { v.controls[0].framework_mappings[0].reference_title = 'other'; }],
    ['mapping time', v => { v.controls[0].framework_mappings[0].verified_at = '2026-02-30T00:00:00Z'; }],
    ['mapping checksum', v => { v.controls[0].framework_mappings[0].mapping_checksum = 'bad'; }],
    ['mapping UUID duplicate', v => { v.controls[0].framework_mappings[1].mapping_id = v.controls[0].framework_mappings[0].mapping_id; }],
    ['mapping pair duplicate', v => { v.controls[0].framework_mappings.push({ ...v.controls[0].framework_mappings[0], mapping_id: id(500) }); }],
    ['coercive UUID', v => { (v.frameworks[0] as unknown as Record<string, unknown>).framework_id = { toString: () => id(100) }; }],
    ['noncanonical UUID alias', v => { v.controls[0].control_id = v.controls[0].control_id.toUpperCase(); }]
  ];
  it.each(mutations)('rejects inconsistent/unsupported %s', (_, mutate) => {
    const v = nistFixture(); mutate(v); expect(buildNistIndex(v)).toBeNull();
  });
  it('does not turn independently valid investigation context into a NIST guard failure', () => {
    const v = nistFixture(); v.frameworks[0].references[0].assessment_counts!.pass_count++;
    expect(isScope(v)).toBe(true); expect(buildNistIndex(v)).toBeNull();
  });
  it('retains empty enabled-profile definition coverage as unavailable, never an assessment', () => {
    const v = unavailableFixture(true); v.enabled_controls = [];
    for (const c of v.controls) { c.enabled = false; c.assessment_coverage = 'DISABLED'; }
    v.control_coverage.enabled_count = 0; v.control_coverage.disabled_count = v.controls.length;
    for (const f of v.frameworks) for (const r of f.references) {
      r.control_coverage.enabled_count = 0; r.control_coverage.disabled_count = r.mapped_control_version_ids.length;
    }
    expect(buildNistIndex(v)?.report.assessment_counts).toBeNull();
  });
  it('rejects available counts in an unavailable definition-only report', () => {
    const v = unavailableFixture(); v.frameworks[0].references[0].assessment_counts = { pass_count: 0, fail_count: 0, insufficient_evidence_count: 0, not_applicable_count: 0 };
    expect(buildNistIndex(v)).toBeNull();
  });
  it.each([128, 512])('indexes %s additional references with bounded property visits rather than repeated whole-graph scans', size => {
    const v = nistFixture(), f = v.frameworks[0], control = v.controls[0];
    for (let n = 0; n < size; n++) {
      const ref = { ...f.references[2], framework_reference_id: id(1000 + n), reference_key: `TEST.${n}`,
        mapped_control_version_ids: [control.control_version_id], control_coverage: { registered_count: 1, enabled_count: 1,
          disabled_count: 0, assessed_count: 1, unassessed_count: 0 } };
      f.references.push(ref);
      control.framework_mappings.push({ ...control.framework_mappings[0], mapping_id: id(2000 + n),
        framework_reference_id: ref.framework_reference_id, reference_key: ref.reference_key });
    }
    let visits = 0;
    for (const r of f.references) {
      const key = r.reference_key;
      Object.defineProperty(r, 'reference_key', { get: () => { visits++; return key; } });
    }
    const index = buildNistIndex(v)!;
    expect(index.releases[0].references.size).toBe(size + 5);
    expect(index.releases[0].contributors.get(id(101))?.get(id(20))).toHaveLength(size + 2);
    expect(index.releases[0].roots[0].assessment_counts?.pass_count).toBe(1);
    expect(visits).toBeLessThanOrEqual(4 * (size + 5));
  });
});
