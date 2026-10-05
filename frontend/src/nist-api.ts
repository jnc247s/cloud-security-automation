// Display-integrity checks only: READ/session authorization remains entirely server-side.
import { isUUID, type Posture } from './api';
import { instant, isScope, object, type Scope } from './investigation-api';

export const countFields = ['pass_count', 'fail_count', 'insufficient_evidence_count', 'not_applicable_count'] as const;
export type Counts = Record<typeof countFields[number], number>;
export interface Coverage { registered_count: number; enabled_count: number; disabled_count: number;
  assessed_count: number | null; unassessed_count: number | null }
export type Level = 'function' | 'category' | 'subcategory';
export interface Mapping { mapping_id: string; control_version_id: string; framework_id: string;
  framework_key: string; framework_version: string; framework_reference_id: string; reference_key: string;
  reference_level: Level; reference_title: string; mapping_rationale: string; mapping_source: string;
  mapping_source_version: string; verified_at: string; mapping_checksum: string }
export interface NistControl { control_id: string; control_version_id: string; control_key: string;
  definition_checksum: string; title: string; category: string; resource_type: string; assessment_type: 'automated';
  severity: string; enabled: boolean; assessment_coverage: 'ASSESSED' | 'UNASSESSED' | 'DISABLED' | 'UNAVAILABLE';
  assessment_counts: Counts | null; framework_mappings: Mapping[] }
export interface Reference { framework_reference_id: string; reference_key: string; level: Level; title: string;
  parent_reference_id: string | null; mapped_control_version_ids: string[];
  control_coverage: Coverage; assessment_counts: Counts | null }
export interface Framework { framework_id: string; framework_key: string; name: string; version: string;
  source: string; source_retrieved_at: string; source_checksum: string;
  interpretation: 'MAPPED_TECHNICAL_SUBSET'; references: Reference[] }
export type NistReport = Omit<Scope, 'controls'> & { controls: NistControl[]; frameworks: Framework[];
  enabled_controls: string[]; control_coverage: Coverage; assessment_counts: Counts | null };
export interface ReleaseIndex { framework: Framework; roots: Reference[]; references: Map<string, Reference>;
  children: Map<string, Reference[]>; contributors: Map<string, Map<string, Mapping[]>> }
export interface NistIndex { report: NistReport; controls: Map<string, NistControl>; releases: ReleaseIndex[] }

const text = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
// UUIDs serialized by the API are canonical lower-case; reject alternate encodings, not aliases.
const uuid = (v: unknown): v is string => typeof v === 'string' && isUUID(v) && v === v.toLowerCase();
const sha = (v: unknown) => typeof v === 'string' && /^[a-f0-9]{64}$/i.test(v);
const integer = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const level = (v: unknown): v is Level => v === 'function' || v === 'category' || v === 'subcategory';
const fields = (v: Record<string, unknown>, keys: string[]) => keys.every(k => text(v[k]));
const unique = (items: string[]) => new Set(items).size === items.length;
function equalSet(a: string[], b: string[]) {
  const other = new Set(b);
  return unique(a) && a.length === b.length && other.size === b.length && a.every(x => other.has(x));
}
const zero = (): Counts => ({ pass_count: 0, fail_count: 0, insufficient_evidence_count: 0, not_applicable_count: 0 });
export const countTotal = (v: Counts) => countFields.reduce((sum, key) => sum + v[key], 0);
function counts(v: unknown): v is Counts {
  return object(v) && countFields.every(k => integer(v[k])) && integer(countTotal(v as Counts));
}
function coverage(v: unknown): v is Coverage {
  return object(v) && ['registered_count', 'enabled_count', 'disabled_count'].every(k => integer(v[k]))
    && ['assessed_count', 'unassessed_count'].every(k => v[k] === null || integer(v[k]));
}
function sameCounts(a: Counts | null, b: Counts | null) {
  return a === null || b === null ? a === b : countFields.every(k => a[k] === b[k]);
}
function sumCounts(controls: NistControl[], available: boolean): Counts | null {
  if (!available) return null;
  const sum = zero();
  for (const c of controls) for (const k of countFields) sum[k] += c.assessment_counts![k];
  return sum;
}
function sameCoverage(v: Coverage, controls: NistControl[], available: boolean) {
  const enabled = controls.filter(c => c.enabled).length;
  const assessed = controls.filter(c => c.assessment_coverage === 'ASSESSED').length;
  return v.registered_count === controls.length && v.enabled_count === enabled && v.disabled_count === controls.length - enabled
    && v.assessed_count === (available ? assessed : null) && v.unassessed_count === (available ? enabled - assessed : null);
}
function isMapping(v: unknown): v is Mapping {
  return object(v) && ['mapping_id', 'control_version_id', 'framework_id', 'framework_reference_id'].every(k => uuid(v[k]))
    && fields(v, ['framework_key', 'framework_version', 'reference_key', 'reference_title', 'mapping_rationale',
      'mapping_source', 'mapping_source_version']) && level(v.reference_level) && instant(v.verified_at) !== null && sha(v.mapping_checksum);
}
function isControl(v: unknown): v is NistControl {
  return object(v) && ['control_id', 'control_version_id'].every(k => uuid(v[k])) && sha(v.definition_checksum)
    && fields(v, ['control_key', 'title', 'resource_type']) && ['network', 'storage', 'identity', 'logging', 'governance'].includes(v.category as string)
    && v.assessment_type === 'automated' && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(v.severity as string)
    && typeof v.enabled === 'boolean' && ['ASSESSED', 'UNASSESSED', 'DISABLED', 'UNAVAILABLE'].includes(v.assessment_coverage as string)
    && (v.assessment_counts === null || counts(v.assessment_counts)) && Array.isArray(v.framework_mappings) && v.framework_mappings.every(isMapping);
}
function isReference(v: unknown): v is Reference {
  return object(v) && uuid(v.framework_reference_id) && fields(v, ['reference_key', 'title']) && level(v.level)
    && (v.parent_reference_id === null || uuid(v.parent_reference_id)) && Array.isArray(v.mapped_control_version_ids)
    && v.mapped_control_version_ids.every(uuid) && unique(v.mapped_control_version_ids)
    && coverage(v.control_coverage) && (v.assessment_counts === null || counts(v.assessment_counts));
}
function isFramework(v: unknown): v is Framework {
  return object(v) && uuid(v.framework_id) && fields(v, ['framework_key', 'name', 'version', 'source'])
    && sha(v.source_checksum) && instant(v.source_retrieved_at) !== null && v.interpretation === 'MAPPED_TECHNICAL_SUBSET'
    && Array.isArray(v.references) && v.references.every(isReference);
}

// Only a fully validated graph escapes. No latest release, graph-by-key inference or checksum certification.
// Work is O(controls + references + mappings * three levels + reported union memberships).
export function buildNistIndex(v: Posture | unknown): NistIndex | null {
  if (!isScope(v) || !object(v) || !uuid(v.scan.scan_id) || !uuid(v.catalog.catalog_id) || !uuid(v.assessment_profile_version_id)
    || !sha(v.scan.assessment_profile_checksum)
    || instant(v.scan.started_at) === null || (v.scan.completed_at !== null && instant(v.scan.completed_at) === null)
    || !Array.isArray(v.enabled_controls) || !v.enabled_controls.every(text) || !unique(v.enabled_controls)
    || !Array.isArray(v.controls) || !v.controls.every(isControl)
    || !Array.isArray(v.frameworks) || !v.frameworks.every(isFramework)
    || !coverage(v.control_coverage) || (v.assessment_counts !== null && !counts(v.assessment_counts))) return null;
  const report = v as NistReport;
  const available = report.availability === 'AVAILABLE';
  const bundle = report.scan.scope !== null && sha(report.scan.inventory_sha256) && sha(report.scan.result_checksum);
  if (report.availability !== (report.scan.status === 'RUNNING' ? 'IN_PROGRESS' : bundle ? 'AVAILABLE' : 'UNAVAILABLE')
    || !unique(report.controls.map(c => c.control_id)) || !unique(report.controls.map(c => c.control_key))
    || !equalSet(report.enabled_controls, report.controls.filter(c => c.enabled).map(c => c.control_key))
    || (report.scan.scope !== null && !equalSet(report.enabled_controls, report.scan.scope.enabled_controls))) return null;
  for (const c of report.controls) {
    if ((available ? !counts(c.assessment_counts) : c.assessment_counts !== null)
      || c.assessment_coverage !== (!c.enabled ? 'DISABLED' : !available ? 'UNAVAILABLE' : countTotal(c.assessment_counts!) ? 'ASSESSED' : 'UNASSESSED')
      || (!c.enabled && available && countTotal(c.assessment_counts!) !== 0)) return null;
  }
  const total = sumCounts(report.controls, available);
  if ((total !== null && !counts(total)) || !sameCounts(report.assessment_counts, total)
    || !sameCoverage(report.control_coverage, report.controls, available)) return null;
  if (!unique(report.frameworks.map(f => f.framework_id))
    || !unique(report.frameworks.map(f => JSON.stringify([f.framework_key, f.version])))) return null;
  const controls = new Map(report.controls.map(c => [c.control_version_id, c]));
  const releases: ReleaseIndex[] = [];
  const byRelease = new Map<string, ReleaseIndex>();
  const referenceIds = new Set<string>();
  for (const framework of report.frameworks) {
    const references = new Map(framework.references.map(r => [r.framework_reference_id, r]));
    if (references.size !== framework.references.length || !unique(framework.references.map(r => r.reference_key))) return null;
    const index: ReleaseIndex = { framework, references, roots: [], children: new Map(), contributors: new Map() };
    for (const r of framework.references) {
      if (referenceIds.has(r.framework_reference_id)) return null;
      referenceIds.add(r.framework_reference_id);
      index.contributors.set(r.framework_reference_id, new Map());
      if (r.level === 'function') {
        if (r.parent_reference_id !== null) return null;
        index.roots.push(r);
      } else {
        const parent = r.parent_reference_id && references.get(r.parent_reference_id);
        if (!parent || parent.level !== (r.level === 'category' ? 'function' : 'category')) return null;
        const siblings = index.children.get(parent.framework_reference_id) ?? [];
        siblings.push(r); index.children.set(parent.framework_reference_id, siblings);
      }
    }
    releases.push(index); byRelease.set(framework.framework_id, index);
  }
  const mappingIds = new Set<string>(), pairs = new Set<string>(), mappedReleases = new Set<string>();
  for (const c of report.controls) for (const m of c.framework_mappings) {
    const release = byRelease.get(m.framework_id), pair = `${c.control_version_id}:${m.framework_reference_id}`;
    const r = release?.references.get(m.framework_reference_id);
    if (!release || !r || m.control_version_id !== c.control_version_id || m.framework_key !== release.framework.framework_key
      || m.framework_version !== release.framework.version || m.reference_key !== r.reference_key || m.reference_level !== r.level
      || m.reference_title !== r.title || mappingIds.has(m.mapping_id) || pairs.has(pair)) return null;
    mappingIds.add(m.mapping_id); pairs.add(pair); mappedReleases.add(m.framework_id);
    let ancestor: Reference | undefined = r;
    while (ancestor) {
      const contributors = release.contributors.get(ancestor.framework_reference_id)!;
      const mappings = contributors.get(c.control_version_id) ?? [];
      mappings.push(m); contributors.set(c.control_version_id, mappings);
      ancestor = ancestor.parent_reference_id === null ? undefined : release.references.get(ancestor.parent_reference_id);
    }
  }
  for (const release of releases) {
    if (!mappedReleases.has(release.framework.framework_id)) return null;
    for (const r of release.framework.references) {
      const ids = [...release.contributors.get(r.framework_reference_id)!.keys()];
      const mapped = ids.map(id => controls.get(id)!);
      if (!equalSet(r.mapped_control_version_ids, ids) || !sameCoverage(r.control_coverage, mapped, available)
        || !sameCounts(r.assessment_counts, sumCounts(mapped, available))) return null;
    }
  }
  return { report, controls, releases };
}
