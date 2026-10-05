import { useMemo, useState, type ReactNode } from 'react';
import type { Posture } from './api';
import { buildNistIndex, type Counts, type Coverage, type NistIndex, type Reference, type ReleaseIndex } from './nist-api';

export const nistText = (value: string, limit = 2048) => value.length <= limit ? value : `${value.slice(0, limit)}… [Display truncated]`;

// Native keyboard-accessible disclosure; mount potentially large metadata/children only on demand.
function Disclosure({ label, children }: { label: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return <details onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>{nistText(label, 512)}</summary>{open ? children : null}</details>;
}
function CountsView({ value }: { value: Counts | null }) {
  return value === null ? <p>Assessment counts unavailable — not zero.</p> : <dl className="counts">
    <dt>PASS assessments</dt><dd>{value.pass_count}</dd>
    <dt>FAIL assessments</dt><dd>{value.fail_count}</dd>
    <dt>INSUFFICIENT_EVIDENCE assessments</dt><dd>{value.insufficient_evidence_count}</dd>
    <dt>NOT_APPLICABLE assessments</dt><dd>{value.not_applicable_count}</dd></dl>;
}
function CoverageView({ value }: { value: Coverage }) {
  return <dl><dt>Registered controls</dt><dd>{value.registered_count}</dd>
    <dt>Enabled controls</dt><dd>{value.enabled_count}</dd><dt>Disabled controls</dt><dd>{value.disabled_count}</dd>
    <dt>Assessed enabled controls</dt><dd>{value.assessed_count ?? 'Unavailable'}</dd>
    <dt>Unassessed enabled controls</dt><dd>{value.unassessed_count ?? 'Unavailable'}</dd></dl>;
}
function ReferenceView({ reference: r, release, index }: { reference: Reference; release: ReleaseIndex; index: NistIndex }) {
  const children = release.children.get(r.framework_reference_id) ?? [];
  const contributors = release.contributors.get(r.framework_reference_id)!;
  return <Disclosure label={`${r.level.toUpperCase()} ${r.reference_key} — ${r.title}`}>
    <p className="mono">Reference UUID: {r.framework_reference_id}</p>
    <p>Unique mapped controls in this reference and its descendants; overlapping rows are not additive.</p>
    <CoverageView value={r.control_coverage} /><CountsView value={r.assessment_counts} />
    {contributors.size === 0 ? <p>No mapped controls. This outcome is not assessed by the scanner, not a passing NIST outcome.</p>
      : <Disclosure label={`Contributing controls and mappings (${contributors.size})`}>
        {[...contributors].map(([id, mappings]) => {
          const control = index.controls.get(id)!;
          return <article key={id}><h5>{nistText(control.control_key)} — {nistText(control.title)}</h5>
            <p>{control.enabled ? 'Enabled' : 'Disabled'} · {control.assessment_coverage} · {control.assessment_type}</p>
            <p className="mono">Control UUID: {control.control_id}<br />Control version UUID: {id}</p>
            <p className="mono">Definition checksum: {control.definition_checksum}</p>
            <CountsView value={control.assessment_counts} />
            {mappings.map(m => <Disclosure key={m.mapping_id} label={`Mapping ${m.reference_key} · ${m.mapping_id}`}>
              <dl><dt>Mapped reference</dt><dd>{m.reference_level} {nistText(m.reference_key)} — {nistText(m.reference_title)}</dd>
                <dt>Reference UUID</dt><dd className="mono">{m.framework_reference_id}</dd>
                <dt>Framework UUID</dt><dd className="mono">{m.framework_id}</dd>
                <dt>Framework release</dt><dd>{nistText(m.framework_key)} / {nistText(m.framework_version)}</dd>
                <dt>Rationale</dt><dd>{nistText(m.mapping_rationale)}</dd><dt>Mapping source</dt><dd>{nistText(m.mapping_source)}</dd>
                <dt>Mapping source version</dt><dd>{nistText(m.mapping_source_version)}</dd>
                <dt>Verified at</dt><dd>{m.verified_at}</dd><dt>Mapping checksum</dt><dd className="mono">{m.mapping_checksum}</dd></dl>
            </Disclosure>)}</article>;
        })}</Disclosure>}
    {children.map(child => <ReferenceView key={child.framework_reference_id} reference={child} release={release} index={index} />)}
  </Disclosure>;
}
function ValidatedContext({ index }: { index: NistIndex }) {
  const [selection, setSelection] = useState('');
  const report = index.report;
  const selected = index.releases.find(r => r.framework.framework_id === selection);
  return <>
    <p className="notice">TECHNICAL_CONTEXT_ONLY · MAPPED_TECHNICAL_SUBSET. This is a mapped technical subset,
      not the full CSF Core, a NIST outcome result, or a compliance score. No manual attestation is inferred.</p>
    <h4>Unique technical assessment counts for this scan</h4><CountsView value={report.assessment_counts} />
    <p>Each historical assessment is counted once here, regardless of mapping fan-out. Current findings,
      ACCEPTED_RISK and exceptions never change these counts.</p>
    <h4>Exact catalog and profile coverage</h4><CoverageView value={report.control_coverage} />
    <dl><dt>Catalog release</dt><dd>{nistText(report.catalog.catalog_key)} / {nistText(report.catalog.version)}</dd>
      <dt>Catalog UUID</dt><dd className="mono">{report.catalog.catalog_id}</dd>
      <dt>Catalog content checksum</dt><dd className="mono">{report.catalog.content_checksum}</dd>
      <dt>Profile release</dt><dd>{nistText(report.scan.assessment_profile_id)} / {nistText(report.scan.assessment_profile_version)}</dd>
      <dt>Profile version UUID</dt><dd className="mono">{report.assessment_profile_version_id}</dd>
      <dt>Profile checksum</dt><dd className="mono">{report.scan.assessment_profile_checksum}</dd></dl>
    <Disclosure label="Catalog control coverage">
      {report.controls.map(c => <p key={c.control_version_id}>{nistText(c.control_key)} — {nistText(c.title)}: {c.enabled ? 'Enabled' : 'Disabled'},
        {' '}{c.assessment_coverage}; {c.framework_mappings.length === 0 ? 'Unmapped' : 'Mapped'}; {c.assessment_type}.</p>)}
    </Disclosure>
    <p>Control coverage is separate from target-assessment counts. Disabled, unmapped, empty and unassessed
      context never imply PASS or NOT_APPLICABLE. Unsupported/manual outcomes are not assessed by this scanner.</p>
    {index.releases.length === 0 ? <p>No framework releases are mapped by this exact catalog.</p> : <>
      <label htmlFor="nist-release">Select exact framework release</label>
      <select id="nist-release" value={selection} onChange={e => setSelection(e.target.value)}>
        <option value="">Choose a retained mapped release</option>
        {index.releases.map(({ framework: f }) => <option key={f.framework_id} value={f.framework_id}>
          {nistText(`${f.framework_key} / ${f.version}`, 256)} · {f.framework_id}</option>)}
      </select>
      {selected ? <div key={selected.framework.framework_id} aria-label="Selected framework context">
        <h4>{nistText(selected.framework.name)} · {nistText(selected.framework.version)}</h4>
        <dl><dt>Framework UUID</dt><dd className="mono">{selected.framework.framework_id}</dd>
          <dt>Source</dt><dd>{nistText(selected.framework.source)}</dd>
          <dt>Source retrieved at</dt><dd>{selected.framework.source_retrieved_at}</dd>
          <dt>Source checksum</dt><dd className="mono">{selected.framework.source_checksum}</dd></dl>
        <p>Reference coverage concerns mapped definitions, not the whole catalog or CSF Core. Parent counts
          use a unique direct/descendant control-version union, not a sum of child rows. Separate releases do not merge.</p>
        {selected.roots.map(r => <ReferenceView key={r.framework_reference_id} reference={r} release={selected} index={index} />)}
      </div> : <p>No framework release selected. A latest release has not been assumed.</p>}
    </>}
    <p>Checksums are retained provenance, not client-side certification of unseen source bytes. Source URLs
      and metadata are text only. Definition context may remain when results are unavailable; available results do not establish complete collection.</p>
  </>;
}
export function NistContext({ report }: { report: Posture }) {
  const index = useMemo(() => buildNistIndex(report), [report]);
  return <section className="nist-context" aria-labelledby="nist-context-title"><h3 id="nist-context-title">NIST technical context</h3>
    {index ? <ValidatedContext index={index} /> : <p role="alert">The NIST context is unsupported or inconsistent.
      No hierarchy or counts have been assumed. Valid investigation views remain separate.</p>}
  </section>;
}
